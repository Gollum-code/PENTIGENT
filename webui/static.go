package webui

import (
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

var distSub fs.FS

func init() {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	distSub = sub
}

// Handler 返回静态资源 handler（SPA 兜底：未知路径回退 index.html）。
// 单二进制直连部署时前面没有反代，这里补齐两件事：
//  1. 缓存策略 —— Next 的内容哈希资源可永久缓存，HTML 永远走协商缓存；
//  2. gzip —— 文本型资源按 Accept-Encoding 压缩，JS 包体积能小 70% 左右。
func Handler() http.Handler { return handlerFor(distSub) }

// handlerFor 与 Handler 相同，但允许注入文件系统（测试用，不依赖真实 dist 内容）。
func handlerFor(root fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servePath, fallback := resolveServePath(root, r.URL.Path)
		cacheKey := servePath
		if fallback {
			cacheKey = "/index.html" // 兜底返回的是 index.html
		}

		// 缓存策略
		switch {
		case strings.HasPrefix(cacheKey, "/_next/static/"):
			// 文件名含内容哈希，内容变文件名就变，可永久缓存
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		case strings.HasSuffix(cacheKey, ".html"):
			// HTML 是路由入口，重新部署后必须立即生效
			w.Header().Set("Cache-Control", "no-cache")
		default:
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}

		// gzip：GET + 无 Range + 客户端支持 + 文本型资源才压缩
		var gwr *gzipResponseWriter
		sw := w
		if r.Method == http.MethodGet &&
			r.Header.Get("Range") == "" &&
			acceptsGzip(r) &&
			isTextAsset(cacheKey) {
			gwr = &gzipResponseWriter{ResponseWriter: w, gw: gzip.NewWriter(w)}
			sw = gwr
		}

		// 用克隆的请求改写路径，避免污染原始请求（middleware 还要读它记日志）
		r2 := r.Clone(r.Context())
		if fallback {
			// SPA 兜底：按原始 URL 返回 index.html 内容。
			// 绝不能把 URL 改写成 /index.html —— http.FileServer 会对以 /index.html
			// 结尾的请求做 301 规范化，深层路由（如 /tasks/999/）会被弹回首页，
			// 客户端路由就断了。该 bug 在旧实现里就存在（本次测试抓到）。
			http.ServeFileFS(sw, r2, root, "index.html")
		} else {
			r2.URL.Path = servePath
			fileServer.ServeHTTP(sw, r2)
		}

		// 只有真正压缩了才写 gzip trailer；404/304 等空响应必须原样透传，
		// 否则会在错误响应体后面追加一段 gzip 垃圾字节。
		if gwr != nil {
			_ = gwr.close()
		}
	})
}

// resolveServePath 把 URL 映射到 dist 内要服务的文件。
// 返回的 servePath 带 "/"+FileServer 需要的形态；fallback=true 表示该路径
// 在 dist 里不存在，调用方需按原始 URL 返回 index.html（不能改写 URL，
// 否则 FileServer 会把 /index.html 规范化成 301，深层客户端路由就断了）。
func resolveServePath(root fs.FS, urlPath string) (servePath string, fallback bool) {
	rel := strings.TrimPrefix(urlPath, "/")
	if rel == "" {
		// 根路径交给 FileServer 服务目录下的 index.html（保持 "/"，避免重定向循环）
		return "/", false
	}
	if strings.HasSuffix(rel, "/") {
		// 目录形式：存在该目录的 index.html 则服务之
		cand := rel + "index.html"
		if f, err := fs.Stat(root, cand); err == nil && !f.IsDir() {
			return "/" + cand, false
		}
		return "/index.html", true
	}
	// 普通形式：先看是否是文件，再看是否是目录（Next 导出会生成 x/index.html）
	if f, err := fs.Stat(root, rel); err == nil && !f.IsDir() {
		return "/" + rel, false
	}
	if f2, err := fs.Stat(root, rel+"/index.html"); err == nil && !f2.IsDir() {
		return "/" + rel + "/index.html", false
	}
	return "/index.html", true
}

// acceptsGzip 客户端是否接受 gzip
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.HasPrefix(strings.TrimSpace(part), "gzip") {
			return true
		}
	}
	return false
}

// isTextAsset 是否文本型静态资源（压缩有收益且无风险）
func isTextAsset(p string) bool {
	// 已压缩的二进制资源：再压一遍没收益还费 CPU
	if hasExt(p, ".woff2", ".woff", ".ttf", ".eot", ".png", ".jpg", ".jpeg",
		".gif", ".webp", ".avif", ".ico", ".mp4", ".webm", ".ogg", ".zip", ".gz") {
		return false
	}
	if strings.HasPrefix(p, "/_next/static/") {
		return true
	}
	return hasExt(p, ".html", ".js", ".css", ".svg", ".txt", ".json",
		".xml", ".map", ".webmanifest")
}

func hasExt(p string, exts ...string) bool {
	for _, e := range exts {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return false
}

// gzipResponseWriter 拦截 WriteHeader：删掉压缩前算的 Content-Length、
// 标注 Content-Encoding；非 2xx/304（如协商缓存的空响应）不压缩。
type gzipResponseWriter struct {
	http.ResponseWriter
	gw         *gzip.Writer
	headerDone bool
	bypass     bool
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if !g.headerDone {
		g.headerDone = true
		if code != http.StatusOK {
			// 404/304 等空响应或错误响应：原样透传，不压缩
			g.bypass = true
		} else {
			h := g.Header()
			h.Del("Content-Length")
			h.Set("Content-Encoding", "gzip")
			h.Add("Vary", "Accept-Encoding")
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.headerDone {
		g.WriteHeader(http.StatusOK)
	}
	if g.bypass {
		return g.ResponseWriter.Write(b)
	}
	return g.gw.Write(b)
}

// close 结束 gzip 流；bypass/未写头的响应直接跳过（gzipWriter 未写入数据，无需收尾）。
func (g *gzipResponseWriter) close() error {
	if g.bypass || !g.headerDone {
		return nil
	}
	return g.gw.Close()
}
