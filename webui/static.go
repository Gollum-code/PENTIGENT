package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
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

// Handler 返回静态资源 handler（SPA 兜底：未知路径回退 index.html）
func Handler() http.Handler {
	fileServer := http.FileServer(http.FS(distSub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if strings.HasSuffix(p, "/") {
			p += "index.html"
		}
		if f, err := fs.Stat(distSub, p); err != nil || f.IsDir() {
			if f, err := fs.Stat(distSub, path.Join(p, "index.html")); err == nil && !f.IsDir() {
				r.URL.Path = "/" + path.Join(p, "index.html")
				fileServer.ServeHTTP(w, r)
				return
			}
			r.URL.Path = "/index.html"
		}
		fileServer.ServeHTTP(w, r)
	})
}