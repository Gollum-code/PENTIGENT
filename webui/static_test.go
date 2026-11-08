package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// 生成一段足够长的 JS 文本，验证 gzip 压缩收益
var sampleJS = "console.log('x');" + strings.Repeat("// padding\n", 400)

// 静态资源服务：gzip 压缩 + 缓存头 + SPA 兜底
func TestStaticHandler(t *testing.T) {
	root := fstest.MapFS{
		"index.html":                &fstest.MapFile{Data: []byte("<html><body>" + strings.Repeat("x", 200) + "</body></html>")},
		"_next/static/chunk-abc.js": &fstest.MapFile{Data: []byte(sampleJS)},
		"favicon.png":               &fstest.MapFile{Data: []byte{0x89, 0x50, 0x4e, 0x47}},
		"logo.svg":                  &fstest.MapFile{Data: []byte("<svg>" + strings.Repeat("x", 200) + "</svg>")},
	}
	h := handlerFor(root)

	t.Run("js 被 gzip 且标记不可变缓存", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_next/static/chunk-abc.js", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
			t.Errorf("Content-Encoding=%q, want gzip", got)
		}
		if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
			t.Errorf("哈希资源应 immutable 缓存, got %q", got)
		}
		zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("响应不是合法 gzip: %v", err)
		}
		got, _ := io.ReadAll(zr)
		if !bytes.Equal(got, []byte(sampleJS)) {
			t.Error("解压后的内容与源文件不一致")
		}
	})

	t.Run("客户端不支持 gzip 时原样返回", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_next/static/chunk-abc.js", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Encoding") != "" {
			t.Errorf("未声明 gzip 却压缩了: %q", rec.Header().Get("Content-Encoding"))
		}
		if rec.Body.String() != sampleJS {
			t.Error("未压缩响应体应等于源文件")
		}
	})

	t.Run("二进制资源不压缩", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/favicon.png", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Encoding") != "" {
			t.Error("PNG 不应被 gzip")
		}
	})

	t.Run("SPA 兜底回 index.html 且 no-cache", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tasks/999/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("HTML 应 no-cache, got %q", got)
		}
		zr, _ := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		body, _ := io.ReadAll(zr)
		if !strings.HasPrefix(string(body), "<html>") {
			t.Errorf("兜底应返回 index.html 内容, got %q", string(body[:min(len(body), 40)]))
		}
	})

	t.Run("HEAD 请求不产生压缩空响应", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/_next/static/chunk-abc.js", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if len(rec.Body.Bytes()) != 0 {
			t.Errorf("HEAD 响应不应有 body, got %d bytes", len(rec.Body.Bytes()))
		}
	})
}
