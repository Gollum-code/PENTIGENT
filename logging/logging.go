package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// rotatingFile 一个简单的按大小轮转文件写入器
type rotatingFile struct {
	mu         sync.Mutex
	f          *os.File
	path       string
	maxBytes   int64
	maxBackups int
	written    int64
}

// Write 实现 io.Writer：超过阈值则轮转
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.written += int64(n)
	if r.written >= r.maxBytes {
		_ = r.rotate()
	}
	return n, err
}

func (r *rotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if fi, err := f.Stat(); err == nil {
		r.written = fi.Size()
	}
	r.f = f
	return nil
}

// rotate 关闭当前文件，重命名备份并新建
func (r *rotatingFile) rotate() error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	ts := time.Now().Format("20060102-150405")
	if err := os.Rename(r.path, fmt.Sprintf("%s.%s", r.path, ts)); err != nil {
		return err
	}
	// 清理多余备份
	if r.maxBackups > 0 {
		matches, _ := filepath.Glob(r.path + ".*")
		if len(matches) > r.maxBackups {
			for _, m := range matches[:len(matches)-r.maxBackups] {
				_ = os.Remove(m)
			}
		}
	}
	r.written = 0
	return r.open()
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}

// Setup 配置全局 logger：输出到 stdout + 可选的轮转文件
func Setup(logFile string, maxSizeMB, maxBackups int) {
	var writers []io.Writer
	writers = append(writers, os.Stdout)
	if logFile != "" {
		rf := &rotatingFile{
			path:       logFile,
			maxBytes:   int64(maxSizeMB) << 20,
			maxBackups: maxBackups,
		}
		if err := rf.open(); err == nil {
			writers = append(writers, rf)
			log.Printf("log: writing to file %s", logFile)
		} else {
			log.Printf("log: open %s failed: %v (stdout only)", logFile, err)
		}
	}
	log.SetOutput(io.MultiWriter(writers...))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}