package logging

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingFileWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "app.log")
	rf := &rotatingFile{path: path, maxBytes: 1 << 20, maxBackups: 3}
	if err := rf.open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rf.Close()

	if _, err := rf.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Errorf("写入内容未落盘: %q", string(data))
	}
}

// 超过 maxBytes 应触发轮转，且备份文件被保留
func TestRotatingFileRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	rf := &rotatingFile{path: path, maxBytes: 64, maxBackups: 2}
	if err := rf.open(); err != nil {
		t.Fatal(err)
	}
	defer rf.Close()

	payload := []byte(strings.Repeat("x", 40))
	for i := 0; i < 8; i++ {
		if _, err := rf.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	matches, _ := filepath.Glob(path + ".*")
	if len(matches) == 0 {
		t.Error("超过阈值后应产生备份文件")
	}
	// 当前文件不应超阈值太多
	if fi, err := os.Stat(path); err == nil {
		if fi.Size() > 128 {
			t.Errorf("当前文件应被限制大小, got %d", fi.Size())
		}
	}
}

// Setup 应写文件到磁盘；返回的 closer 必须能释放文件句柄
// （Windows 上不释放会导致日志文件无法删除/轮转）
func TestSetupWritesToFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "artex-log-test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "setup.log")

	closeFn := Setup(path, 1, 1)
	log.Println("setup-test-message")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("日志文件未创建: %v", err)
	}
	if !strings.Contains(string(data), "setup-test-message") {
		t.Errorf("日志未写入文件: %q", string(data))
	}

	closeFn()
	if err := os.Remove(path); err != nil {
		t.Errorf("closer 未释放文件句柄: %v", err)
	}
	_ = os.RemoveAll(dir)
}

// Setup 传空路径时只输出 stdout，不应 panic
func TestSetupEmptyFilePath(t *testing.T) {
	closeFn := Setup("", 1, 1)
	log.Println("stdout-only")
	closeFn()
}