package agent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8(t *testing.T) {
	s := strings.Repeat("中", 100) // 每个字符 3 字节
	got := truncateUTF8(s, 10)
	if !utf8.ValidString(got) {
		t.Fatalf("截断产生了非法 UTF-8: %q", got)
	}
	if len(got) > 10 {
		t.Errorf("截断后长度 %d > 10", len(got))
	}
	if n := utf8.RuneCountInString(got); n != 3 {
		t.Errorf("期望 3 个完整字符，got %d", n)
	}
	// 未超长时原样返回
	if got := truncateUTF8("abc", 10); got != "abc" {
		t.Errorf("未超长不应改变内容: %q", got)
	}
}
