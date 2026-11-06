package db

import "testing"

// 纯逻辑测试：父子关系/根域推导（不依赖数据库）。
func TestBaseDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a.example.com", "example.com"},
		{"example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"a.example.co.uk", "example.co.uk"},
		{"api.example.com.cn", "example.com.cn"},
		{"example.com:8080", "example.com"},
		{"10.0.0.1", "10.0.0.1"},
		{"[::1]", "::1"},
		{"localhost", "localhost"},
		{"", ""},
	}
	for _, c := range cases {
		if got := baseDomain(c.in); got != c.want {
			t.Errorf("baseDomain(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}
