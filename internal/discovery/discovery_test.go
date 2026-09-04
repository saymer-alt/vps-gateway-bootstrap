package discovery

import "testing"

func TestSplitEndpoint(t *testing.T) {
	cases := []struct{ in, wantHost string; wantPort int }{
		{"0.0.0.0:22", "0.0.0.0", 22},
		{"[::]:2222", "::", 2222},
		{"127.0.0.1:7890", "127.0.0.1", 7890},
	}
	for _, tc := range cases {
		h, p := splitEndpoint(tc.in)
		if h != tc.wantHost || p != tc.wantPort { t.Fatalf("splitEndpoint(%q) = %q:%d, want %q:%d", tc.in, h, p, tc.wantHost, tc.wantPort) }
	}
}

func TestAppendUnique(t *testing.T) {
	got := appendUnique([]int{22, 2222}, 2222)
	if len(got) != 2 { t.Fatalf("duplicate was appended: %#v", got) }
	got = appendUnique(got, 2200)
	if len(got) != 3 || got[2] != 2200 { t.Fatalf("new value not appended: %#v", got) }
}
