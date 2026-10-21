package netdiag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The assembly package is PURE: it must never gain its own I/O surface.
// All machine access flows through the injected discovery producers.
func TestNetdiagSourceIsPure(t *testing.T) {
	for _, file := range []string{"netdiag.go", "render.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		for _, banned := range []string{"os/exec", "exec.Command", "os.ReadFile", "os.Open", "net.Dial", "http.Get", "filepath.Walk"} {
			if strings.Contains(s, banned) {
				t.Fatalf("%s must not reference %s", file, banned)
			}
		}
	}
}

// The document's only production consumers are internal/doctor and the
// vps-gateway CLI (pinned): nothing in the mutation/planning stack may
// start reading network diagnostics.
func TestNetdiagConsumersPinned(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/netdiag/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/netdiag") {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			found = append(found, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"internal/doctor/network.go":   true,
		"cmd/vps-gateway/main.go":      true,
		"cmd/vps-gateway/apply.go":     true,
		"cmd/vps-gateway/main_test.go": true,
	}
	for _, f := range found {
		if !allowed[f] {
			t.Fatalf("unexpected production consumer of internal/netdiag: %s", f)
		}
	}
}
