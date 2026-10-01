//go:build linux

package fileobs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Real-filesystem collector behavior (ZAI-28 §47: temporary directories,
// synthetic harmless contents — never /etc, never production paths). The
// collector itself is path-agnostic: path confinement lives in ObserveFile,
// so the real DefaultCollector is exercised against temp paths at the
// collector+normalize boundary, while ObserveFile's confinement is tested
// through the injected seam (fileobs_test.go).

func col() *Collector { return DefaultCollector() }

func normFor(t *testing.T, id ownership.ResourceIdentity, raw rawObservation) FileObservation {
	t.Helper()
	o, err := normalize(id, state.ActionCreateFile, raw)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestCollectorRegularFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "managed.conf")
	if err := os.WriteFile(p, []byte("key: value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := col().Observe(p)
	if raw.LstatClass != errNone || !raw.LstatIsReg || raw.LstatIsSymlink {
		t.Fatalf("lstat legs wrong: %+v", raw)
	}
	if raw.OpenClass != errNone || raw.OpenMode != 0600 {
		t.Fatalf("open legs wrong: %+v", raw)
	}
	if raw.LstatDev != raw.OpenDev || raw.LstatIno != raw.OpenIno {
		t.Fatalf("dev/ino must agree for a stable file: %+v", raw)
	}
	if string(raw.Content) != "key: value\n" {
		t.Fatalf("content mismatch: %q", raw.Content)
	}
	o := normFor(t, fileID(nsPath), raw)
	if o.Status != StatusPresent || o.SpecHash == nil || o.Mode != 0600 {
		t.Fatalf("normalized: %+v", o)
	}
}

func TestCollectorEmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.conf")
	if err := os.WriteFile(p, nil, 0644); err != nil {
		t.Fatal(err)
	}
	raw := col().Observe(p)
	if raw.LstatClass != errNone || !raw.LstatIsReg || raw.OpenClass != errNone || len(raw.Content) != 0 {
		t.Fatalf("empty file legs wrong: %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusPresent {
		t.Fatalf("empty file must normalize PRESENT: %+v", o)
	}
}

func TestCollectorAbsent(t *testing.T) {
	raw := col().Observe(filepath.Join(t.TempDir(), "missing.conf"))
	if raw.LstatClass != errNotFound {
		t.Fatalf("missing entry must classify errNotFound: %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusAbsent {
		t.Fatalf("normalized: %+v", o)
	}
	// A missing parent chain is also positive absence at the collector
	// layer (ENOTDIR/ENOENT classification).
	raw = col().Observe(filepath.Join(t.TempDir(), "no", "such", "child.conf"))
	if raw.LstatClass != errNotFound {
		t.Fatalf("missing parent must classify errNotFound: %+v", raw)
	}
}

func TestCollectorSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	raw := col().Observe(link)
	if raw.LstatClass != errNone || !raw.LstatIsSymlink || raw.LstatIsReg {
		t.Fatalf("symlink must be observed at the entry itself (no follow): %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusPresentUnsupported {
		t.Fatalf("symlink must normalize PRESENT_UNSUPPORTED: %+v", o)
	}

	// A broken symlink still has a directory entry: occupancy, not absence.
	broken := filepath.Join(dir, "broken.link")
	if err := os.Symlink(filepath.Join(dir, "vanished"), broken); err != nil {
		t.Fatal(err)
	}
	raw = col().Observe(broken)
	if raw.LstatClass != errNone || !raw.LstatIsSymlink {
		t.Fatalf("broken symlink must be an observed entry: %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusPresentUnsupported {
		t.Fatalf("broken symlink must never be ABSENT: %+v", o)
	}
}

func TestCollectorSymlinkLoopFailsClosed(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "loop-a")
	b := filepath.Join(dir, "loop-b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	// lstat of the loop entry itself succeeds (it is a symlink entry);
	// ELOOP fires when the path must be TRAVERSED through the loop, so
	// observe a child under it.
	raw := col().Observe(filepath.Join(a, "child.conf"))
	if raw.LstatClass != errLoop {
		t.Fatalf("traversal through a symlink loop must classify errLoop: %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusUnknown {
		t.Fatalf("loop must stay UNKNOWN: %+v", o)
	}
}

func TestCollectorDirectoryAtTarget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "subdir")
	if err := os.Mkdir(p, 0755); err != nil {
		t.Fatal(err)
	}
	raw := col().Observe(p)
	if raw.LstatClass != errNone || raw.LstatIsReg || raw.LstatIsSymlink {
		t.Fatalf("directory legs wrong: %+v", raw)
	}
	if raw.OpenClass != errNone || raw.Content != nil {
		t.Fatalf("non-regular shapes must not be opened: %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusPresentUnsupported {
		t.Fatalf("normalized: %+v", o)
	}
}

func TestCollectorFIFOAtTarget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(p, 0644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	raw := col().Observe(p)
	if raw.LstatClass != errNone || raw.LstatIsReg || raw.LstatIsSymlink {
		t.Fatalf("FIFO legs wrong: %+v", raw)
	}
	if o := normFor(t, fileID(nsPath), raw); o.Status != StatusPresentUnsupported {
		t.Fatalf("FIFO must normalize PRESENT_UNSUPPORTED: %+v", o)
	}
}

// O_NOFOLLOW proof at the collector layer: a symlink swapped in after a
// regular-file lstat would be refused by the kernel — simulated directly by
// observing a symlink (the entry classifies as symlink at lstat) and by the
// injected-seam ELOOP matrix in fileobs_test.go.
func TestCollectorSymlinkSwapRefusalEndToEnd(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.conf")
	if err := os.WriteFile(real, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "swap.conf")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// The collector never follows: observing the symlink path yields the
	// symlink's own entry, not the target's regular-file record.
	raw := col().Observe(link)
	if !raw.LstatIsSymlink {
		t.Fatalf("collector followed a symlink: %+v", raw)
	}
	if len(raw.Content) != 0 {
		t.Fatalf("no content may be read through a symlink: %+v", raw)
	}
}
