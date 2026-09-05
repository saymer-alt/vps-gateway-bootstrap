package lock

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAcquireReleaseAndReacquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vps-gateway.lock")
	l, err := Acquire(path)
	if err != nil { t.Fatal(err) }
	if _, err := Acquire(path); err == nil { t.Fatal("second acquire while held must fail") }
	if err := l.Release(); err != nil { t.Fatal(err) }
	l2, err := Acquire(path)
	if err != nil { t.Fatalf("reacquire after release failed: %v", err) }
	if err := l2.Release(); err != nil { t.Fatal(err) }
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("lock file must be removed: %v", err) }
}

// All contenders try to take the lock and HOLD it until the test says so.
// Exactly one can ever hold it; the others must fail while the winner holds.
func TestConcurrentAcquireHasSingleWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vps-gateway.lock")
	const contenders = 8
	var wg sync.WaitGroup
	winner := make(chan *Lock, 1)
	losers := make(chan struct{}, contenders)
	hold := make(chan struct{})
	start := make(chan struct{})
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l, err := Acquire(path)
			if err != nil {
				losers <- struct{}{}
				return
			}
			winner <- l
			<-hold
			// Release is done by the test via the winner's Lock handle.
		}()
	}
	close(start)

	wins, losses := 0, 0
	var held *Lock
	for wins+losses < contenders {
		select {
		case l := <-winner:
			wins++
			held = l
		case <-losers:
			losses++
		}
	}
	if wins != 1 { t.Fatalf("exactly one contender must hold the lock, got %d", wins) }
	close(hold)
	wg.Wait()
	if err := held.Release(); err != nil { t.Fatal(err) }
	again, err := Acquire(path)
	if err != nil { t.Fatalf("lock must be free after release: %v", err) }
	if err := again.Release(); err != nil { t.Fatal(err) }
}

func TestAcquireRejectsEmptyPath(t *testing.T) {
	if _, err := Acquire(""); err == nil { t.Fatal("expected empty path rejection") }
}
