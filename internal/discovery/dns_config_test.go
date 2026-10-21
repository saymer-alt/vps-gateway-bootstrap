package discovery

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

type dnsFiles struct {
	content *string
	link    *string
	readErr error
	linkErr error
	run     Runner
}

func (d dnsFiles) collector() *Collector {
	if d.run == nil {
		d.run = healthRunner(map[string][3]string{
			"systemd-resolved.service": {"loaded", "active", "running"},
		})
	}
	return &Collector{
		Run: d.run,
		ReadFile: func(string) ([]byte, error) {
			if d.readErr != nil {
				return nil, d.readErr
			}
			if d.content == nil {
				return nil, fs.ErrNotExist
			}
			return []byte(*d.content), nil
		},
		Readlink: func(string) (string, error) {
			if d.linkErr != nil {
				return "", d.linkErr
			}
			if d.link == nil {
				return "", errors.New("not a symlink")
			}
			return *d.link, nil
		},
	}
}

func strp(s string) *string { return &s }

func TestCollectDNSConfigRegularFile(t *testing.T) {
	c := dnsFiles{content: strp("nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions edns0\n")}.collector()
	ev := c.CollectDNSConfig(context.Background())
	if ev.Status != FactStatusOK || ev.FileKind != DNSFileRegular || ev.EvidenceLevel != netdiagEvidenceConfigInferred {
		t.Fatalf("evidence = %+v", ev)
	}
	if len(ev.Nameservers) != 2 || ev.Nameservers[0] != "1.1.1.1" {
		t.Fatalf("nameservers = %v", ev.Nameservers)
	}
	if ev.StubResolver {
		t.Fatal("no stub expected")
	}
}

func TestCollectDNSConfigSymlinkVariants(t *testing.T) {
	// Symlink with readable target.
	c := dnsFiles{content: strp("nameserver 127.0.0.53\n"), link: strp("/run/systemd/resolve/stub-resolv.conf")}.collector()
	ev := c.CollectDNSConfig(context.Background())
	if ev.FileKind != DNSFileSymlink || ev.SymlinkTarget != "/run/systemd/resolve/stub-resolv.conf" || ev.Status != FactStatusOK {
		t.Fatalf("evidence = %+v", ev)
	}
	if !ev.StubResolver || ev.Resolved.Status != FactStatusOK {
		t.Fatalf("stub/resolved = %v/%s", ev.StubResolver, ev.Resolved.Status)
	}

	// Broken symlink: positively broken configuration.
	c = dnsFiles{readErr: fs.ErrNotExist, link: strp("/run/systemd/resolve/stub-resolv.conf"),
		run: fakeRunner{outputs: map[string][]byte{}}}.collector()
	ev = c.CollectDNSConfig(context.Background())
	if ev.FileKind != DNSFileBroken || ev.Status != FactStatusFail {
		t.Fatalf("broken symlink evidence = %+v", ev)
	}

	// Missing file: positively broken configuration, observed fact.
	c = dnsFiles{}.collector()
	ev = c.CollectDNSConfig(context.Background())
	if ev.FileKind != DNSFileMissing || ev.Status != FactStatusFail || ev.EvidenceLevel != netdiagEvidenceObserved {
		t.Fatalf("missing evidence = %+v", ev)
	}

	// Unreadable: a broken reader is never a broken network.
	c = dnsFiles{readErr: fs.ErrPermission, linkErr: fs.ErrPermission}.collector()
	ev = c.CollectDNSConfig(context.Background())
	if ev.Status != FactStatusInconclusive || ev.FileKind != DNSFileReadErr {
		t.Fatalf("unreadable evidence = %+v", ev)
	}
}

func TestCollectDNSConfigNoNameserversAndMalformed(t *testing.T) {
	// No nameserver directives at all.
	c := dnsFiles{content: strp("options edns0\nsearch example.invalid\n")}.collector()
	ev := c.CollectDNSConfig(context.Background())
	if ev.Status != FactStatusFail || len(ev.Nameservers) != 0 {
		t.Fatalf("no-nameserver evidence = %+v", ev)
	}

	// Malformed nameserver lines: INCONCLUSIVE with counts, never content.
	c = dnsFiles{content: strp("nameserver\nnameserver not-an-address\n")}.collector()
	ev = c.CollectDNSConfig(context.Background())
	if ev.Status != FactStatusInconclusive || ev.MalformedNameserverCount != 2 {
		t.Fatalf("malformed evidence = %+v", ev)
	}
	for _, u := range ev.Unknowns {
		if strings.Contains(u, "not-an-address") {
			t.Fatalf("unknown echoes directive content: %q", u)
		}
	}
}

func TestCollectDNSConfigStubWithoutResolvedFails(t *testing.T) {
	// resolv.conf points at the resolved stub while the unit is absent:
	// positively observed inconsistency (the resolver blackholes).
	c := &Collector{
		ReadFile: func(string) ([]byte, error) { return []byte("nameserver 127.0.0.53\n"), nil },
		Readlink: func(string) (string, error) { return "", errors.New("not a symlink") },
		Run:      fakeRunner{outputs: map[string][]byte{`systemctl show -p LoadState -p ActiveState -p SubState systemd-resolved.service`: []byte("LoadState=not-found\nActiveState=inactive\nSubState=dead\n")}},
	}
	ev := c.CollectDNSConfig(context.Background())
	if ev.Status != FactStatusFail {
		t.Fatalf("stub-without-resolved evidence = %+v", ev)
	}
	if !ev.StubResolver || ev.Resolved.LoadState != "not-found" {
		t.Fatalf("evidence = %+v", ev)
	}
}
