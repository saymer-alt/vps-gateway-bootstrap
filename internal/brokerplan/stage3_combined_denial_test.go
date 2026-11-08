package brokerplan_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokeradmission"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerplan"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceadoption"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceunitcontent"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceunitmeta"
)

// P1-C5D tripwire: an agent can supply all three individually plausible
// artifacts (an Ed25519 adoption-intent statement, stable disk bytes and an
// exact v2 restart approval). None is independently acquired adoption-grade
// ownership. The assembled broker gate MUST still fail closed before any
// privileged execution. This is purely synthetic; it never invokes systemctl.
func TestCombinedSignedAdoptionAndDiskReviewCannotMakeBrokerReady(t *testing.T) {
	const host = "machine-id:1111222233334444aaaabbbbccccdddd"
	const fragment = "/usr/lib/systemd/system/fail2ban.service"
	const fingerprint = "synthetic-full-plan-fingerprint"
	const grant = "muvg.service.restart.v1;unit=fail2ban.service"
	const unitBytes = "[Unit]\nDescription=Fail2Ban\n[Service]\nType=simple\nExecStart=/usr/bin/fail2ban-server -xf start\n"
	const unitMetadata = "Id=fail2ban.service\nLoadState=loaded\n" +
		"FragmentPath=" + fragment + "\nDropInPaths=\nSourcePath=\n" +
		"Transient=no\nUnitFileState=enabled\n"
	const reloadMetadata = "Id=fail2ban.service\nNeedDaemonReload=no\n"

	queryMetadata := []string{
		"--system", "show", "--all", "fail2ban.service",
		"--property=Id", "--property=LoadState", "--property=FragmentPath",
		"--property=DropInPaths", "--property=SourcePath",
		"--property=Transient", "--property=UnitFileState",
	}
	queryReload := []string{
		"--system", "show", "--all", "fail2ban.service",
		"--property=Id", "--property=NeedDaemonReload",
	}
	var queryCalls, readCalls int
	show := func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		if binary != "systemctl" {
			t.Fatalf("unexpected binary: %s", binary)
		}
		defer func() { queryCalls++ }()
		switch queryCalls {
		case 0, 3:
			if !reflect.DeepEqual(args, queryMetadata) {
				t.Fatalf("unexpected metadata query: %v", args)
			}
			return []byte(unitMetadata), nil
		case 1, 2:
			if !reflect.DeepEqual(args, queryReload) {
				t.Fatalf("unexpected reload query: %v", args)
			}
			return []byte(reloadMetadata), nil
		default:
			t.Fatalf("unexpected additional systemctl query")
			return nil, nil
		}
	}
	reader := func(ctx context.Context, path string) (serviceunitcontent.Blob, error) {
		readCalls++
		if path != fragment {
			t.Fatalf("reader called with unexpected path: %q", path)
		}
		return serviceunitcontent.Blob{
			Path: path, Regular: true, Data: []byte(unitBytes),
		}, nil
	}
	disk, err := serviceunitcontent.Review(context.Background(), serviceunitmeta.Runner(show), reader)
	if err != nil || disk.Status != serviceunitcontent.DiskStableOnly ||
		disk.SHA256 == "" || queryCalls != 4 || readCalls != 2 {
		t.Fatalf("fixture must produce positive-but-untrusted disk review: %+v / %v", disk, err)
	}

	now := time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	intent := serviceadoption.Statement{
		SchemaVersion: serviceadoption.SchemaVersion,
		Purpose: serviceadoption.Purpose,
		Resource: serviceadoption.PinnedResource,
		Unit: serviceadoption.PinnedUnit,
		HostIdentity: host,
		IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	adoptionArtifact := approval.Artifact{
		Payload: payload, Signature: ed25519.Sign(priv, payload),
	}
	if _, err := serviceadoption.VerifyForReview(adoptionArtifact, pub, host, now); err != nil {
		t.Fatalf("synthetic independent adoption-intent signature must verify: %v", err)
	}

	restart, err := approval.SignPayloadV2(approval.PayloadV2{
		SchemaVersion: approval.SchemaVersionV2,
		Purpose: string(approval.PurposeServiceExperimentV1),
		PlanFingerprint: fingerprint,
		HostIdentity: host,
		ExpiresAt: now.Add(time.Hour),
		Capabilities: []string{grant},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(brokerproto.Request{
		SchemaVersion: brokerproto.Version,
		Operation: brokerproto.RestartPinnedFail2ban,
		Payload: restart.Payload,
		Signature: restart.Signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := approval.Verifier{
		TrustAnchor: pub, HostIdentity: host,
		Now: func() time.Time { return now },
	}
	if err := brokeradmission.VerifyPinnedRestartRequest(raw, verifier, fingerprint); err != nil {
		t.Fatalf("synthetic signed-v2 restart must independently verify: %v", err)
	}

	candidate := brokerplan.Candidate{
		Fingerprint: fingerprint,
		HostIdentity: host,
		OwnershipSource: "unverified-legacy-config-assertion",
	}
	if candidate.Snapshot().Ready {
		t.Fatal("reviewable disk + valid adoption intent became Stage-3 authority")
	}
	gate := brokergate.Gate{
		ExpectedAgentUID: 1001, ExpectedAgentGID: 1001,
		ReadPeer: func() (brokergate.Peer, error) {
			return brokergate.Peer{PID: 42, UID: 1001, GID: 1001}, nil
		},
		ReadPlan: func() (brokergate.PlanSnapshot, error) {
			return candidate.Snapshot(), nil
		},
		ReadVerifier: func() (approval.Verifier, error) {
			return verifier, nil
		},
	}
	if err := gate.CheckOnly(raw); err == nil ||
		!strings.Contains(err.Error(), "not a ready pinned service plan") {
		t.Fatalf("positive synthetic signals bypassed independent ownership denial: %v", err)
	}
}
