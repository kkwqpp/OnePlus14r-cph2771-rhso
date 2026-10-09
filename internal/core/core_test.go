package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Every private key below is generated for a temporary test fixture. No device
// keyboxes, app databases, certificates, account data or phones are used.
var coreTestNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func syntheticKeybox(t *testing.T) []byte {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic root key generation failed")
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-sensitive-root"}, NotBefore: coreTestNow.Add(-time.Hour), NotAfter: coreTestNow.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, MaxPathLen: 5}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal("synthetic root certificate generation failed")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal("synthetic root certificate parse failed")
	}
	var out strings.Builder
	out.WriteString("<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox DeviceID=\"synthetic-sensitive-device-id\">")
	for i, algorithm := range []string{"ecdsa", "rsa"} {
		var signer crypto.Signer
		if algorithm == "ecdsa" {
			signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else {
			signer, err = rsa.GenerateKey(rand.Reader, 2048)
		}
		if err != nil {
			t.Fatal("synthetic signing key generation failed")
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "synthetic-sensitive-signer"}, NotBefore: coreTestNow.Add(-time.Hour), NotAfter: coreTestNow.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, MaxPathLen: 3}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, signer.Public(), rootKey)
		if err != nil {
			t.Fatal("synthetic signing certificate generation failed")
		}
		private, err := x509.MarshalPKCS8PrivateKey(signer)
		if err != nil {
			t.Fatal("synthetic private key encoding failed")
		}
		fmt.Fprintf(&out, "<Key algorithm=\"%s\"><PrivateKey format=\"pem\">%s</PrivateKey><CertificateChain><NumberOfCertificates>2</NumberOfCertificates><Certificate format=\"pem\">%s</Certificate><Certificate format=\"pem\">%s</Certificate></CertificateChain></Key>", algorithm, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	}
	out.WriteString("</Keybox></AndroidAttestation>")
	return []byte(out.String())
}

type sandbox struct {
	app     *App
	old     map[string]FileState
	raw     map[string][]byte
	planID  string
	stageID string
}

func testWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal("fixture file write failed")
	}
}

func newSandbox(t *testing.T, fixture []byte, absent ...string) sandbox {
	t.Helper()
	dir := t.TempDir()
	a := New(filepath.Join(dir, "private"), filepath.Join(dir, "active"), filepath.Join(dir, "modules"), true)
	a.SharedInbox = filepath.Join(dir, "shared-inbox")
	a.Now = func() time.Time { return coreTestNow }
	for _, p := range []string{a.Active, a.SharedInbox, filepath.Join(a.Modules, "playintegrityfix")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal("fixture directory creation failed")
		}
	}
	if err := a.Init(); err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	raw := map[string][]byte{
		"keybox.xml":         fixture,
		"security_patch.txt": []byte("# preserve patch comment\nall=2026-08-05\nno=retain\n"),
		"target.txt":         []byte("# preserve unrelated target comment\norg.example.unrelated?\n  com.google.android.gms\n"),
	}
	for _, n := range absent {
		delete(raw, n)
	}
	for n, body := range raw {
		testWrite(t, filepath.Join(a.Active, n), body)
	}
	testWrite(t, filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), []byte("FINGERPRINT="+fingerprint+"\nSECURITY_PATCH=2026-09-05\n"))
	old, err := a.snapshot()
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	testWrite(t, filepath.Join(a.Root, "inbox", "local.xml"), fixture)
	v, err := a.Ingest(filepath.Join(a.Root, "inbox", "local.xml"))
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	stage := v.(Stage)
	v, err = a.Plan(stage.ID+":0:0:ecdsa,"+stage.ID+":0:1:rsa", true, "2026-09-05")
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireRedacted(t, Response(v, nil))
	id := v.(map[string]any)["id"].(string)
	return sandbox{a, old, raw, id, stage.ID}
}

func mustPlan(t *testing.T, s sandbox) Plan {
	t.Helper()
	p, _, err := s.app.loadPlan(s.planID)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	return p
}
func mustJournal(t *testing.T, a *App) Journal {
	t.Helper()
	var j Journal
	if err := readJSON(filepath.Join(a.Root, "journal.json"), &j); err != nil {
		t.Fatal("journal missing or unreadable")
	}
	return j
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s; operation was accepted", code)
	}
	if got := Response(nil, err).Code; got != code {
		t.Fatalf("expected %s; received %s", code, got)
	}
}
func requireSnapshot(t *testing.T, a *App, expected map[string]FileState) {
	t.Helper()
	got, err := a.snapshot()
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	if !equal(got, expected) {
		t.Fatal("complete file set or metadata differs from expected state (contents withheld)")
	}
}
func requireRedacted(t *testing.T, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal("public response JSON encoding failed")
	}
	for _, forbidden := range []string{"synthetic-sensitive-device-id", "synthetic-sensitive-root", "synthetic-sensitive-signer", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE", "file:///synthetic-secret"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatal("public response exposed synthetic secret content")
		}
	}
}

func TestCoreLocalWorkflowAndNamedRollback(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	validated, err := s.app.Validate(s.stageID)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireRedacted(t, Response(validated, nil))
	p := mustPlan(t, s)
	if len(p.Changes) != 3 {
		t.Fatal("fixture did not plan all three configuration files")
	}
	v, err := s.app.Apply(s.planID)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireRedacted(t, Response(v, nil))
	requireSnapshot(t, s.app, p.Intended)
	result := v.(map[string]any)
	if result["adoption"] != "pending" || result["wallet_acceptance"] != "unverified" || result["files_committed"] != true {
		t.Fatal("commit conflated file success with identity adoption or Wallet acceptance")
	}
	j := mustJournal(t, s.app)
	b, err := s.app.loadBackup(j.Backup)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	if !equal(b.Files, s.old) || b.Verified {
		t.Fatal("backup was not complete or was falsely marked verified")
	}
	for n, original := range s.raw {
		copied, err := os.ReadFile(filepath.Join(s.app.Root, "backups", b.ID, n))
		if err != nil || !bytes.Equal(copied, original) {
			t.Fatal("backup did not preserve original bytes")
		}
	}
	target, _ := os.ReadFile(filepath.Join(s.app.Active, "target.txt"))
	if !bytes.Contains(target, []byte("# preserve unrelated target comment\norg.example.unrelated?\n")) {
		t.Fatal("target repair changed unrelated comments or leaf flags")
	}
	for _, pkg := range requiredPackages {
		count := 0
		for _, l := range strings.Split(string(target), "\n") {
			if strings.TrimSpace(l) == pkg+"!" {
				count++
			}
		}
		if count != 1 {
			t.Fatal("required generate-mode target was not unique")
		}
	}
	merged, _ := os.ReadFile(filepath.Join(s.app.Active, "keybox.xml"))
	if !bytes.Contains(merged, []byte("BEGIN EC PRIVATE KEY")) || !bytes.Contains(merged, []byte("BEGIN RSA PRIVATE KEY")) || bytes.Contains(merged, []byte("DeviceID=\"synthetic-sensitive-device-id\"")) {
		t.Fatal("merge output omitted installed-engine compatible encodings or helper DeviceID")
	}
	v, err = s.app.Verify(true, false)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireRedacted(t, v)
	verify := v.(map[string]any)
	if verify["wallet_readiness"] != "user-confirmed" || verify["tap_to_pay"] != "unverified" || verify["adoption"] != "pending" {
		t.Fatal("verification overstated user or signer evidence")
	}
	_, err = s.app.Rollback("last-verified")
	requireCode(t, err, "E_BACKUP")
	_, err = s.app.Rollback(j.Backup)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireSnapshot(t, s.app, s.old)
}

func TestCoreTargetRepairRequiresExplicitLeafDecision(t *testing.T) {
	for _, tail := range []string{"?", "!?", "!!"} {
		t.Run(tail, func(t *testing.T) {
			original := []byte("# untouched\norg.example.unrelated?\n" + requiredPackages[0] + tail + "\n")
			_, err := repairTargets(original)
			requireCode(t, err, "E_SELECTION")
		})
	}
	_, err := repairTargets([]byte(requiredPackages[0] + "\n" + requiredPackages[0] + "!\n"))
	requireCode(t, err, "E_SELECTION")
	for _, patch := range []string{"all=2026-08-05\nall=2026-07-05\n", "system=2026-08-05\n", "boot=2026-08-05\n", "vendor=2026-08-05\n"} {
		_, err := repairPatch([]byte(patch), "2026-09-05")
		requireCode(t, err, "E_SELECTION")
	}
	s := newSandbox(t, syntheticKeybox(t))
	_, err = s.app.Plan("", false, "2026-10-05")
	requireCode(t, err, "E_SELECTION")
	_, err = s.app.Plan("", false, "2026-99-05")
	requireCode(t, err, "E_INPUT")
	requireSnapshot(t, s.app, s.old)
}

var commitFaultPoints = []string{"before-backup", "after-backup", "after-journal", "before-write-security_patch.txt", "after-write-security_patch.txt", "before-write-target.txt", "after-write-target.txt", "before-write-keybox.xml", "after-write-keybox.xml", "after-file-set", "before-commit-marker", "after-commit-marker"}

func TestCoreReturnedFaultRestoresWholeSet(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, point := range commitFaultPoints {
		t.Run(point, func(t *testing.T) {
			s := newSandbox(t, fixture)
			fired := false
			s.app.Fault = func(name string) error {
				if name == point {
					fired = true
					return errors.New("synthetic storage failure")
				}
				return nil
			}
			_, err := s.app.Apply(s.planID)
			if err == nil || !fired {
				t.Fatal("fault did not abort the operation")
			}
			requireRedacted(t, Response(nil, err))
			requireSnapshot(t, s.app, s.old)
			if point != "before-backup" && point != "after-backup" && mustJournal(t, s.app).State != "restored" {
				t.Fatal("failed commit was not recorded as restored")
			}
			if _, err := os.Lstat(filepath.Join(s.app.Root, "operation.lock")); !os.IsNotExist(err) {
				t.Fatal("returned failure left the operation lock")
			}
		})
	}
}

func TestCorePanicRecoveryAtEveryTransactionBoundary(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, point := range commitFaultPoints {
		t.Run(point, func(t *testing.T) {
			s := newSandbox(t, fixture)
			p := mustPlan(t, s)
			fired := false
			s.app.Fault = func(name string) error {
				if name == point {
					fired = true
					panic("synthetic interrupted process")
				}
				return nil
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("expected injected panic")
					}
				}()
				_, _ = s.app.Apply(s.planID)
			}()
			if !fired {
				t.Fatal("panic boundary was not reached")
			}
			s.app.Fault = nil
			_, err := s.app.Recovery("restore")
			if err != nil {
				t.Fatal(Response(nil, err).Code)
			}
			if point == "after-commit-marker" {
				requireSnapshot(t, s.app, p.Intended)
			} else {
				requireSnapshot(t, s.app, s.old)
			}
		})
	}
}

// Unlike panic, os.Exit does not execute lock-release defers. The parent test
// recreates the App and exercises the persisted journal and stale lock.
func TestCoreCrashChild(t *testing.T) {
	if os.Getenv("WALLETDIAG_TEST_CRASH_CHILD") != "1" {
		t.Skip("subprocess-only crash helper")
	}
	a := New(os.Getenv("WALLETDIAG_TEST_ROOT"), os.Getenv("WALLETDIAG_TEST_ACTIVE"), os.Getenv("WALLETDIAG_TEST_MODULES"), true)
	a.Now = func() time.Time { return coreTestNow }
	a.Fault = func(point string) error {
		if point == os.Getenv("WALLETDIAG_TEST_CRASH_POINT") {
			os.Exit(83)
		}
		if strings.HasPrefix(os.Getenv("WALLETDIAG_TEST_CRASH_POINT"), "before-restore-") && point == "after-file-set" {
			return errors.New("synthetic commit failure entering restoration")
		}
		return nil
	}
	_, _ = a.Apply(os.Getenv("WALLETDIAG_TEST_PLAN"))
	os.Exit(84)
}

func TestCoreLostProcessRecovery(t *testing.T) {
	fixture := syntheticKeybox(t)
	points := append([]string{}, commitFaultPoints...)
	for _, n := range files {
		points = append(points, "before-restore-"+n)
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			s := newSandbox(t, fixture)
			p := mustPlan(t, s)
			cmd := exec.Command(os.Args[0], "-test.run=^TestCoreCrashChild$")
			cmd.Env = append(os.Environ(), "WALLETDIAG_TEST_CRASH_CHILD=1", "WALLETDIAG_TEST_ROOT="+s.app.Root, "WALLETDIAG_TEST_ACTIVE="+s.app.Active, "WALLETDIAG_TEST_MODULES="+s.app.Modules, "WALLETDIAG_TEST_PLAN="+s.planID, "WALLETDIAG_TEST_CRASH_POINT="+point)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("crash child did not exit")
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 83 {
				t.Fatalf("crash child failed before boundary; output length %d", len(out))
			}
			if _, err := os.Stat(filepath.Join(s.app.Root, "operation.lock", "owner.json")); err != nil {
				t.Fatal("os.Exit did not leave the persisted lock")
			}
			fresh := New(s.app.Root, s.app.Active, s.app.Modules, true)
			fresh.Now = s.app.Now
			_, err = fresh.Recovery("restore")
			if err != nil {
				t.Fatal(Response(nil, err).Code)
			}
			if point == "after-commit-marker" {
				requireSnapshot(t, fresh, p.Intended)
			} else {
				requireSnapshot(t, fresh, s.old)
			}
			if _, err := os.Lstat(filepath.Join(fresh.Root, "operation.lock")); !os.IsNotExist(err) {
				t.Fatal("recovered crash left a stale lock")
			}
		})
	}
}

func TestCoreRecoveryLockOwnerAndReboot(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	lock := filepath.Join(s.app.Root, "operation.lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		t.Fatal("lock fixture failed")
	}
	if err := writeJSON(filepath.Join(lock, "owner.json"), lockRecord{os.Getpid(), bootID()}); err != nil {
		t.Fatal("lock fixture failed")
	}
	_, err := s.app.Recovery("release-lock")
	requireCode(t, err, "E_BUSY")
	if err := writeJSON(filepath.Join(lock, "owner.json"), lockRecord{os.Getpid(), "synthetic-previous-boot"}); err != nil {
		t.Fatal("lock fixture failed")
	}
	_, err = s.app.Recovery("release-lock")
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireSnapshot(t, s.app, s.old)
}

func TestCoreRestoreFaultRetainsRecoverableJournal(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, fixture)
			s.app.Fault = func(point string) error {
				if point == "after-write-target.txt" || point == "before-restore-"+name {
					return errors.New("synthetic interrupted restoration")
				}
				return nil
			}
			_, err := s.app.Apply(s.planID)
			requireCode(t, err, "E_RECOVERY")
			if mustJournal(t, s.app).State == "committed" {
				t.Fatal("failed restoration was falsely committed")
			}
			_, err = s.app.Plan("", true, "")
			requireCode(t, err, "E_RECOVERY")
			s.app.Fault = nil
			_, err = s.app.Recovery("restore")
			if err != nil {
				t.Fatal(Response(nil, err).Code)
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
}

func TestCoreCorruptBackupStopsRecoveryWithoutWriting(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, corruption := range []string{"bytes", "missing", "manifest", "unexpected-absent-file", "manifest-metadata", "manifest-missing-state"} {
		t.Run(corruption, func(t *testing.T) {
			var absent []string
			if corruption == "unexpected-absent-file" {
				absent = []string{"target.txt"}
			}
			s := newSandbox(t, fixture, absent...)
			s.app.Fault = func(point string) error {
				if point == "after-write-target.txt" {
					panic("synthetic stopped commit")
				}
				return nil
			}
			func() { defer func() { _ = recover() }(); _, _ = s.app.Apply(s.planID) }()
			s.app.Fault = nil
			j := mustJournal(t, s.app)
			dir := filepath.Join(s.app.Root, "backups", j.Backup)
			switch corruption {
			case "bytes":
				testWrite(t, filepath.Join(dir, "keybox.xml"), []byte("corrupt synthetic backup"))
			case "missing":
				if err := os.Remove(filepath.Join(dir, "keybox.xml")); err != nil {
					t.Fatal("corruption fixture failed")
				}
			case "manifest":
				testWrite(t, filepath.Join(dir, "backup.json"), []byte("{}"))
			case "unexpected-absent-file":
				testWrite(t, filepath.Join(dir, "target.txt"), []byte("unexpected data"))
			case "manifest-metadata", "manifest-missing-state":
				b, e := s.app.loadBackup(j.Backup)
				if e != nil {
					t.Fatal("backup corruption fixture failed")
				}
				if corruption == "manifest-metadata" {
					st := b.Files["keybox.xml"]
					st.Metadata.Mode = 07777
					b.Files["keybox.xml"] = st
				} else {
					delete(b.Files, "target.txt")
					b.Files["unexpected"] = FileState{}
				}
				if e := writeJSON(filepath.Join(dir, "backup.json"), b); e != nil {
					t.Fatal("backup corruption fixture failed")
				}
			}
			interrupted, err := s.app.snapshot()
			if err != nil {
				t.Fatal(Response(nil, err).Code)
			}
			_, err = s.app.Recovery("restore")
			requireCode(t, err, "E_BACKUP")
			requireSnapshot(t, s.app, interrupted)
			if !s.app.unfinished() {
				t.Fatal("corrupt backup cleared recovery requirement")
			}
		})
	}
}

func TestCoreMissingFilesRollbackRestoresAbsence(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t), "target.txt", "security_patch.txt", "keybox.xml")
	_, err := s.app.Apply(s.planID)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	_, err = s.app.Rollback("previous")
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireSnapshot(t, s.app, s.old)
}

func TestCoreBackupFailuresMakeNoActiveChange(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, failure := range []string{"permission", "space", "storage-path"} {
		t.Run(failure, func(t *testing.T) {
			s := newSandbox(t, fixture)
			s.app.Fault = func(point string) error {
				if point != "before-backup" {
					return nil
				}
				switch failure {
				case "permission":
					return os.ErrPermission
				case "space":
					return syscall.ENOSPC
				case "storage-path":
					p := filepath.Join(s.app.Root, "backups")
					if err := os.Remove(p); err != nil {
						return err
					}
					return os.WriteFile(p, []byte("blocked backup destination"), 0600)
				}
				return nil
			}
			_, err := s.app.Apply(s.planID)
			if err == nil {
				t.Fatal("failed backup allowed apply")
			}
			requireSnapshot(t, s.app, s.old)
			if _, err := os.Stat(filepath.Join(s.app.Root, "journal.json")); !os.IsNotExist(err) {
				t.Fatal("backup failure opened a commit journal")
			}
		})
	}
}

func TestCoreStalePlansInputsAndCapabilitiesRejectedBeforeBackup(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, stale := range []string{"active-bytes", "active-absence", "staged-bytes", "proposed-bytes", "capabilities", "expired-input"} {
		t.Run(stale, func(t *testing.T) {
			s := newSandbox(t, fixture)
			switch stale {
			case "active-bytes":
				testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("external current bytes\n"))
			case "active-absence":
				if err := os.Remove(filepath.Join(s.app.Active, "target.txt")); err != nil {
					t.Fatal("stale fixture failed")
				}
			case "staged-bytes":
				testWrite(t, filepath.Join(s.app.Root, "staged", s.stageID, "input.xml"), []byte("changed staged input"))
			case "proposed-bytes":
				testWrite(t, filepath.Join(s.app.Root, "plans", s.planID, "target.txt"), []byte("changed proposal"))
			case "capabilities":
				p := mustPlan(t, s)
				p.Capabilities["reload"] = "changed"
				if err := writeJSON(filepath.Join(s.app.Root, "plans", s.planID, "plan.json"), p); err != nil {
					t.Fatal("stale fixture failed")
				}
			case "expired-input":
				s.app.Now = func() time.Time { return coreTestNow.Add(72 * time.Hour) }
			}
			current, err := s.app.snapshot()
			if err != nil {
				t.Fatal(Response(nil, err).Code)
			}
			_, err = s.app.Apply(s.planID)
			if err == nil {
				t.Fatal("stale plan was accepted")
			}
			requireSnapshot(t, s.app, current)
			entries, _ := os.ReadDir(filepath.Join(s.app.Root, "backups"))
			if len(entries) != 0 {
				t.Fatal("stale plan created a transaction backup")
			}
		})
	}
}

func TestCoreDuplicateApplyAndFailedAdoption(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	_, err := s.app.Apply(s.planID)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	committed, err := s.app.snapshot()
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	_, err = s.app.Apply(s.planID)
	requireCode(t, err, "E_DUPLICATE")
	requireSnapshot(t, s.app, committed)
	s = newSandbox(t, syntheticKeybox(t))
	s.app.Adoption = func() (map[string]any, error) {
		return map[string]any{"health": "failed"}, fail("E_ADOPTION", "Synthetic process health failed.")
	}
	_, err = s.app.Apply(s.planID)
	if err == nil {
		t.Fatal("failed adoption allowed commit")
	}
	requireSnapshot(t, s.app, s.old)
	if mustJournal(t, s.app).State != "restored" {
		t.Fatal("failed adoption did not restore file set")
	}
}

func TestCoreCorruptJournalFailsClosed(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, corrupt := range []string{"{", "{}", `{"schema":99,"state":"committed"}`, `{"schema":1,"state":"unsupported-state"}`, `{"schema":1,"state":"committed"}`, `{"schema":1,"state":"restored"}`} {
		t.Run(hash([]byte(corrupt))[:8], func(t *testing.T) {
			s := newSandbox(t, fixture)
			testWrite(t, filepath.Join(s.app.Root, "journal.json"), []byte(corrupt))
			_, err := s.app.Apply(s.planID)
			requireCode(t, err, "E_RECOVERY")
			requireSnapshot(t, s.app, s.old)
			retained, _ := os.ReadFile(filepath.Join(s.app.Root, "journal.json"))
			if !bytes.Equal(retained, []byte(corrupt)) {
				t.Fatal("unsafe apply overwrote corrupt recovery evidence")
			}
			_, err = s.app.Ingest(filepath.Join(s.app.Root, "inbox", "local.xml"))
			requireCode(t, err, "E_RECOVERY")
			_, err = s.app.Recovery("restore")
			requireCode(t, err, "E_RECOVERY")
		})
	}
}

func TestCorePlanStructuralCorruptionRejectedBeforeBackup(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, corrupt := range []string{"missing-required-active", "missing-required-intended", "duplicate-change", "missing-change", "unknown-change", "unbound-input"} {
		t.Run(corrupt, func(t *testing.T) {
			s := newSandbox(t, fixture)
			p := mustPlan(t, s)
			switch corrupt {
			case "missing-required-active":
				delete(p.Active, "target.txt")
				p.Active["unexpected"] = FileState{}
			case "missing-required-intended":
				delete(p.Intended, "target.txt")
				p.Intended["unexpected"] = FileState{}
			case "duplicate-change":
				p.Changes = append(p.Changes, p.Changes[0])
			case "missing-change":
				p.Changes = p.Changes[:1]
			case "unknown-change":
				p.Changes = append(p.Changes, "../unexpected")
			case "unbound-input":
				p.Inputs = nil
			}
			if err := writeJSON(filepath.Join(s.app.Root, "plans", s.planID, "plan.json"), p); err != nil {
				t.Fatal("corrupt fixture failed")
			}
			_, err := s.app.Apply(s.planID)
			if err == nil {
				t.Fatal("structurally corrupt plan was accepted")
			}
			requireSnapshot(t, s.app, s.old)
			entries, _ := os.ReadDir(filepath.Join(s.app.Root, "backups"))
			if len(entries) != 0 {
				t.Fatal("corrupt plan reached backup or commit")
			}
		})
	}
}

func TestCoreExternalWriterAtWriteBoundaryIsDetected(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, point := range []string{"before-write-security_patch.txt", "after-write-security_patch.txt", "after-file-set", "before-commit-marker"} {
		t.Run(point, func(t *testing.T) {
			s := newSandbox(t, fixture)
			fired := false
			s.app.Fault = func(name string) error {
				if name == point && !fired {
					fired = true
					return os.WriteFile(filepath.Join(s.app.Active, "target.txt"), []byte("external writer data requiring conflict preservation\n"), 0600)
				}
				return nil
			}
			_, err := s.app.Apply(s.planID)
			if !fired || err == nil {
				t.Fatal("concurrent external writer was silently accepted or overwritten")
			}
			entries, readErr := os.ReadDir(filepath.Join(s.app.Root, "backups"))
			if readErr != nil {
				t.Fatal("writer evidence inventory failed")
			}
			preserved := false
			for _, en := range entries {
				b, e := s.app.loadBackup(en.Name())
				if e != nil || b.Type != "external-writer-evidence" {
					continue
				}
				body, e := os.ReadFile(filepath.Join(s.app.Root, "backups", b.ID, "target.txt"))
				if e == nil && bytes.Equal(body, []byte("external writer data requiring conflict preservation\n")) {
					preserved = true
				}
			}
			if !preserved {
				t.Fatal("external writer bytes were not preserved before restoration")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
}

func TestCoreLateProposalChangeNeverReachesActive(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, fixture)
			unsafe := []byte("synthetic invalid proposal changed after preflight\n")
			reachedActive := false
			s.app.Fault = func(point string) error {
				if point == "before-write-"+name {
					return os.WriteFile(filepath.Join(s.app.Root, "plans", s.planID, name), unsafe, 0600)
				}
				if point == "after-write-"+name {
					body, _ := os.ReadFile(filepath.Join(s.app.Active, name))
					reachedActive = bytes.Equal(body, unsafe)
				}
				return nil
			}
			_, err := s.app.Apply(s.planID)
			if err == nil {
				t.Fatal("late proposed-file change was accepted")
			}
			if reachedActive {
				t.Fatal("unvalidated late proposal reached active engine configuration")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
}

func TestCorePathXMLAndResponseRedaction(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	for _, input := range []string{"relative.xml", filepath.Join(filepath.Dir(s.app.Root), "outside.xml"), filepath.Join(s.app.Root, "inbox") + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "local.xml", filepath.Join(s.app.Root, "inbox", "local.xml") + "\n"} {
		_, err := s.app.Ingest(input)
		requireCode(t, err, "E_PATH")
	}
	for _, id := range []string{"../outside", strings.Repeat("f", 31), strings.Repeat("F", 32), strings.Repeat("g", 32), ""} {
		_, err := s.app.Validate(id)
		requireCode(t, err, "E_ID")
	}
	xxe := []byte(`<!DOCTYPE AndroidAttestation [<!ENTITY secret SYSTEM "file:///synthetic-secret">]><AndroidAttestation>&secret;</AndroidAttestation>`)
	xxePath := filepath.Join(s.app.Root, "inbox", "xxe.xml")
	testWrite(t, xxePath, xxe)
	v, err := s.app.Ingest(xxePath)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	_, err = s.app.Validate(v.(Stage).ID)
	if err == nil {
		t.Fatal("external-entity XML was accepted")
	}
	requireRedacted(t, Response(nil, err))
	status, err := s.app.Status()
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireRedacted(t, status)
	requireSnapshot(t, s.app, s.old)
}

func TestCoreSymlinkInputsAndActiveFilesRejected(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	source := filepath.Join(s.app.Root, "inbox", "local.xml")
	link := filepath.Join(s.app.Root, "inbox", "link.xml")
	if err := os.Symlink(source, link); err != nil {
		t.Skip("host does not permit test symlinks; Android symlink verification remains required")
	}
	_, err := s.app.Ingest(link)
	requireCode(t, err, "E_PATH")
	if err := os.Remove(filepath.Join(s.app.Active, "keybox.xml")); err != nil {
		t.Fatal("symlink fixture failed")
	}
	if err := os.Symlink(source, filepath.Join(s.app.Active, "keybox.xml")); err != nil {
		t.Fatal("active symlink fixture failed")
	}
	_, err = s.app.Apply(s.planID)
	requireCode(t, err, "E_PATH")
	if _, err := s.app.snapshot(); err == nil {
		t.Fatal("snapshot followed active symlink")
	}
}

func TestCoreRealModeMissingRuntimeRejectsWithoutApply(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	s.app.Fake = false
	_, err := s.app.Apply(s.planID)
	if err == nil {
		t.Fatal("nonfake mode accepted missing device runtime")
	}
	code := Response(nil, err).Code
	if code != "E_ROOT" && code != "E_CAPABILITY" && code != "E_IO" {
		t.Fatalf("unexpected missing-runtime error %s", code)
	}
	requireSnapshot(t, s.app, s.old)
}
