package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Only synthetic configuration/keys in temporary fake-engine directories.
const stackSyntheticHMA = `{"configVersion":93,"futureGlobal":{"keep":123456789012345678901234567890},"altAppDataIsolation":true,"defaultConfig":{"useWhitelist":false,"extraAppList":["org.example.previous"],"extraOppositeAppList":[],"futureDefault":{"retain":true}},"scope":{"com.google.android.gms":{"useWhitelist":false,"extraAppList":["org.example.previous"],"extraOppositeAppList":[],"hideInstallationSource":true,"futureLocal":[1,2,3]},"org.example.unrelated":{"useWhitelist":true,"extraAppList":["org.example.privatefixture"],"futureApp":"synthetic-sensitive-private-app"}},"templates":{"synthetic-sensitive-template":{"future":true}},"settingsTemplates":{}}`

type stackSandbox struct {
	sandbox
	path     string
	original []byte
	before   FileState
	parent   Metadata
	locator  string
}

func newStackSandbox(t *testing.T, body []byte) stackSandbox {
	t.Helper()
	s := newSandbox(t, syntheticKeybox(t))
	a := s.app
	for _, p := range []string{filepath.Join(a.stackBasePath(), "misc", "hide_my_applist_abcdefghijklmnop"), filepath.Join(a.stackBasePath(), "adb", "brezygisk")} {
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	path := filepath.Join(a.stackBasePath(), "misc", "hide_my_applist_abcdefghijklmnop", "config.json")
	if body == nil {
		body = []byte(stackSyntheticHMA)
	}
	testWrite(t, path, body)
	st, _, parent, loc, e := a.stackRead("hma-config", "")
	if e != nil {
		t.Fatal(e)
	}
	return stackSandbox{s, path, body, st, parent, loc}
}
func stackPlanID(t *testing.T, a *App, profile, targets, packages, enabled string) string {
	t.Helper()
	v, e := a.Stack("plan", profile, targets, packages, enabled, "")
	if e != nil {
		t.Fatalf("stack plan: %s", Response(nil, e).Code)
	}
	return v.(map[string]any)["id"].(string)
}
func stackCall(t *testing.T, a *App, action, id string) map[string]any {
	t.Helper()
	v, e := a.Stack(action, "", "", "", "", id)
	if e != nil {
		t.Fatalf("stack %s: %s", action, Response(nil, e).Code)
	}
	out := v.(map[string]any)
	if out["manual_reboot_required"] != true || out["runtime_adoption"] != "unknown" {
		t.Fatal("file readback overstated runtime adoption")
	}
	return out
}
func requireStackOriginal(t *testing.T, s stackSandbox) {
	t.Helper()
	st, b, par, _, e := s.app.stackRead("hma-config", s.locator)
	if e != nil || st != s.before || par != s.parent || !bytes.Equal(b, s.original) {
		t.Fatal("full resource bytes/metadata were not restored")
	}
	now, e := s.app.snapshot()
	if e != nil || !equal(now, s.old) {
		t.Fatal("protected TrickyStore files changed")
	}
}
func requireStackRedacted(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	for _, s := range []string{"synthetic-sensitive-private-app", "synthetic-sensitive-template", "org.example.privatefixture", "org.example.hidden", "hide_my_applist_abcdefghijklmnop", "config.json", "resource.bin", "futureGlobal"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("stack view leaked private configuration: %s", s)
		}
	}
}
func TestStackHMAPreservationApplyVerifyRollback(t *testing.T) {
	s := newStackSandbox(t, nil)
	id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms,com.android.vending", "org.example.hidden", "")
	p, _, e := s.app.stackLoadPlan(id)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Changes) != 2 {
		t.Fatal("selected scopes missing")
	}
	requireStackRedacted(t, p.view())
	out := stackCall(t, s.app, "apply", id)
	if out["state"] != "committed" {
		t.Fatal(out)
	}
	current, e := bounded(s.path, stackLimit)
	if e != nil {
		t.Fatal(e)
	}
	var before, after map[string]json.RawMessage
	_ = stackJSON(s.original, &before)
	_ = stackJSON(current, &after)
	for _, key := range []string{"futureGlobal", "altAppDataIsolation", "templates", "settingsTemplates", "defaultConfig"} {
		if !bytes.Equal(bytes.TrimSpace(before[key]), bytes.TrimSpace(after[key])) {
			var b, a any
			json.Unmarshal(before[key], &b)
			json.Unmarshal(after[key], &a)
			if !equalJSON(b, a) {
				t.Fatalf("unrelated %s changed", key)
			}
		}
	}
	var scopeBefore, scopeAfter map[string]json.RawMessage
	json.Unmarshal(before["scope"], &scopeBefore)
	json.Unmarshal(after["scope"], &scopeAfter)
	var oldScope, newScope map[string]json.RawMessage
	json.Unmarshal(scopeBefore["com.google.android.gms"], &oldScope)
	json.Unmarshal(scopeAfter["com.google.android.gms"], &newScope)
	for _, key := range []string{"useWhitelist", "hideInstallationSource", "futureLocal", "extraOppositeAppList"} {
		var b, a any
		json.Unmarshal(oldScope[key], &b)
		json.Unmarshal(newScope[key], &a)
		if !equalJSON(b, a) {
			t.Fatalf("selected scope unrelated %s changed", key)
		}
	}
	var unrelatedBefore, unrelatedAfter any
	json.Unmarshal(scopeBefore["org.example.unrelated"], &unrelatedBefore)
	json.Unmarshal(scopeAfter["org.example.unrelated"], &unrelatedAfter)
	if !equalJSON(unrelatedBefore, unrelatedAfter) {
		t.Fatal("unselected scope changed")
	}
	requireStackRedacted(t, stackCall(t, s.app, "verify", id))
	s.app.Now = func() time.Time { return coreTestNow.Add(time.Hour) }
	stackCall(t, s.app, "verify", id)
	stackCall(t, s.app, "rollback", id)
	requireStackOriginal(t, s)
	stackCall(t, s.app, "verify", id)
	if s.app.stackUnfinished() {
		t.Fatal("terminal restored transaction remained pending")
	}
}
func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func TestStackMarkerAbsenceAndExactExistingRestoration(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "originally_absent", true: "originally_present"}[existing], func(t *testing.T) {
			s := newStackSandbox(t, nil)
			path, _, e := s.app.stackPath("brezygisk-unmount", "")
			if e != nil {
				t.Fatal(e)
			}
			original := []byte("retain original marker bytes\n")
			if existing {
				testWrite(t, path, original)
			}
			before, _, parent, _, e := s.app.stackRead("brezygisk-unmount", "")
			if e != nil {
				t.Fatal(e)
			}
			enabled := "true"
			if existing {
				enabled = "false"
			}
			id := stackPlanID(t, s.app, "brezygisk-unmount", "", "", enabled)
			stackCall(t, s.app, "apply", id)
			stackCall(t, s.app, "verify", id)
			stackCall(t, s.app, "rollback", id)
			st, b, par, _, e := s.app.stackRead("brezygisk-unmount", "")
			if e != nil || st != before || par != parent || !bytes.Equal(b, func() []byte {
				if existing {
					return original
				}
				return nil
			}()) {
				t.Fatal("marker presence/bytes/meta not restored")
			}
		})
	}
}
func TestStackHMARefusesAmbiguityAndProtectedPackages(t *testing.T) {
	cases := []struct {
		name, body, targets, packages string
		code                          string
	}{
		{"duplicate_root", `{"configVersion":93,"configVersion":93,"scope":{}}`, "com.google.android.gms", "org.example.hidden", "E_CAPABILITY"},
		{"duplicate_unknown", `{"configVersion":93,"scope":{},"future":{"x":1,"x":2}}`, "com.google.android.gms", "org.example.hidden", "E_CAPABILITY"},
		{"wrong_schema", `{"configVersion":94,"scope":{}}`, "com.google.android.gms", "org.example.hidden", "E_CAPABILITY"},
		{"whitelist", `{"configVersion":93,"scope":{"com.google.android.gms":{"useWhitelist":true}}}`, "com.google.android.gms", "org.example.hidden", "E_SELECTION"},
		{"default_whitelist", `{"configVersion":93,"defaultConfig":{"useWhitelist":true},"scope":{}}`, "com.google.android.gms", "org.example.hidden", "E_SELECTION"},
		{"null_whitelist", `{"configVersion":93,"scope":{"com.google.android.gms":{"useWhitelist":null}}}`, "com.google.android.gms", "org.example.hidden", "E_FORMAT"},
		{"opposite", `{"configVersion":93,"scope":{"com.google.android.gms":{"extraOppositeAppList":["org.example.hidden"]}}}`, "com.google.android.gms", "org.example.hidden", "E_SELECTION"},
		{"protected_target", stackSyntheticHMA, "com.google.android.gms", "com.google.android.apps.walletnfcrel", "E_SELECTION"},
		{"protected_system", stackSyntheticHMA, "com.google.android.gms", "com.android.permissioncontroller", "E_SELECTION"},
		{"protected_hma", stackSyntheticHMA, "com.google.android.gms", "org.frknkrc44.hma_oss", "E_SELECTION"},
		{"unsupported_target", stackSyntheticHMA, "org.example.unrelated", "org.example.hidden", "E_SELECTION"},
		{"duplicate_selection", stackSyntheticHMA, "com.google.android.gms", "org.example.hidden,org.example.hidden", "E_SELECTION"},
		{"bad_package", stackSyntheticHMA, "com.google.android.gms", "org.example.hidden;touch /x", "E_SELECTION"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newStackSandbox(t, []byte(c.body))
			_, e := s.app.Stack("plan", "hma-scope", c.targets, c.packages, "", "")
			requireCode(t, e, c.code)
			requireStackOriginal(t, s)
		})
	}
}
func TestStackMissingDefaultCreatesOnlyExplicitScope(t *testing.T) {
	for _, root := range []string{`{"configVersion":93,"scope":{},"unknown":[null,3]}`, `{"configVersion":93,"scope":{},"defaultConfig":null,"unknown":[null,3]}`} {
		s := newStackSandbox(t, []byte(root))
		id := stackPlanID(t, s.app, "hma-scope", "com.android.vending", "org.example.hidden", "")
		p, _, e := s.app.stackLoadPlan(id)
		if e != nil {
			t.Fatal(e)
		}
		if p.Changes[0]["scopes_created"].(float64) != 1 {
			t.Fatal("new scope creation missing in review")
		}
		stackCall(t, s.app, "apply", id)
		stackCall(t, s.app, "rollback", id)
		requireStackOriginal(t, s)
	}
}
func TestStackStaleBindingsAndDuplicateApply(t *testing.T) {
	for _, change := range []string{"resource", "protected", "pif", "module", "parent", "intent", "plan_metadata", "other_resource", "expired"} {
		t.Run(change, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
			p, dir, e := s.app.stackLoadPlan(id)
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "resource":
				testWrite(t, s.path, append(s.original, ' '))
			case "protected":
				testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("external target\n"))
			case "pif":
				testWrite(t, filepath.Join(s.app.Modules, "playintegrityfix", "custom.pif.prop"), []byte("external pif\n"))
			case "module":
				testWrite(t, filepath.Join(s.app.Modules, "playintegrityfix", "module.prop"), []byte("external module\n"))
			case "parent":
				if e := os.Chmod(filepath.Dir(s.path), 0500); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(filepath.Dir(s.path), 0700)
			case "intent":
				testWrite(t, filepath.Join(dir, "intent.bin"), []byte("tampered"))
			case "plan_metadata":
				p.After.Metadata.Mode = 0777
				writeJSON(filepath.Join(dir, "plan.json"), p)
			case "other_resource":
				path, _, _ := s.app.stackPath("brezygisk-unmount", "")
				testWrite(t, path, []byte("external marker"))
			case "expired":
				s.app.Now = func() time.Time { return coreTestNow.Add(31 * time.Minute) }
			}
			_, e = s.app.Stack("apply", "", "", "", "", id)
			if e == nil {
				t.Fatal("stale or corrupt review applied")
			}
			if change != "resource" {
				b, _ := bounded(s.path, stackLimit)
				if !bytes.Equal(b, s.original) {
					t.Fatal("failed preflight modified HMA")
				}
			}
		})
	}
	s := newStackSandbox(t, nil)
	id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
	stackCall(t, s.app, "apply", id)
	_, e := s.app.Stack("apply", "", "", "", "", id)
	requireCode(t, e, "E_DUPLICATE")
}
func TestStackFaultBoundariesRestoreOrLeaveRecovery(t *testing.T) {
	for _, point := range []string{"stack-before-backup", "before-backup", "after-backup", "stack-after-backup", "stack-before-write", "stack-after-write", "stack-before-commit", "stack-after-commit"} {
		t.Run(point, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
			hit := false
			s.app.Fault = func(p string) error {
				if p == point && !hit {
					hit = true
					return errors.New("synthetic injected failure")
				}
				return nil
			}
			_, e := s.app.Stack("apply", "", "", "", "", id)
			if e == nil || !hit {
				t.Fatal("fault boundary not reached")
			}
			requireStackOriginal(t, s)
			if s.app.stackUnfinished() {
				t.Fatal("successful failure restoration remained unfinished")
			}
		})
	}
	for _, point := range []string{"stack-before-restore", "stack-after-restore"} {
		t.Run(point, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
			stackCall(t, s.app, "apply", id)
			s.app.Fault = func(p string) error {
				if p == point {
					return errors.New("synthetic restore failure")
				}
				return nil
			}
			_, e := s.app.Stack("rollback", "", "", "", "", id)
			requireCode(t, e, "E_RECOVERY")
			if !s.app.stackUnfinished() {
				t.Fatal("interrupted restore was not gated")
			}
			s.app.Fault = nil
			stackCall(t, s.app, "rollback", id)
			requireStackOriginal(t, s)
		})
	}
}

func TestStackStrictRequestArgumentsAndUTF8(t *testing.T) {
	s := newStackSandbox(t, nil)
	for _, action := range []string{"status", "apply", "verify", "rollback"} {
		for _, field := range []string{"profile", "targets", "packages", "enabled"} {
			args := [6]string{action, "", "", "", "", ""}
			index := map[string]int{"profile": 1, "targets": 2, "packages": 3, "enabled": 4}[field]
			args[index] = "synthetic-unrelated-selection"
			_, e := s.app.Stack(args[0], args[1], args[2], args[3], args[4], args[5])
			requireCode(t, e, "E_REQUEST")
		}
	}
	_, e := s.app.Stack("status", "", "", "", "", strings.Repeat("a", 32))
	requireCode(t, e, "E_REQUEST")
	_, e = s.app.Stack("plan", "hma-scope", "com.google.android.gms", "org.example.hidden", "", strings.Repeat("a", 32))
	requireCode(t, e, "E_REQUEST")
	bad := append([]byte(`{"configVersion":93,"scope":{},"future":"`), 0xff)
	bad = append(bad, []byte(`"}`)...)
	var value any
	if e = stackJSON(bad, &value); e == nil {
		t.Fatal("invalid UTF-8 was repaired rather than rejected")
	}
	requireStackOriginal(t, s)
}

func TestStackProtectedBackupAssociationIntegrity(t *testing.T) {
	s := newStackSandbox(t, nil)
	id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
	stackCall(t, s.app, "apply", id)
	b, e := s.app.stackLoadBackup(id)
	if e != nil || b.ProtectedBackup == "" || !equal(b.Protected, s.old) {
		t.Fatal("stack Apply omitted its complete protected-file backup association")
	}
	protected, e := s.app.loadBackup(b.ProtectedBackup)
	if e != nil || protected.Type != "stack-profile" || !equal(protected.Files, s.old) {
		t.Fatal("associated protected-file backup was not independently verified")
	}
	current, _ := bounded(s.path, stackLimit)
	protectedDir, _ := s.app.object("backups", b.ProtectedBackup)
	testWrite(t, filepath.Join(protectedDir, "target.txt"), []byte("synthetic corrupt protected backup"))
	_, e = s.app.Stack("verify", "", "", "", "", id)
	requireCode(t, e, "E_BACKUP")
	operation := s.app.stackStatus()["operation"].(map[string]any)
	if operation["backup_available"] != false || operation["can_verify"] != false || operation["can_rollback"] != false {
		t.Fatal("corrupt protected backup was presented as available")
	}
	_, e = s.app.Stack("rollback", "", "", "", "", id)
	requireCode(t, e, "E_RECOVERY")
	after, _ := bounded(s.path, stackLimit)
	if !bytes.Equal(current, after) {
		t.Fatal("corrupt protected association allowed a stack rollback write")
	}
	now, e := s.app.snapshot()
	if e != nil || !equal(now, s.old) {
		t.Fatal("stack recovery restored or changed protected configuration")
	}
}

func TestStackExplicitRollbackCurrentSnapshot(t *testing.T) {
	for _, profile := range []string{"hma-scope", "brezygisk-unmount"} {
		t.Run(profile, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			targets, packages, enabled := "com.google.android.gms", "org.example.hidden", ""
			if profile == "brezygisk-unmount" {
				targets, packages, enabled = "", "", "true"
			}
			id := stackPlanID(t, s.app, profile, targets, packages, enabled)
			p, _, _ := s.app.stackLoadPlan(id)
			stackCall(t, s.app, "apply", id)
			before, body, parent, _, e := s.app.stackRead(p.Resource, p.Locator)
			if e != nil {
				t.Fatal(e)
			}
			dir, _ := s.app.stackObject("backups", id)
			original, _ := bounded(filepath.Join(dir, "resource.bin"), stackLimit)
			stackCall(t, s.app, "rollback", id)
			var r stackBackup
			if e = stackReadJSON(filepath.Join(dir, "rollback-current.json"), &r); e != nil || r.Before != before || r.Parent != parent {
				t.Fatal("rollback did not preserve actual current bytes/existence/metadata")
			}
			saved, e := bounded(filepath.Join(dir, "rollback-current.bin"), stackLimit)
			if e != nil || !bytes.Equal(saved, body) {
				t.Fatal("actual pre-rollback resource bytes were not saved")
			}
			pb, e := s.app.loadBackup(r.ProtectedBackup)
			if e != nil || pb.Type != "stack-profile" || !equal(pb.Files, s.old) {
				t.Fatal("rollback omitted its fresh verified protected-file backup")
			}
			if profile == "hma-scope" {
				again, _ := bounded(filepath.Join(dir, "resource.bin"), stackLimit)
				if !bytes.Equal(original, again) {
					t.Fatal("rollback replaced the immutable original resource backup")
				}
			}
			requireStackOriginal(t, s)
		})
	}
}

func TestStackRollbackLateContextAndBackupFailures(t *testing.T) {
	for _, kind := range []string{"protected", "pif", "other-resource", "protected-backup-after-restore", "rollback-backup-failure", "rollback-current-corruption"} {
		t.Run(kind, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
			stackCall(t, s.app, "apply", id)
			applied, _ := bounded(s.path, stackLimit)
			b, _ := s.app.stackLoadBackup(id)
			hit := false
			s.app.Fault = func(point string) error {
				if point == "stack-before-restore" {
					path := ""
					switch kind {
					case "protected":
						path = filepath.Join(s.app.Active, "target.txt")
					case "pif":
						path = filepath.Join(s.app.Modules, "playintegrityfix", "custom.pif.prop")
					case "other-resource":
						path, _, _ = s.app.stackPath("brezygisk-unmount", "")
					}
					if path != "" {
						hit = true
						testWrite(t, path, []byte("synthetic external context"))
					}
				}
				if kind == "protected-backup-after-restore" && point == "stack-after-restore" {
					hit = true
					dir, _ := s.app.object("backups", b.ProtectedBackup)
					testWrite(t, filepath.Join(dir, "target.txt"), []byte("synthetic late backup corruption"))
				}
				if kind == "rollback-backup-failure" && point == "before-backup" {
					hit = true
					return errors.New("synthetic rollback backup failure")
				}
				if kind == "rollback-current-corruption" && point == "stack-after-rollback-backup" {
					hit = true
					dir, _ := s.app.stackObject("backups", id)
					testWrite(t, filepath.Join(dir, "rollback-current.bin"), []byte("synthetic corruption"))
				}
				return nil
			}
			out, e := s.app.Stack("rollback", "", "", "", "", id)
			requireCode(t, e, "E_RECOVERY")
			if !hit || out != nil || !s.app.stackUnfinished() {
				t.Fatal("late rollback fault produced a verified result or lost recovery gate")
			}
			after, _ := bounded(s.path, stackLimit)
			if kind == "protected-backup-after-restore" {
				if !bytes.Equal(after, s.original) {
					t.Fatal("completed restoration bytes were not retained")
				}
			} else if !bytes.Equal(after, applied) {
				t.Fatal("late context/backup fault allowed rollback resource write")
			}
			if kind == "protected" {
				body, _ := bounded(filepath.Join(s.app.Active, "target.txt"), stackLimit)
				if string(body) != "synthetic external context" {
					t.Fatal("stack rollback restored protected files over external context")
				}
			}
		})
	}
}
func TestStackLostProcessRecoveryAndCorruptBackup(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "recover", true: "corrupt_backup"}[corrupt], func(t *testing.T) {
			s := newStackSandbox(t, nil)
			id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
			s.app.Fault = func(point string) error {
				if point == "stack-after-write" {
					panic("synthetic process loss")
				}
				return nil
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("loss fault not reached")
					}
				}()
				s.app.Stack("apply", "", "", "", "", id)
			}()
			s.app.Fault = nil
			if !s.app.stackUnfinished() {
				t.Fatal("lost process did not require recovery")
			}
			_, e := s.app.Stack("plan", "brezygisk-unmount", "", "", "true", "")
			requireCode(t, e, "E_RECOVERY")
			if corrupt {
				dir, _ := s.app.stackObject("backups", id)
				testWrite(t, filepath.Join(dir, "resource.bin"), []byte("corrupt backup"))
				before, _ := bounded(s.path, stackLimit)
				_, e = s.app.Stack("rollback", "", "", "", "", id)
				requireCode(t, e, "E_RECOVERY")
				after, _ := bounded(s.path, stackLimit)
				if !bytes.Equal(before, after) || !s.app.stackUnfinished() {
					t.Fatal("corrupt backup recovery touched resource or removed gate")
				}
				return
			}
			stackCall(t, s.app, "rollback", id)
			requireStackOriginal(t, s)
		})
	}
}
func TestStackExternalWritersRemainPreserved(t *testing.T) {
	for _, point := range []string{"stack-before-write", "stack-after-write", "stack-before-commit", "stack-after-commit", "stack-before-restore"} {
		t.Run(point, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
			conflict := append(append([]byte{}, s.original...), []byte("\n ")...)
			hit := false
			s.app.Fault = func(p string) error {
				if p == point && !hit {
					hit = true
					testWrite(t, s.path, conflict)
				}
				return nil
			}
			if point == "stack-before-restore" {
				s.app.Fault = nil
				stackCall(t, s.app, "apply", id)
				s.app.Fault = func(p string) error {
					if p == point && !hit {
						hit = true
						testWrite(t, s.path, conflict)
					}
					return nil
				}
				_, _ = s.app.Stack("rollback", "", "", "", "", id)
			} else {
				_, _ = s.app.Stack("apply", "", "", "", "", id)
			}
			b, _ := bounded(s.path, stackLimit)
			if !hit || !bytes.Equal(b, conflict) || !s.app.stackUnfinished() {
				t.Fatal("external writer was overwritten or recovery gate lost")
			}
			if point != "stack-before-restore" {
				dir, _ := s.app.stackObject("backups", id)
				saved, e := bounded(filepath.Join(dir, "conflict.bin"), stackLimit)
				if e != nil || !bytes.Equal(saved, conflict) {
					t.Fatal("external writer evidence not preserved")
				}
			}
		})
	}
}
func TestStackCorruptJournalAndForeignResetFailClosed(t *testing.T) {
	for _, which := range []string{"stack", "protected", "reset"} {
		t.Run(which, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			path := map[string]string{"stack": "stack-journal.json", "protected": "journal.json", "reset": "reset-journal.json"}[which]
			testWrite(t, filepath.Join(s.app.Root, path), []byte(`{"invalid":"synthetic-sensitive-private-app"}`))
			if which == "stack" && !s.app.stackUnfinished() {
				t.Fatal("corrupt journal did not fail closed")
			}
			_, e := s.app.Stack("plan", "hma-scope", "com.google.android.gms", "org.example.hidden", "", "")
			requireCode(t, e, "E_RECOVERY")
			requireStackRedacted(t, s.app.stackStatus())
			requireStackOriginal(t, s)
		})
	}
}
func TestStackUnsafePathsAndAmbiguousDiscovery(t *testing.T) {
	for _, which := range []string{"multiple", "file_directory", "symlink_file", "marker_symlink"} {
		t.Run(which, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			profile, targets, pkgs, enabled := "hma-scope", "com.google.android.gms", "org.example.hidden", ""
			switch which {
			case "multiple":
				os.Mkdir(filepath.Join(s.app.stackBasePath(), "misc", "hide_my_applist_ponmlkjihgfedcba"), 0700)
			case "file_directory":
				os.Remove(s.path)
				os.Mkdir(s.path, 0700)
			case "symlink_file":
				os.Remove(s.path)
				outside := filepath.Join(t.TempDir(), "unrelated")
				testWrite(t, outside, []byte(stackSyntheticHMA))
				if e := os.Symlink(outside, s.path); e != nil {
					t.Skip("symlink privileges unavailable")
				}
			case "marker_symlink":
				profile, targets, pkgs, enabled = "brezygisk-unmount", "", "", "true"
				path, _, _ := s.app.stackPath("brezygisk-unmount", "")
				outside := filepath.Join(t.TempDir(), "unrelated")
				testWrite(t, outside, []byte("preserve"))
				if e := os.Symlink(outside, path); e != nil {
					t.Skip("symlink privileges unavailable")
				}
			}
			_, e := s.app.Stack("plan", profile, targets, pkgs, enabled, "")
			if e == nil {
				t.Fatal("unsafe or ambiguous resource accepted")
			}
		})
	}
}
func TestStackEvidenceTracksLiveBytesAfterCommit(t *testing.T) {
	s := newStackSandbox(t, nil)
	first, e := s.app.stackEvidenceBinding()
	if e != nil {
		t.Fatal(e)
	}
	id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
	stackCall(t, s.app, "apply", id)
	second, e := s.app.stackEvidenceBinding()
	if e != nil || first == second {
		t.Fatal("commit did not invalidate previous evidence")
	}
	testWrite(t, s.path, append(s.original, ' '))
	third, e := s.app.stackEvidenceBinding()
	if e != nil || third == second {
		t.Fatal("live external bytes ignored after committed journal")
	}
	_, e = s.app.Stack("verify", "", "", "", "", id)
	requireCode(t, e, "E_STALE")
}

func TestStackMetadataCaseAliasesRejectAndGate(t *testing.T) {
	s := newStackSandbox(t, nil)
	id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
	p, dir, e := s.app.stackLoadPlan(id)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(p)
	b = append(b[:len(b)-1], []byte(`,"ID":"`+strings.Repeat("a", 32)+`"}`)...)
	testWrite(t, filepath.Join(dir, "plan.json"), b)
	_, e = s.app.Stack("apply", "", "", "", "", id)
	requireCode(t, e, "E_FORMAT")
	requireStackOriginal(t, s)
	j := stackJournal{1, id, "hma-scope", "hma-config", p.Locator, "committed", s.app.time(), p.Before, p.After, p.Parent}
	b, _ = json.Marshal(j)
	b = append(b[:len(b)-1], []byte(`,"State":"restored"}`)...)
	testWrite(t, filepath.Join(s.app.Root, "stack-journal.json"), b)
	if !s.app.stackUnfinished() {
		t.Fatal("case aliases bypassed recovery gate")
	}
}

func TestStackOptionalAbsenceAndCrossFeatureEvidence(t *testing.T) {
	t.Run("ordinary_misc_without_hma", func(t *testing.T) {
		s := newSandbox(t, syntheticKeybox(t))
		if e := os.MkdirAll(filepath.Join(s.app.stackBasePath(), "misc"), 0700); e != nil {
			t.Fatal(e)
		}
		if _, e := s.app.stackEvidenceBinding(); e != nil {
			t.Fatal("optional HMA absence blocked core evidence")
		}
		// Both a missing optional backend parent and an empty readable parent
		// establish the same HMA absence; directory creation adds no configuration.
		if _, e := s.app.Apply(s.planID); e != nil {
			t.Fatal("optional HMA absence invalidated an otherwise current core plan")
		}
	})
	t.Run("old_keybox_plan_marker_change", func(t *testing.T) {
		s := newStackSandbox(t, nil)
		v, e := s.app.Plan(s.stageID+":0:0:ecdsa,"+s.stageID+":0:1:rsa", true, "2026-09-05")
		if e != nil {
			t.Fatal(e)
		}
		id := v.(map[string]any)["id"].(string)
		p, _, _ := s.app.stackPath("brezygisk-unmount", "")
		testWrite(t, p, nil)
		_, e = s.app.Apply(id)
		requireCode(t, e, "E_STALE")
		requireStackOriginal(t, s)
	})
	for _, resource := range []string{"marker", "pif"} {
		t.Run("verification_persistence_"+resource, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			v, e := s.app.Plan(s.stageID+":0:0:ecdsa,"+s.stageID+":0:1:rsa", true, "2026-09-05")
			if e != nil {
				t.Fatal(e)
			}
			id := v.(map[string]any)["id"].(string)
			if _, e = s.app.Apply(id); e != nil {
				t.Fatal(e)
			}
			before, e := s.app.stackEvidenceBinding()
			if e != nil {
				t.Fatal(e)
			}
			s.app.Fault = func(p string) error {
				if p == "before-verification-persist" {
					path := filepath.Join(s.app.Modules, "playintegrityfix", "custom.pif.prop")
					if resource == "marker" {
						path, _, _ = s.app.stackPath("brezygisk-unmount", "")
					}
					testWrite(t, path, []byte("synthetic external state"))
				}
				return nil
			}
			_, e = s.app.Verify(true, false)
			requireCode(t, e, "E_STALE")
			after, e := s.app.stackEvidenceBinding()
			if e != nil || after == before {
				t.Fatal("external state failed to invalidate evidence")
			}
			if _, e = os.Lstat(filepath.Join(s.app.Root, "verification.json")); !os.IsNotExist(e) {
				t.Fatal("stale readiness was persisted")
			}
		})
	}
}
func TestStackOtherResourceLateMutationAndRestoredBackupIntegrity(t *testing.T) {
	s := newStackSandbox(t, nil)
	id := stackPlanID(t, s.app, "hma-scope", "com.google.android.gms", "org.example.hidden", "")
	hit := false
	s.app.Fault = func(p string) error {
		if p == "stack-after-commit" && !hit {
			hit = true
			path, _, _ := s.app.stackPath("brezygisk-unmount", "")
			testWrite(t, path, nil)
		}
		return nil
	}
	_, e := s.app.Stack("apply", "", "", "", "", id)
	requireCode(t, e, "E_ROLLED_BACK")
	requireStackOriginal(t, s)
	s.app.Fault = nil
	dir, _ := s.app.stackObject("backups", id)
	testWrite(t, filepath.Join(dir, "resource.bin"), []byte("corrupted restored backup"))
	_, e = s.app.Stack("rollback", "", "", "", "", id)
	requireCode(t, e, "E_BACKUP")
	st := s.app.stackStatus()["operation"].(map[string]any)
	if st["backup_available"] != false || st["can_verify"] != false {
		t.Fatal("corrupt restored backup reported verified")
	}
}
func TestStackUnsupportedJournalTransitionFailsClosed(t *testing.T) {
	for _, field := range []string{"parent_mode", "parent_context", "hma_absent", "hma_metadata", "marker_payload"} {
		t.Run(field, func(t *testing.T) {
			s := newStackSandbox(t, nil)
			profile, targets, pkgs, enabled := "hma-scope", "com.google.android.gms", "org.example.hidden", ""
			if field == "marker_payload" {
				profile, targets, pkgs, enabled = "brezygisk-unmount", "", "", "true"
			}
			id := stackPlanID(t, s.app, profile, targets, pkgs, enabled)
			p, _, e := s.app.stackLoadPlan(id)
			if e != nil {
				t.Fatal(e)
			}
			j := stackJournal{1, id, p.Profile, p.Resource, p.Locator, "committed", s.app.time(), p.Before, p.After, p.Parent}
			switch field {
			case "parent_mode":
				j.Parent.Mode = 0777
			case "parent_context":
				j.Parent.SELinux = "synthetic-invalid-label"
			case "hma_absent":
				j.Before = FileState{}
			case "hma_metadata":
				j.After.Metadata.Mode = 0400
			case "marker_payload":
				j.After.Size = 1
				j.After.SHA256 = hash([]byte("x"))
			}
			writeJSON(filepath.Join(s.app.Root, "stack-journal.json"), j)
			if !s.app.stackUnfinished() {
				t.Fatal("unsupported terminal journal bypassed gate")
			}
			_, e = s.app.Stack("plan", "brezygisk-unmount", "", "", "true", "")
			requireCode(t, e, "E_RECOVERY")
			requireStackRedacted(t, s.app.stackStatus())
		})
	}
}
