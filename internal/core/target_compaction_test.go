package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTargetCompactionPreservesRulesCommentsAndBytes(t *testing.T) {
	for _, tc := range []struct {
		name, input, want          string
		entries, removed, packages int
	}{
		{"interleaved", "# keep\ncom.example.one!\ncom.example.two?\ncom.example.one!\n\ncom.example.two?\n", "# keep\ncom.example.one!\ncom.example.two?\n\n", 4, 2, 2},
		{"crlf-and-spacing", "# comment\r\n \tcom.example.one! \t\r\ncom.example.two\r\ncom.example.one!\r\n# retain\r\n", "# comment\r\n \tcom.example.one! \t\r\ncom.example.two\r\n# retain\r\n", 3, 1, 2},
		{"framework-unflagged", "android\ncom.example.one\nandroid\ncom.example.one", "android\ncom.example.one\n", 4, 2, 2},
		{"unique-no-final-newline", "# !? not a rule\ncom.example.one?\ncom.example.two!", "# !? not a rule\ncom.example.one?\ncom.example.two!", 2, 0, 2},
		{"comments-only", "# only comment\n\t\n", "# only comment\n\t\n", 0, 0, 0},
		{"empty", "", "", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, summary, err := compactTargets([]byte(tc.input))
			if err != nil || string(out) != tc.want {
				t.Fatal("compaction failed to preserve selected rule semantics and unrelated bytes")
			}
			if summary != (TargetCompactionSummary{tc.entries, tc.entries - tc.removed, tc.removed, tc.packages}) {
				t.Fatal("compaction counts do not describe actual removals")
			}
			again, next, err := compactTargets(out)
			if err != nil || !bytes.Equal(again, out) || next.RemovedEntries != 0 {
				t.Fatal("compaction is not idempotent")
			}
		})
	}
}

func TestTargetCompactionRejectsAmbiguousOrUnsupportedTargets(t *testing.T) {
	for _, tc := range []struct{ name, input, code string }{
		{"last-mode-wins-counterexample", "com.example.one!\ncom.example.one?\ncom.example.one!\n", "E_SELECTION"},
		{"unflagged-conflict", "com.example.one\ncom.example.one!\n", "E_SELECTION"},
		{"conflict-after-other-duplicates", "com.example.two!\ncom.example.two!\ncom.example.one!\ncom.example.one?\n", "E_SELECTION"},
		{"leading-marker", "!com.example.one\n", "E_SELECTION"},
		{"repeated-marker", "com.example.one!!\n", "E_SELECTION"},
		{"mixed-marker", "com.example.one!?\n", "E_SELECTION"},
		{"indented-comment", " # does not start with raw comment prefix\n", "E_SELECTION"},
		{"inline-comment", "com.example.one! # commentary\n", "E_SELECTION"},
		{"path", "/data/adb/unknown\n", "E_SELECTION"},
		{"uid", "1000\n", "E_SELECTION"},
		{"unicode-space", "\u00a0com.example.one\n", "E_SELECTION"},
		{"bare-carriage-return", "com.example.one\rcom.example.two\n", "E_SELECTION"},
		{"control", "com.example.one\x01\n", "E_SELECTION"},
		{"nul-comment", "# comment\x00\n", "E_INPUT"},
		{"invalid-utf8", string([]byte{'#', 0xff, '\n'}), "E_INPUT"},
		{"oversize", strings.Repeat("#", (1<<20)+1), "E_INPUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, summary, err := compactTargets([]byte(tc.input))
			requireCode(t, err, tc.code)
			if out != nil || summary != (TargetCompactionSummary{}) {
				t.Fatal("rejected list exposed a partially compacted result")
			}
		})
	}
}

func compactionPlan(t *testing.T, s sandbox, body string, repair bool) (Plan, map[string]FileState) {
	t.Helper()
	testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte(body))
	before, err := s.app.snapshot()
	if err != nil {
		t.Fatal("fixture snapshot failed")
	}
	v, err := s.app.Plan("", repair, "", true)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	view := v.(map[string]any)
	id := view["id"].(string)
	p, _, err := s.app.loadPlan(id)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	if p.TargetCompaction == nil || view["target_compaction"] == nil {
		t.Fatal("compaction lacks explicit redacted review")
	}
	return p, before
}

func TestTargetCompactionPlanApplyBacksUpAndPreservesOtherFiles(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	input := "# keep\ncom.example.one!\ncom.example.two?\ncom.example.one!\n\ncom.example.two?\n"
	p, before := compactionPlan(t, s, input, false)
	pifPath := filepath.Join(s.app.Modules, "playintegrityfix", "custom.pif.prop")
	pif, _ := os.ReadFile(pifPath)
	if !reflect.DeepEqual(p.Changes, []string{"target.txt"}) || len(p.Inputs) != 0 || len(p.Selections) != 0 || p.Intended["keybox.xml"] != before["keybox.xml"] || p.Intended["security_patch.txt"] != before["security_patch.txt"] {
		t.Fatal("compaction silently selected another repair or regenerated the keybox")
	}
	if got := p.Preview[0]["removed_lines"].([]any); !reflect.DeepEqual(got, []any{"com.example.one!", "com.example.two?"}) {
		t.Fatal("preview hides exact duplicate removals")
	}
	if got := p.Preview[0]["added_lines"].([]any); len(got) != 0 {
		t.Fatal("compaction added target rules")
	}
	state, _ := s.app.snapshot()
	if !equal(state, before) {
		t.Fatal("planning changed active files")
	}
	v, err := s.app.Apply(p.ID)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	after, err := s.app.snapshot()
	if err != nil || !equal(after, p.Intended) {
		t.Fatal("applied bytes or metadata do not match reviewed plan")
	}
	backupID := v.(map[string]any)["backup"].(string)
	b, err := s.app.loadBackup(backupID)
	if err != nil || !equal(b.Files, before) {
		t.Fatal("compaction lacks a checked complete previous-set backup")
	}
	pifAfter, _ := os.ReadFile(pifPath)
	if !bytes.Equal(pif, pifAfter) {
		t.Fatal("compaction changed PIF")
	}
	if _, err = s.app.Plan("", false, "", true); Response(nil, err).Code != "E_SELECTION" {
		t.Fatal("already compacted target list produced a new change")
	}
	if _, err = s.app.Rollback(backupID); err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	restored, _ := s.app.snapshot()
	if !equal(restored, before) {
		t.Fatal("named rollback failed to restore target list and all metadata")
	}
}

func TestTargetCompactionCombinesOnlyExplicitTargetRepair(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	p, _ := compactionPlan(t, s, "# keep\norg.example.unrelated?\ncom.google.android.gms\ncom.google.android.gms\n", true)
	prepared, err := os.ReadFile(filepath.Join(s.app.Root, "plans", p.ID, "target.txt"))
	if err != nil {
		t.Fatal("prepared targets missing")
	}
	if strings.Count(string(prepared), "com.google.android.gms!\n") != 1 || !bytes.Contains(prepared, []byte("# keep\norg.example.unrelated?\n")) || p.TargetCompaction.RemovedEntries != 1 || len(p.Changes) != 1 {
		t.Fatal("explicit repair and compaction did not preserve unrelated rules")
	}
}

func TestTargetCompactionGuardedPlansAndStaleInputs(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, kind := range []string{"pending-reset", "invalid-keybox", "unsupported", "conflict", "stale-target", "excess-options"} {
		t.Run(kind, func(t *testing.T) {
			s := newSandbox(t, fixture)
			testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("com.example.one!\ncom.example.one!\n"))
			code := "E_SELECTION"
			switch kind {
			case "pending-reset":
				if err := writeJSON(filepath.Join(s.app.Root, "reset-journal.json"), finalResetFixture()); err != nil {
					t.Fatal("fixture write failed")
				}
				code = "E_RECOVERY"
			case "invalid-keybox":
				testWrite(t, filepath.Join(s.app.Active, "keybox.xml"), []byte("invalid"))
				code = "E_VALIDATION"
			case "unsupported":
				testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("com.example.one!\n # unsupported\n"))
			case "conflict":
				testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("com.example.one!\ncom.example.one?\n"))
			case "excess-options":
				code = "E_REQUEST"
			}
			before, _ := s.app.snapshot()
			var v any
			var err error
			if kind == "excess-options" {
				v, err = s.app.Plan("", false, "", true, false)
			} else {
				v, err = s.app.Plan("", false, "", true)
			}
			if kind == "stale-target" {
				if err != nil {
					t.Fatal("fresh fixture plan failed")
				}
				id := v.(map[string]any)["id"].(string)
				testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("com.example.one!\ncom.example.one!\ncom.example.two?\n"))
				before, _ = s.app.snapshot()
				_, err = s.app.Apply(id)
				code = "E_STALE"
			}
			requireCode(t, err, code)
			after, _ := s.app.snapshot()
			if !equal(before, after) {
				t.Fatal("rejected optimizer plan/apply changed active files")
			}
			backups, _ := os.ReadDir(filepath.Join(s.app.Root, "backups"))
			if len(backups) != 0 {
				t.Fatal("rejected optimizer plan/apply created a backup")
			}
		})
	}
}

func TestTargetCompactionFailureRestoresCompleteSet(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, point := range []string{"after-journal", "before-write-target.txt", "after-write-target.txt", "before-commit-marker", "after-commit-marker"} {
		t.Run(point, func(t *testing.T) {
			s := newSandbox(t, fixture)
			p, before := compactionPlan(t, s, "# preserved\ncom.example.one!\ncom.example.one!\n", false)
			s.app.Fault = func(p string) error {
				if p == point {
					return errors.New("synthetic compaction interruption")
				}
				return nil
			}
			_, err := s.app.Apply(p.ID)
			requireCode(t, err, "E_APPLY")
			after, e := s.app.snapshot()
			if e != nil || !equal(after, before) {
				t.Fatal("failed compaction did not restore the complete previous bytes and metadata")
			}
			var j Journal
			if readJSON(filepath.Join(s.app.Root, "journal.json"), &j) != nil || j.State != "restored" {
				t.Fatal("failed compaction left an incorrect recovery state")
			}
		})
	}
}
