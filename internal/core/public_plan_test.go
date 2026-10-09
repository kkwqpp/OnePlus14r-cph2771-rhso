package core

import (
	"path/filepath"
	"testing"
	"time"
)

func replanPublicFixture(t *testing.T, s sandbox, retained bool) (any, error) {
	t.Helper()
	selection := s.stageID + ":0:0:ecdsa," + s.stageID + ":0:1:rsa"
	if retained {
		selection = ""
	}
	return s.app.Plan(selection, true, "2026-09-05")
}

func TestPublicListedSelectedAndRetainedPlansStopBeforeBackup(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, state := range []string{"REVOKED", "SUSPENDED"} {
		for _, retained := range []bool{false, true} {
			name := state + "_selected"
			if retained {
				name = state + "_retained"
			}
			t.Run(name, func(t *testing.T) {
				s := newSandbox(t, fixture)
				cache := syntheticPublicCache(t, fixture)
				cache.Status.Body = []byte(`{"entries":{"1":{"status":"` + state + `"}}}`)
				cache.Status.SHA256 = hash(cache.Status.Body)
				saveSyntheticPublicCache(t, s.app, cache)
				_, err := replanPublicFixture(t, s, retained)
				requireCode(t, err, "E_VALIDATION")
				requireSnapshot(t, s.app, s.old)
				backups, err := s.app.Backups()
				if err != nil || len(backups.(map[string]any)["backups"].([]map[string]any)) != 0 {
					t.Fatal("rejected public-status plan created a backup")
				}
			})
		}
	}
}

func TestPublicPlanRefreshOrExpiryRejectsBeforeWrites(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, kind := range []string{"refresh", "expiry", "new-cache"} {
		t.Run(kind, func(t *testing.T) {
			s := newSandbox(t, fixture)
			cache := syntheticPublicCache(t, fixture)
			if kind != "new-cache" {
				saveSyntheticPublicCache(t, s.app, cache)
			}
			v, err := replanPublicFixture(t, s, false)
			if err != nil {
				t.Fatal(Response(nil, err).Code)
			}
			id := v.(map[string]any)["id"].(string)
			if kind == "expiry" {
				s.app.Now = func() time.Time { return coreTestNow.Add(2 * time.Hour) }
			} else {
				cache.Status.Body = []byte(`{"entries":{"2":{"status":"REVOKED"}}}`)
				cache.Status.SHA256 = hash(cache.Status.Body)
				saveSyntheticPublicCache(t, s.app, cache)
			}
			_, err = s.app.Apply(id)
			requireCode(t, err, "E_STALE")
			requireSnapshot(t, s.app, s.old)
			var journal Journal
			if readJSON(filepath.Join(s.app.Root, "journal.json"), &journal) == nil {
				t.Fatal("stale evidence reached a transaction journal")
			}
		})
	}
}

func TestPublicEvidenceChangesAtCommitCompletionRestoreWholeSet(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, boundary := range []string{"after-write-keybox.xml", "before-commit-marker", "after-commit-marker"} {
		for _, kind := range []string{"refresh", "expiry"} {
			t.Run(boundary+"_"+kind, func(t *testing.T) {
				s := newSandbox(t, fixture)
				cache := syntheticPublicCache(t, fixture)
				saveSyntheticPublicCache(t, s.app, cache)
				v, err := replanPublicFixture(t, s, false)
				if err != nil {
					t.Fatal(Response(nil, err).Code)
				}
				id := v.(map[string]any)["id"].(string)
				fired := false
				s.app.Fault = func(at string) error {
					if at == boundary && !fired {
						fired = true
						if kind == "expiry" {
							s.app.Now = func() time.Time { return coreTestNow.Add(2 * time.Hour) }
						} else {
							cache.Status.Body = []byte(`{"entries":{"2":{"status":"SUSPENDED"}}}`)
							cache.Status.SHA256 = hash(cache.Status.Body)
							saveSyntheticPublicCache(t, s.app, cache)
						}
					}
					return nil
				}
				v, err = s.app.Apply(id)
				requireCode(t, err, "E_APPLY")
				if !fired || v.(map[string]any)["state"] != "restored" {
					t.Fatal("evidence change did not restore")
				}
				requireSnapshot(t, s.app, s.old)
				requireRedacted(t, Response(v, err))
			})
		}
	}
}

func TestPublicFreshNonlistedApplyKeepsAcceptancePending(t *testing.T) {
	fixture := syntheticKeybox(t)
	s := newSandbox(t, fixture)
	saveSyntheticPublicCache(t, s.app, syntheticPublicCache(t, fixture))
	v, err := replanPublicFixture(t, s, false)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	id := v.(map[string]any)["id"].(string)
	v, err = s.app.Apply(id)
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	view := v.(map[string]any)
	if view["adoption"] != "pending" || view["wallet_acceptance"] != "unverified" {
		t.Fatal("public-list absence promoted acceptance")
	}
	requireRedacted(t, Response(v, nil))
}
