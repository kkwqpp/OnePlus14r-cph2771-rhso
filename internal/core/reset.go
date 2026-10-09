package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func (a *App) validateReset(r resetJournal, review bool) error {
	bad := func() error {
		return fail("E_RECOVERY", "Reset journal or review is incomplete, corrupt or unsupported. Preserve it; do not repeat app-data clearing.")
	}
	if r.Schema != 1 || !validHash.MatchString(r.ReviewHash) || !validHash.MatchString(r.PIFHash) || len(r.Scripts) != 3 {
		return bad()
	}
	for _, n := range []string{"action.sh", "autopif4.sh", "killpi.sh"} {
		if !validHash.MatchString(r.Scripts[n]) {
			return bad()
		}
	}
	if _, e := time.Parse(time.RFC3339, r.Time); e != nil {
		return bad()
	}
	if !validUser.MatchString(r.User) || (!a.Fake && !validBoot.MatchString(r.Boot)) {
		return bad()
	}
	if review {
		if r.State != "reviewed" || r.Step != 0 || r.Backup != "" {
			return bad()
		}
		return nil
	}
	if !validID.MatchString(r.Backup) || r.Step < 0 || r.Step > 5 {
		return bad()
	}
	switch r.State {
	case "clearing":
	case "attempting-clear", "failed-do-not-repeat":
		if r.Step > 4 {
			return bad()
		}
	case "awaiting-manual-reboot", "completed":
		if r.Step != 5 {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}

const resetPhrase = "CLEAR WALLET AND GOOGLE SERVICES"

type resetJournal struct {
	Schema     int               `json:"schema"`
	State      string            `json:"state"`
	Boot       string            `json:"boot"`
	User       string            `json:"user"`
	ReviewHash string            `json:"review_hash"`
	Scripts    map[string]string `json:"scripts"`
	Step       int               `json:"step"`
	Time       string            `json:"time"`
	Backup     string            `json:"backup"`
	PIFHash    string            `json:"pif_hash"`
}

var validUser = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})$`)

func (a *App) currentUser() (string, error) {
	if a.Fake {
		return "0", nil
	}
	u, e := run("/system/bin/am", "get-current-user")
	u = strings.TrimSpace(u)
	if e != nil || !validUser.MatchString(u) {
		return "", fail("E_CAPABILITY", "The current Android user could not be verified; reset is blocked.")
	}
	return u, nil
}

func (a *App) resetBoot() (string, error) {
	b := bootID()
	if !a.Fake && !validBoot.MatchString(b) {
		return "", fail("E_CAPABILITY", "The current boot identity could not be verified; reset is blocked.")
	}
	return b, nil
}

func resetHash(scripts map[string]string, pif []byte, config map[string]FileState, user string) string {
	return hash([]byte(scripts["action.sh"] + scripts["autopif4.sh"] + scripts["killpi.sh"] + hash(pif) + config["keybox.xml"].SHA256 + config["target.txt"].SHA256 + config["security_patch.txt"].SHA256 + hash([]byte(user))))
}

func (a *App) resetResumeContext(r resetJournal) error {
	b, e := a.resetBoot()
	if e != nil {
		return e
	}
	if r.Boot == b {
		return fail("E_CONFIRM", "The device has not rebooted since the confirmed clears. Reboot manually before resume.")
	}
	u, e := a.currentUser()
	if e != nil {
		return e
	}
	if u != r.User {
		return fail("E_STALE", "The Android user changed since reset confirmation. Return to the reviewed user before resuming; do not repeat the clears.")
	}
	return nil
}

func (a *App) resetScripts() (map[string]string, error) {
	result := map[string]string{}
	// These are the reviewed installed PIF action's executable shell dependencies.
	for _, n := range []string{"action.sh", "autopif4.sh", "killpi.sh"} {
		b, e := bounded(filepath.Join(a.Modules, "playintegrityfix", n), 1<<20)
		if e != nil {
			return nil, fail("E_CAPABILITY", "The installed PIF action or a required dependency is unavailable. Reset is blocked.")
		}
		result[n] = hash(b)
	}
	return result, nil
}
func (a *App) resetPreview() (any, error) {
	user, e := a.currentUser()
	if e != nil {
		return nil, e
	}
	boot, e := a.resetBoot()
	if e != nil {
		return nil, e
	}
	scripts, e := a.resetScripts()
	if e != nil {
		return nil, e
	}
	config, e := a.snapshot()
	if e != nil {
		return nil, e
	}
	pif, e := bounded(filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), 64<<10)
	if e != nil {
		return nil, e
	}
	r := resetJournal{Schema: 1, State: "reviewed", Boot: boot, User: user, Scripts: scripts, Time: a.time(), PIFHash: hash(pif)}
	// Bind exact scripts, current configuration and PIF settings. No credentials or app data included.
	r.ReviewHash = resetHash(scripts, pif, config, user)
	if e = writeJSON(filepath.Join(a.Root, "reset-review.json"), r); e != nil {
		return nil, e
	}
	return map[string]any{"review_hash": r.ReviewHash, "user": r.User, "confirmation": resetPhrase, "steps": []string{"Clear Wallet for the reviewed numeric Android user shown here.", "Clear Play Store for the same reviewed user.", "Clear Google Services Framework for the same reviewed user.", "Clear Google Play services twice (as requested by the owner).", "Stop and ask the owner to reboot manually. No unattended reboot or automatic resume.", "After reboot, explicitly resume to recheck PIF scripts. Automatic execution is unavailable; separately review and run the manual PIF action and GMS force-stop, then record completion.", "Sign back in if needed, re-provision cards and check Wallet."}, "consequences": []string{"App-data clearing is destructive and cannot be undone by configuration backups.", "Wallet/card setup and Google sign-in may need to be repeated. GSF state and Android ID may be regenerated.", "The repeated GMS clear is the owner's requested sequence; its technical rationale is unverified.", "The installed PIF action runs autopif4.sh -m. It can change custom.pif.prop, TrickyStore patch settings and kill Play services; this is a separate scoped authorization from ordinary Apply.", "Review the installed action and its dependencies locally before confirmation. Network output is not displayed by the helper."}}, nil
}
func (a *App) Reset(action, confirmation, reviewHash string) (any, error) {
	return a.withLock(func() (any, error) {
		p := filepath.Join(a.Root, "reset-journal.json")
		if action == "preview" {
			if e := a.requireRecovered(); e != nil {
				return nil, e
			}
			return a.resetPreview()
		}
		if action == "status" {
			var r resetJournal
			if e := readJSON(p, &r); e != nil {
				if os.IsNotExist(e) {
					return map[string]string{"state": "none"}, nil
				}
				return nil, fail("E_RECOVERY", "Reset journal is unreadable. Preserve it; do not repeat app-data clearing.")
			}
			if e := a.validateReset(r, false); e != nil {
				return nil, e
			}
			return map[string]any{"state": r.State, "user": r.User, "completed_steps": r.Step, "time": r.Time, "next_step": "Resume manually only after reboot and a separate review; never repeat failed app-data clearing automatically."}, nil
		}
		if action == "confirm" {
			if confirmation != resetPhrase {
				return nil, fail("E_CONFIRM", "Review the destructive consequences and type the exact reset confirmation phrase.")
			}
			if a.Fake {
				return nil, fail("E_CAPABILITY", "Destructive reset is disabled in the fake-engine test backend.")
			}
			if e := a.requireRecovered(); e != nil {
				return nil, e
			}
			var old resetJournal
			if e := readJSON(p, &old); e == nil {
				if e = a.validateReset(old, false); e != nil {
					return nil, e
				}
				if old.State != "completed" {
					return nil, fail("E_RECOVERY", "A reset is already recorded. Inspect its state; never repeat destructive steps automatically.")
				}
			} else if !os.IsNotExist(e) {
				return nil, fail("E_RECOVERY", "Reset journal is unreadable; preserve it.")
			}
			var r resetJournal
			if e := readJSON(filepath.Join(a.Root, "reset-review.json"), &r); e != nil {
				return nil, fail("E_CONFIRM", "Preview the installed PIF action and reset steps first.")
			}
			if e := a.validateReset(r, true); e != nil {
				return nil, e
			}
			if reviewHash != r.ReviewHash {
				return nil, fail("E_STALE", "Reset review does not match; preview again.")
			}
			user, e := a.currentUser()
			if e != nil {
				return nil, e
			}
			boot, e := a.resetBoot()
			if e != nil {
				return nil, e
			}
			if user != r.User || boot != r.Boot {
				return nil, fail("E_STALE", "Android user or boot changed since reset review; preview again before any app-data clearing.")
			}
			scripts, e := a.resetScripts()
			if e != nil {
				return nil, e
			}
			if !sameStrings(scripts, r.Scripts) {
				return nil, fail("E_STALE", "A reviewed PIF script changed; inspect and preview again.")
			}
			pif, e := bounded(filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), 64<<10)
			if e != nil || hash(pif) != r.PIFHash {
				return nil, fail("E_STALE", "PIF configuration changed since reset review.")
			}
			snap, e := a.snapshot()
			if e != nil {
				return nil, e
			}
			fresh := resetHash(scripts, pif, snap, user)
			if fresh != r.ReviewHash {
				return nil, fail("E_STALE", "Active configuration changed since reset review.")
			}
			b, e := a.backup("wallet-reset-preparation", snap)
			if e != nil {
				return nil, e
			}
			r.Backup = b.ID
			if e = atomicWrite(filepath.Join(a.Root, "backups", b.ID, "custom.pif.prop"), pif, Metadata{0600, ownerID(), ownerID(), ""}); e != nil {
				return nil, e
			}
			r.State = "clearing"
			r.Boot = boot
			if e = writeJSON(p, r); e != nil {
				return nil, e
			}
			for i, pkg := range []string{"com.google.android.apps.walletnfcrel", "com.android.vending", "com.google.android.gsf", "com.google.android.gms", "com.google.android.gms"} {
				// Journal records the next attempted step before dispatch; unexpected failure is never retried silently.
				r.Step = i
				r.State = "attempting-clear"
				if e = writeJSON(p, r); e != nil {
					return nil, e
				}
				if a.Fake {
					return nil, fail("E_CAPABILITY", "Destructive reset is disabled in the fake-engine test backend.")
				}
				out, e := run("/system/bin/pm", "clear", "--user", r.User, pkg)
				if e != nil || strings.TrimSpace(out) != "Success" {
					r.State = "failed-do-not-repeat"
					writeJSON(p, r)
					return nil, fail("E_RESET", "An app-data clear failed or returned unexpected output. Stop and inspect; prior clears are irreversible.")
				}
				r.Step = i + 1
				r.State = "clearing"
				if e = writeJSON(p, r); e != nil {
					return nil, e
				}
			}
			r.State = "awaiting-manual-reboot"
			if e = writeJSON(p, r); e != nil {
				return nil, e
			}
			a.history("wallet-reset", b.ID, r.State)
			return map[string]string{"state": r.State, "message": "The five separately confirmed clears completed. Reboot manually, then invoke reset --action resume. No background continuation is installed."}, nil
		}
		if action == "resume" {
			var r resetJournal
			if e := readJSON(p, &r); e != nil {
				return nil, fail("E_RESET", "No one-shot reset journal is available.")
			}
			if e := a.validateReset(r, false); e != nil {
				return nil, e
			}
			if r.State != "awaiting-manual-reboot" {
				return nil, fail("E_RESET", "Reset cannot resume from this state; inspect without repeating destructive steps.")
			}
			if e := a.resetResumeContext(r); e != nil {
				return nil, e
			}
			scripts, e := a.resetScripts()
			if e != nil {
				return nil, e
			}
			if !sameStrings(scripts, r.Scripts) {
				return nil, fail("E_STALE", "PIF scripts changed across reboot. Inspect them; no action was run.")
			}
			// PIF invokes network fetching and its own writers. Automatic execution is blocked pending a separately verified action profile.
			// Do not treat a SHA review as an audit of fetched data or transitive shell behavior.
			return map[string]any{"state": r.State, "user": r.User, "backup": r.Backup, "next_step": "Inspect the pinned installed PIF action and run it manually as documented, then force-stop GMS. Record completion only after each command succeeds."}, fail("E_CAPABILITY", "Automatic post-reboot PIF execution is unavailable: its network mutation contract is not verified. Follow the reviewed manual completion steps; do not repeat the clears.")
		}
		if action == "complete" {
			var r resetJournal
			if e := readJSON(p, &r); e != nil {
				return nil, e
			}
			if e := a.validateReset(r, false); e != nil {
				return nil, e
			}
			if confirmation != "PIF ACTION AND GMS FORCE-STOP COMPLETED" || r.State != "awaiting-manual-reboot" {
				return nil, fail("E_CONFIRM", "Complete requires a reboot and explicit confirmation of the documented successful manual post-reboot commands.")
			}
			if e := a.resetResumeContext(r); e != nil {
				return nil, e
			}
			r.State = "completed"
			r.Time = a.time()
			if e := writeJSON(p, r); e != nil {
				return nil, e
			}
			return map[string]string{"state": "completed", "next_step": "Sign back in if needed, re-provision cards and check Wallet. Actual readiness and Tap-to-Pay remain unverified."}, nil
		}
		return nil, fail("E_REQUEST", "Reset actions: preview, status, confirm, resume, complete.")
	})
}
