package core

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
	"walletdiagnostic/internal/keybox"
)

type Backup struct {
	Schema   int                  `json:"schema"`
	ID       string               `json:"id"`
	Time     string               `json:"time"`
	Type     string               `json:"type"`
	Files    map[string]FileState `json:"files"`
	Verified bool                 `json:"verified"`
	Adoption string               `json:"adoption"`
}
type Journal struct {
	Schema   int                  `json:"schema"`
	Plan     string               `json:"plan"`
	Backup   string               `json:"backup"`
	State    string               `json:"state"`
	Time     string               `json:"time"`
	Intended map[string]FileState `json:"intended"`
}

func (a *App) backup(kind string, expected map[string]FileState) (Backup, error) {
	if e := a.checkpoint("before-backup"); e != nil {
		return Backup{}, e
	}
	total := uint64(16 << 20)
	for _, f := range expected {
		total += uint64(f.Size) * 3
	}
	if e := enoughSpace(a.Root, total); e != nil {
		return Backup{}, e
	}
	if e := enoughSpace(a.Active, total); e != nil {
		return Backup{}, e
	}
	id, e := newID()
	if e != nil {
		return Backup{}, e
	}
	dir := filepath.Join(a.Root, "backups", id)
	if e = os.Mkdir(dir, 0700); e != nil {
		return Backup{}, e
	}
	b := Backup{Schema: 1, ID: id, Time: a.time(), Type: kind, Files: expected, Adoption: "unknown"}
	for _, name := range files {
		st, ok := expected[name]
		if !ok {
			return b, fail("E_BACKUP", "Incomplete snapshot; backup stopped.")
		}
		if !st.Exists {
			continue
		}
		body, e := bounded(filepath.Join(a.Active, name), 1<<20)
		if e != nil {
			return b, e
		}
		if hash(body) != st.SHA256 {
			return b, fail("E_STALE", "Configuration changed during backup. Nothing was applied.")
		}
		if e = atomicWrite(filepath.Join(dir, name), body, Metadata{0600, ownerID(), ownerID(), ""}); e != nil {
			return b, e
		}
	}
	if e = writeJSON(filepath.Join(dir, "backup.json"), b); e != nil {
		return b, e
	}
	if e = syncDir(dir); e != nil {
		return b, e
	}
	if e = syncDir(filepath.Dir(dir)); e != nil {
		return b, e
	}
	if _, e = a.loadBackup(id); e != nil {
		return b, e
	}
	current, e := a.snapshot()
	if e != nil {
		return b, e
	}
	if !equal(current, expected) {
		return b, fail("E_STALE", "Configuration changed during backup. Nothing was applied.")
	}
	return b, a.checkpoint("after-backup")
}
func (a *App) loadBackup(id string) (Backup, error) {
	dir, e := a.object("backups", id)
	if e != nil {
		return Backup{}, e
	}
	var b Backup
	if e = readJSON(filepath.Join(dir, "backup.json"), &b); e != nil {
		return b, e
	}
	if b.Schema != 1 || b.ID != id || len(b.Files) != 3 {
		return b, fail("E_BACKUP", "Unsupported or incomplete backup.")
	}
	kinds := map[string]bool{"apply": true, "rollback": true, "wallet-reset-preparation": true, "external-writer-evidence": true, "verified-configuration": true, "pre-recovery": true, "stack-profile": true}
	if !kinds[b.Type] || (b.Adoption != "unknown" && b.Adoption != "pending" && b.Adoption != "verified") || (b.Verified && b.Adoption != "verified") {
		return b, fail("E_BACKUP", "Backup contains unsupported reporting metadata.")
	}
	if _, e = time.Parse(time.RFC3339, b.Time); e != nil {
		return b, fail("E_BACKUP", "Backup timestamp is invalid.")
	}
	for _, name := range files {
		s, ok := b.Files[name]
		if !ok || !a.validState(s) {
			return b, fail("E_BACKUP", "Backup has missing or invalid file metadata. Nothing was restored.")
		}
		p := filepath.Join(dir, name)
		if !s.Exists {
			if _, e = os.Lstat(p); !os.IsNotExist(e) {
				return b, fail("E_BACKUP", "An absent-file backup contains unexpected data.")
			}
			continue
		}
		body, e := bounded(p, 1<<20)
		if e != nil {
			return b, fail("E_BACKUP", "A backup file is missing or unreadable.")
		}
		if hash(body) != s.SHA256 || int64(len(body)) != s.Size {
			return b, fail("E_BACKUP", "Backup checksum validation failed. Keep this backup for investigation.")
		}
	}
	return b, nil
}
func (a *App) Backups() (any, error) {
	list, e := os.ReadDir(filepath.Join(a.Root, "backups"))
	if e != nil {
		return nil, e
	}
	out := []map[string]any{}
	for _, entry := range list {
		if !entry.IsDir() || !validID.MatchString(entry.Name()) {
			continue
		}
		b, e := a.loadBackup(entry.Name())
		if e != nil {
			out = append(out, map[string]any{"id": entry.Name(), "integrity": "failed", "verified": false})
			continue
		}
		out = append(out, map[string]any{"id": b.ID, "time": b.Time, "type": b.Type, "verified": b.Verified, "adoption": b.Adoption, "integrity": "checked", "changes": b.Files})
	}
	sort.Slice(out, func(i, j int) bool { return toString(out[i]["time"]) > toString(out[j]["time"]) })
	return map[string]any{"backups": out}, nil
}
func toString(v any) string { s, _ := v.(string); return s }
func (a *App) Apply(id string) (any, error) {
	return a.withLock(func() (any, error) { return a.applyLocked(id) })
}
func (a *App) applyLocked(id string) (any, error) {
	if e := a.requireRecovered(); e != nil {
		return nil, e
	}
	var prior Journal
	if e := readJSON(filepath.Join(a.Root, "journal.json"), &prior); e == nil && prior.Plan == id {
		return nil, fail("E_DUPLICATE", "This plan was already submitted. Inspect its recorded operation instead.")
	}
	p, dir, e := a.loadPlan(id)
	if e != nil {
		return nil, e
	}
	if _, e = os.Lstat(filepath.Join(dir, "submitted.json")); e == nil {
		return nil, fail("E_DUPLICATE", "This plan was already submitted. Create a fresh plan after reviewing its outcome.")
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	caps, e := a.planCapabilities()
	if e != nil {
		return nil, e
	}
	if !sameStrings(caps, p.Capabilities) {
		return nil, fail("E_STALE", "Engine, PIF, writer or runtime capabilities changed. Make a new plan.")
	}
	current, e := a.snapshot()
	if e != nil {
		return nil, e
	}
	if !equal(current, p.Active) {
		return nil, fail("E_STALE", "Active files or their metadata changed. Inspect and make a fresh plan.")
	}
	if p.Type == "apply" && len(p.Selections) == 0 {
		if !current["keybox.xml"].Exists {
			return nil, fail("E_VALIDATION", "The retained keybox is unavailable; make a plan with a validated replacement.")
		}
		body, e := bounded(filepath.Join(a.Active, "keybox.xml"), keybox.MaxInput)
		if e != nil {
			return nil, e
		}
		doc, e := keybox.Parse(body, a.Now())
		if e != nil {
			return nil, safeError(e)
		}
		if e = a.rejectPublicListed(doc); e != nil {
			return nil, e
		}
	}
	docs := []*keybox.Document{}
	for _, s := range p.Inputs {
		doc, now, e := a.stage(s.ID)
		if e != nil {
			return nil, e
		}
		if now.SHA256 != s.SHA256 {
			return nil, fail("E_STALE", "Selected input changed. Import and review it again.")
		}
		docs = append(docs, doc)
	}
	if p.Type == "apply" && len(p.Selections) > 0 {
		doc, e := keybox.Merge(docs, p.Selections, a.Now())
		if e != nil {
			return nil, safeError(e)
		}
		if e = a.rejectPublicListed(doc); e != nil {
			return nil, e
		}
		body, e := doc.XML()
		if e != nil {
			return nil, safeError(e)
		}
		if hash(body) != p.Intended["keybox.xml"].SHA256 {
			return nil, fail("E_STALE", "Planned keybox no longer matches its selected validated inputs.")
		}
	}
	for _, n := range p.Changes {
		if !allowedFile(n) {
			return nil, fail("E_FORMAT", "Plan includes an unsupported path.")
		}
		st := p.Intended[n]
		if st.Exists {
			b, e := bounded(filepath.Join(dir, n), 1<<20)
			if e != nil {
				return nil, e
			}
			if hash(b) != st.SHA256 || int64(len(b)) != st.Size {
				return nil, fail("E_STALE", "Proposed file changed. Make a new plan.")
			}
		}
	}
	if e = writeJSON(filepath.Join(dir, "submitted.json"), map[string]string{"time": a.time()}); e != nil {
		return nil, e
	}
	b, e := a.backup(p.Type, current)
	if e != nil {
		return nil, e
	}
	j := Journal{1, p.ID, b.ID, "applying", a.time(), p.Intended}
	if e = writeJSON(filepath.Join(a.Root, "journal.json"), j); e != nil {
		return nil, e
	}
	// From here failures attempt full restoration. Process death is handled by explicit Recovery.
	runErr := a.commit(p, dir, &j)
	if runErr != nil {
		j.State = "recovery-required"
		writeJSON(filepath.Join(a.Root, "journal.json"), j)
		var conflict *Error
		if errors.As(runErr, &conflict) && conflict.Code == "E_WRITER" {
			state, se := a.snapshot()
			if se != nil {
				return nil, fail("E_RECOVERY", "Concurrent writer evidence could not be read; preserve journal and backups.")
			}
			if _, se = a.backup("external-writer-evidence", state); se != nil {
				return nil, fail("E_RECOVERY", "Concurrent writer evidence could not be preserved. Recovery is pending; do not overwrite it.")
			}
		}
		if e = a.restore(b, &j); e != nil {
			return nil, fail("E_RECOVERY", "Commit and restoration failed. Preserve the journal and backups; open Advanced Recovery.")
		}
		a.history(p.Type, p.ID, "restored-after-failure")
		return map[string]any{"backup": b.ID, "state": "restored"}, fail("E_APPLY", "Commit failed; the complete previous file set was restored and checked. Adoption needs verification.")
	}
	a.history(p.Type, p.ID, "committed-adoption-pending")
	return map[string]any{"id": p.ID, "backup": b.ID, "files_committed": true, "engine_health": "healthy", "adoption": "pending", "wallet_acceptance": "unverified", "manual_reboot_required": false, "message": "Files checked; per-file engine reload is documented and observed in installed code. Fresh identity evidence and Wallet testing remain required."}, nil
}
func sameStrings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func allowedFile(n string) bool {
	for _, x := range files {
		if n == x {
			return true
		}
	}
	return false
}
func (a *App) commit(p Plan, dir string, j *Journal) error {
	if e := a.checkpoint("after-journal"); e != nil {
		return e
	}
	expected := map[string]FileState{}
	for n, s := range p.Active {
		expected[n] = s
	}
	// Keybox is replaced last; this is not an atomic configuration-set update.
	for _, n := range []string{"security_patch.txt", "target.txt", "keybox.xml"} {
		changed := false
		for _, v := range p.Changes {
			if v == n {
				changed = true
			}
		}
		if !changed {
			continue
		}
		now, e := a.snapshot()
		if e != nil {
			return e
		}
		if !equal(now, expected) {
			return fail("E_WRITER", "Another writer changed the file set during commit.")
		}
		if e = a.checkpoint("before-write-" + n); e != nil {
			return e
		}
		now, e = a.snapshot()
		if e != nil {
			return e
		}
		if !equal(now, expected) {
			return fail("E_WRITER", "An external writer changed the set at a write boundary.")
		}
		caps, e := a.planCapabilities()
		if e != nil {
			return e
		}
		if !sameStrings(caps, p.Capabilities) {
			return fail("E_WRITER", "A writer or engine capability changed at a write boundary.")
		}
		j.State = "writing-" + n
		if e = writeJSON(filepath.Join(a.Root, "journal.json"), j); e != nil {
			return e
		}
		st := p.Intended[n]
		if st.Exists {
			body, e := bounded(filepath.Join(dir, n), 1<<20)
			if e != nil {
				return e
			}
			if hash(body) != st.SHA256 || int64(len(body)) != st.Size {
				return fail("E_STALE", "Prepared bytes changed at a write boundary; no changed bytes were applied.")
			}
			if e = atomicWrite(filepath.Join(a.Active, n), body, st.Metadata); e != nil {
				return e
			}
		} else {
			if e = noLinks(filepath.Join(a.Active, n)); e != nil {
				return e
			}
			if e = os.Remove(filepath.Join(a.Active, n)); e != nil && !os.IsNotExist(e) {
				return e
			}
			if e = syncDir(a.Active); e != nil {
				return e
			}
		}
		expected[n] = st
		if e = a.checkpoint("after-write-" + n); e != nil {
			return e
		}
	}
	if e := a.checkpoint("after-file-set"); e != nil {
		return e
	}
	now, e := a.snapshot()
	if e != nil {
		return e
	}
	if !equal(now, p.Intended) {
		return fail("E_WRITER", "Committed file set changed or failed verification.")
	}
	if _, e = a.adoption(); e != nil {
		return e
	}
	if e = a.checkpoint("before-commit-marker"); e != nil {
		return e
	}
	now, e = a.snapshot()
	if e != nil {
		return e
	}
	if !equal(now, p.Intended) {
		return fail("E_WRITER", "An external writer changed the file set before commit completion.")
	}
	caps, e := a.planCapabilities()
	if e != nil {
		return e
	}
	if !sameStrings(caps, p.Capabilities) {
		return fail("E_WRITER", "Reviewed runtime or public evidence changed before commit completion.")
	}
	j.State = "committed"
	j.Time = a.time()
	if e = writeJSON(filepath.Join(a.Root, "journal.json"), j); e != nil {
		return e
	}
	if e = a.checkpoint("after-commit-marker"); e != nil {
		return e
	}
	now, e = a.snapshot()
	if e != nil {
		return e
	}
	if !equal(now, p.Intended) {
		return fail("E_WRITER", "An external writer changed the file set after the commit marker.")
	}
	caps, e = a.planCapabilities()
	if e != nil {
		return e
	}
	if !sameStrings(caps, p.Capabilities) {
		return fail("E_WRITER", "Reviewed runtime or public evidence changed after the commit marker.")
	}
	return nil
}
func (a *App) restore(b Backup, j *Journal) error {
	verified, e := a.loadBackup(b.ID)
	if e != nil {
		return e
	}
	// Preserve the current complete (possibly partially applied) set before any
	// restoration writes. A failed snapshot keeps the original journal pending.
	current, e := a.snapshot()
	if e != nil {
		return e
	}
	if _, e = a.backup("pre-recovery", current); e != nil {
		return e
	}
	dir := filepath.Join(a.Root, "backups", b.ID)
	j.State = "restoring"
	if e = writeJSON(filepath.Join(a.Root, "journal.json"), j); e != nil {
		return e
	}
	for _, n := range files {
		if e = a.checkpoint("before-restore-" + n); e != nil {
			return e
		}
		s := verified.Files[n]
		if s.Exists {
			body, e := bounded(filepath.Join(dir, n), 1<<20)
			if e != nil {
				return e
			}
			if hash(body) != s.SHA256 || int64(len(body)) != s.Size {
				return fail("E_BACKUP", "Backup bytes changed at the restoration boundary; changed bytes were not restored. Preserve the recovery journal.")
			}
			if e = atomicWrite(filepath.Join(a.Active, n), body, s.Metadata); e != nil {
				return e
			}
		} else {
			if e = noLinks(filepath.Join(a.Active, n)); e != nil {
				return e
			}
			if e = os.Remove(filepath.Join(a.Active, n)); e != nil && !os.IsNotExist(e) {
				return e
			}
			if e = syncDir(a.Active); e != nil {
				return e
			}
		}
	}
	now, e := a.snapshot()
	if e != nil {
		return e
	}
	if !equal(now, b.Files) {
		return fail("E_RECOVERY", "Restored file checksums or metadata do not match the backup.")
	}
	j.State = "restored"
	j.Time = a.time()
	return writeJSON(filepath.Join(a.Root, "journal.json"), j)
}
func (a *App) Rollback(id string) (any, error) {
	return a.withLock(func() (any, error) {
		lastVerified := id == "last-verified"
		if e := a.requireRecovered(); e != nil {
			return nil, e
		}
		if id == "previous" {
			var j Journal
			if e := readJSON(filepath.Join(a.Root, "journal.json"), &j); e != nil {
				return nil, fail("E_BACKUP", "No previous transaction backup is recorded.")
			}
			id = j.Backup
		}
		if id == "last-verified" {
			var m map[string]string
			if e := readJSON(filepath.Join(a.Root, "last-verified.json"), &m); e != nil {
				return nil, fail("E_BACKUP", "No configuration has recorded identity adoption verification. Last applied is not last verified.")
			}
			id = m["backup"]
		}
		b, e := a.loadBackup(id)
		if e != nil {
			return nil, e
		}
		if lastVerified && (!b.Verified || b.Adoption != "verified" || b.Type != "verified-configuration") {
			return nil, fail("E_BACKUP", "The last-verified pointer does not identify a checked configuration with verified identity adoption.")
		}
		caps, e := a.planCapabilities()
		if e != nil {
			return nil, e
		}
		active, e := a.snapshot()
		if e != nil {
			return nil, e
		}
		pid, e := newID()
		if e != nil {
			return nil, e
		}
		dir := filepath.Join(a.Root, "plans", pid)
		if e = os.Mkdir(dir, 0700); e != nil {
			return nil, e
		}
		p := Plan{Schema: 1, ID: pid, Time: a.time(), Type: "rollback", Active: active, Intended: b.Files, Capabilities: caps, SourceBackup: id}
		for _, n := range files {
			if active[n] == b.Files[n] {
				continue
			}
			p.Changes = append(p.Changes, n)
			if b.Files[n].Exists {
				body, e := bounded(filepath.Join(a.Root, "backups", id, n), 1<<20)
				if e != nil {
					return nil, e
				}
				if e = atomicWrite(filepath.Join(dir, n), body, Metadata{0600, ownerID(), ownerID(), ""}); e != nil {
					return nil, e
				}
			}
		}
		if len(p.Changes) == 0 {
			return map[string]any{"state": "already-restored", "adoption": "pending"}, nil
		}
		if e = writeJSON(filepath.Join(dir, "plan.json"), p); e != nil {
			return nil, e
		}
		return a.applyLocked(pid)
	})
}
func (a *App) Recovery(action string) (any, error) {
	var j Journal
	e := readJSON(filepath.Join(a.Root, "journal.json"), &j)
	state := "none"
	if e == nil {
		if e = a.validateJournal(j); e != nil {
			return nil, e
		}
		state = j.State
	} else if !os.IsNotExist(e) {
		return nil, fail("E_RECOVERY", "The journal is unreadable; preserve all recovery data for investigation.")
	}
	lockPath := filepath.Join(a.Root, "operation.lock")
	lockInfo, lockErr := os.Lstat(lockPath)
	lockExists := lockErr == nil
	if lockErr != nil && !os.IsNotExist(lockErr) {
		return nil, lockErr
	}
	if lockExists && (!lockInfo.IsDir() || lockInfo.Mode()&os.ModeSymlink != 0) {
		return nil, fail("E_BUSY", "Operation lock is an unsafe path; inspect it manually.")
	}
	var l lockRecord
	le := readJSON(filepath.Join(lockPath, "owner.json"), &l)
	if action == "status" || action == "" {
		return map[string]any{"state": state, "journal": j, "lock_present": lockExists, "lock_owner_verified": le == nil && a.validLock(l), "next_step": "If an operation stopped, restore its backup. An ownerless lock needs manual inspection. Lock release is allowed only after its verified process ended or the boot changed."}, nil
	}
	if action != "restore" && action != "release-lock" {
		return nil, fail("E_REQUEST", "Recovery action must be status, restore or release-lock.")
	}
	if lockExists && le != nil {
		return nil, fail("E_BUSY", "An ownerless or corrupt operation lock cannot be safely released automatically. Inspect it manually; preserve the journal.")
	}
	if le == nil {
		if !a.validLock(l) {
			return nil, fail("E_BUSY", "Lock owner is invalid; manual inspection is required.")
		}
		if l.Boot == bootID() && pidAlive(l.PID) {
			return nil, fail("E_BUSY", "The lock-owning process is still running. Wait for it to finish.")
		}
		if e = os.Remove(filepath.Join(lockPath, "owner.json")); e != nil {
			return nil, e
		}
		if e = os.Remove(lockPath); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(le) {
		return nil, fail("E_BUSY", "Incomplete lock requires manual inspection; it cannot be silently removed.")
	}
	if action == "release-lock" {
		return map[string]string{"state": "lock-released"}, nil
	}
	if state == "none" || state == "committed" || state == "restored" {
		return map[string]string{"state": state}, nil
	}
	return a.withLock(func() (any, error) {
		b, e := a.loadBackup(j.Backup)
		if e != nil {
			return nil, e
		}
		if e = a.restore(b, &j); e != nil {
			return nil, e
		}
		a.history("recovery", j.Plan, "restored")
		v, adoptErr := a.adoption()
		if adoptErr != nil {
			return map[string]any{"state": "files-restored", "adoption": "failed", "engine": v}, fail("E_RECOVERY", "Files are restored but engine health remains failed. Preserve the evidence; do not restart unrelated services.")
		}
		return map[string]any{"state": "restored", "engine": v, "adoption": "pending"}, nil
	})
}
func (a *App) validateJournal(j Journal) error {
	if _, e := time.Parse(time.RFC3339, j.Time); e != nil {
		return fail("E_RECOVERY", "Journal timestamp is invalid; preserve recovery evidence.")
	}
	if j.Schema != 1 || !validID.MatchString(j.Plan) || !validID.MatchString(j.Backup) || len(j.Intended) != 3 {
		return fail("E_RECOVERY", "Journal is incomplete or has an unsupported format. Preserve it and all backups.")
	}
	valid := map[string]bool{"applying": true, "committed": true, "restored": true, "restoring": true, "recovery-required": true}
	for _, n := range files {
		valid["writing-"+n] = true
		if st, ok := j.Intended[n]; !ok || !a.validState(st) {
			return fail("E_RECOVERY", "Journal lacks a required file state.")
		}
	}
	if !valid[j.State] {
		return fail("E_RECOVERY", "Unknown journal state; manual inspection is required.")
	}
	return nil
}
