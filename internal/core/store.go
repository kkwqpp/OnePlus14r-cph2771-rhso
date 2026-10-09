package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"walletdiagnostic/internal/keybox"
)

type lockRecord struct {
	PID  int    `json:"pid"`
	Boot string `json:"boot"`
}

var validBoot = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func (a *App) validLock(l lockRecord) bool {
	if l.PID <= 0 {
		return false
	}
	if a.Fake {
		return true
	}
	return validBoot.MatchString(l.Boot) && validBoot.MatchString(bootID())
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
func (a *App) lock() (func(), error) {
	if e := a.Init(); e != nil {
		return nil, e
	}
	p := filepath.Join(a.Root, "operation.lock")
	if e := os.Mkdir(p, 0700); e != nil {
		return nil, fail("E_BUSY", "Another operation or an interrupted lock is present. Open Recovery before retrying.")
	}
	if e := writeJSON(filepath.Join(p, "owner.json"), lockRecord{os.Getpid(), bootID()}); e != nil {
		os.Remove(p)
		return nil, e
	}
	return func() { os.Remove(filepath.Join(p, "owner.json")); os.Remove(p); syncDir(a.Root) }, nil
}
func (a *App) withLock(fn func() (any, error)) (any, error) {
	unlock, e := a.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	return fn()
}
func (a *App) unfinished() bool {
	var j Journal
	e := readJSON(filepath.Join(a.Root, "journal.json"), &j)
	if e != nil && !os.IsNotExist(e) {
		return true
	}
	if e == nil && (a.validateJournal(j) != nil || (j.State != "committed" && j.State != "restored")) {
		return true
	}
	var reset resetJournal
	e = readJSON(filepath.Join(a.Root, "reset-journal.json"), &reset)
	return (e != nil && !os.IsNotExist(e)) || (e == nil && (a.validateReset(reset, false) != nil || reset.State != "completed")) || a.stackUnfinished()
}
func (a *App) requireRecovered() error {
	if a.unfinished() {
		return fail("E_RECOVERY", "An unfinished transaction must be restored through Recovery before another change.")
	}
	return nil
}

type Stage struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Time   string `json:"time"`
	Bytes  int    `json:"bytes"`
}

func (a *App) Ingest(path string) (any, error) {
	return a.withLock(func() (any, error) {
		if e := a.requireRecovered(); e != nil {
			return nil, e
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
			return nil, fail("E_PATH", "Use a clean absolute path inside the private inbox or optional shared inbox.")
		}
		permitted := false
		for _, dir := range []string{filepath.Join(a.Root, "inbox"), a.SharedInbox} {
			rel, e := filepath.Rel(dir, path)
			if e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel) {
				permitted = true
			}
		}
		if path == filepath.Join(a.Active, "keybox.xml") {
			permitted = true
		}
		if !permitted {
			return nil, fail("E_PATH", "Copy the file to the private inbox; active keybox.xml is also an allowed source for a reviewed merge.")
		}
		if !a.Fake && strings.HasPrefix(path, "/sdcard/keybox_inbox/") && a.SharedInbox == "/sdcard/keybox_inbox" {
			// Resolve only Android's known shared-storage alias. The inbox and every
			// component below it still pass the normal no-symlink checks.
			base, e := filepath.EvalSymlinks("/sdcard")
			if e != nil {
				return nil, fail("E_PATH", "Shared storage alias is unavailable. Use the private inbox.")
			}
			if !strings.HasPrefix(base, "/storage/emulated/") && !strings.HasPrefix(base, "/mnt/user/") {
				return nil, fail("E_PATH", "Shared storage alias has an unrecognized target. Use the private inbox.")
			}
			path = filepath.Join(base, "keybox_inbox", strings.TrimPrefix(path, "/sdcard/keybox_inbox/"))
		}
		b, e := bounded(path, keybox.MaxInput)
		if e != nil {
			return nil, e
		}
		if len(b) == 0 {
			return nil, fail("E_INPUT", "The input is empty.")
		}
		return a.stageBytes(b)
	})
}

// Callers hold the operation lock and have checked requireRecovered. Local and
// remote sources share the same immutable private staging/history behavior.
func (a *App) stageBytes(b []byte) (Stage, error) {
	if len(b) == 0 || len(b) > keybox.MaxInput {
		return Stage{}, fail("E_INPUT", "The staged input is empty or exceeds the size limit.")
	}
	id, e := newID()
	if e != nil {
		return Stage{}, e
	}
	dir := filepath.Join(a.Root, "staged", id)
	if e = os.Mkdir(dir, 0700); e != nil {
		return Stage{}, e
	}
	if e = atomicWrite(filepath.Join(dir, "input.xml"), b, Metadata{0600, ownerID(), ownerID(), ""}); e != nil {
		return Stage{}, e
	}
	s := Stage{1, id, hash(b), a.time(), len(b)}
	if e = writeJSON(filepath.Join(dir, "stage.json"), s); e != nil {
		return Stage{}, e
	}
	if e = a.history("ingest", id, "staged"); e != nil {
		return Stage{}, e
	}
	return s, nil
}
func (a *App) stage(id string) (*keybox.Document, Stage, error) {
	p, e := a.object("staged", id)
	if e != nil {
		return nil, Stage{}, e
	}
	var s Stage
	if e = readJSON(filepath.Join(p, "stage.json"), &s); e != nil {
		return nil, s, e
	}
	if s.Schema != 1 || s.ID != id {
		return nil, s, fail("E_FORMAT", "Unsupported or corrupt staged format.")
	}
	if !validStage(s, id) {
		return nil, s, fail("E_FORMAT", "Staged inventory metadata is corrupt or unsupported.")
	}
	b, e := bounded(filepath.Join(p, "input.xml"), keybox.MaxInput)
	if e != nil {
		return nil, s, e
	}
	if hash(b) != s.SHA256 {
		return nil, s, fail("E_STALE", "Staged material changed. Import it again.")
	}
	d, e := keybox.Parse(b, a.Now())
	return d, s, safeError(e)
}
func (a *App) Validate(id string) (any, error) {
	d, s, e := a.stage(id)
	if e != nil {
		return nil, e
	}
	return map[string]any{"id": id, "sha256": s.SHA256, "summary": d.Summary()}, nil
}
func validStage(s Stage, id string) bool {
	if s.Schema != 1 || s.ID != id || !validID.MatchString(s.ID) || !validHash.MatchString(s.SHA256) || s.Bytes < 1 || s.Bytes > keybox.MaxInput {
		return false
	}
	_, e := time.Parse(time.RFC3339, s.Time)
	return e == nil
}

type Plan struct {
	Schema           int                      `json:"schema"`
	ID               string                   `json:"id"`
	Time             string                   `json:"time"`
	Type             string                   `json:"type"`
	Inputs           []Stage                  `json:"inputs"`
	Active           map[string]FileState     `json:"active"`
	Intended         map[string]FileState     `json:"intended"`
	Changes          []string                 `json:"changes"`
	Capabilities     map[string]string        `json:"capabilities"`
	SourceBackup     string                   `json:"source_backup,omitempty"`
	Summary          any                      `json:"summary,omitempty"`
	Preview          []map[string]any         `json:"preview"`
	Warnings         []string                 `json:"warnings"`
	Selections       []keybox.Selection       `json:"selections"`
	TargetCompaction *TargetCompactionSummary `json:"target_compaction,omitempty"`
}

func (p Plan) view() any {
	w := append([]string{}, p.Warnings...)
	w = append(w, "Configuration-set replacement is recoverable, not atomic. Other root writers are outside this helper's lock.", "Public-chain evidence is a separate bounded check, not proof of hardware identity or Wallet acceptance. Wallet acceptance requires a real check.")
	view := map[string]any{"id": p.ID, "time": p.Time, "type": p.Type, "changes": p.Changes, "preview": p.Preview, "summary": p.Summary, "active": p.Active, "intended": p.Intended, "metadata": "Selected inputs are emitted with DeviceID WalletDiagnosticHelper; no hardware identity is recreated.", "adoption": "Per-file FileObserver reload; identity adoption remains pending fresh evidence.", "required_capabilities": p.Capabilities, "warnings": w}
	if p.TargetCompaction != nil {
		view["target_compaction"] = p.TargetCompaction
	}
	return view
}
func (a *App) Plan(selections string, targets bool, patch string, compactTargetOption ...bool) (any, error) {
	return a.withLock(func() (any, error) {
		if len(compactTargetOption) > 1 {
			return nil, fail("E_REQUEST", "Choose one target compaction option.")
		}
		compact := len(compactTargetOption) == 1 && compactTargetOption[0]
		if e := a.requireRecovered(); e != nil {
			return nil, e
		}
		caps, e := a.planCapabilities()
		if e != nil {
			return nil, e
		}
		before, e := a.snapshot()
		if e != nil {
			return nil, e
		}
		id, e := newID()
		if e != nil {
			return nil, e
		}
		dir := filepath.Join(a.Root, "plans", id)
		if e = os.Mkdir(dir, 0700); e != nil {
			return nil, e
		}
		p := Plan{Schema: 1, ID: id, Time: a.time(), Type: "apply", Active: before, Intended: map[string]FileState{}, Capabilities: caps}
		if caps["public_feed_state"] != "fresh" {
			p.Warnings = append(p.Warnings, "No fresh independently acquired Google public status snapshot is available; public root/revocation assessment remains unknown. Refresh explicitly before relying on it.")
		} else {
			p.Warnings = append(p.Warnings, "Google-anchored selected/retained chains were checked locally against the current full Google public status snapshot. Other anchors retain unknown revocation status. Absence from that snapshot does not establish hardware identity or Wallet approval.")
		}
		for n, s := range before {
			p.Intended[n] = s
		}
		if selections == "" {
			if !before["keybox.xml"].Exists {
				return nil, fail("E_VALIDATION", "A target or patch repair requires a validated retained keybox; select a validated replacement first.")
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
		stagedDocs := []*keybox.Document{}
		sels := []keybox.Selection{}
		sources := map[string]int{}
		if selections != "" {
			for _, s := range strings.Split(selections, ",") {
				v := strings.Split(s, ":")
				if len(v) != 4 || !validID.MatchString(v[0]) {
					return nil, fail("E_SELECTION", "Choose an explicit input ID, Keybox index, Key index and algorithm.")
				}
				bi, e := strconv.Atoi(v[1])
				if e != nil {
					return nil, fail("E_SELECTION", "Invalid Keybox index.")
				}
				ki, e := strconv.Atoi(v[2])
				if e != nil {
					return nil, fail("E_SELECTION", "Invalid Key index.")
				}
				idx, ok := sources[v[0]]
				if !ok {
					d, st, e := a.stage(v[0])
					if e != nil {
						return nil, e
					}
					idx = len(stagedDocs)
					sources[v[0]] = idx
					stagedDocs = append(stagedDocs, d)
					p.Inputs = append(p.Inputs, st)
				}
				sels = append(sels, keybox.Selection{Source: idx, Keybox: bi, Key: ki, Algorithm: v[3]})
			}
			d, e := keybox.Merge(stagedDocs, sels, a.Now())
			if e != nil {
				return nil, safeError(e)
			}
			if e = a.rejectPublicListed(d); e != nil {
				return nil, e
			}
			p.Summary = d.Summary()
			p.Selections = sels
			selected := map[string]bool{}
			for _, sel := range sels {
				selected[sel.Algorithm] = true
			}
			if before["keybox.xml"].Exists {
				oldBytes, oe := bounded(filepath.Join(a.Active, "keybox.xml"), keybox.MaxInput)
				if oe == nil {
					old, oe := keybox.Parse(oldBytes, a.Now())
					if oe == nil {
						summary := old.Summary().(keybox.RedactedSummary)
						for _, box := range summary.Keyboxes {
							for _, key := range box.Keys {
								if !selected[key.Algorithm] {
									p.Warnings = append(p.Warnings, "The current "+key.Algorithm+" entry is omitted by this explicit replacement selection.")
								}
							}
						}
					} else {
						p.Warnings = append(p.Warnings, "Current keybox did not validate; its algorithm inventory could not be established.")
					}
				}
			}
			b, e := d.XML()
			if e != nil {
				return nil, safeError(e)
			}
			if e = a.propose(dir, &p, "keybox.xml", b); e != nil {
				return nil, e
			}
		}
		if targets || compact {
			b := []byte{}
			if before["target.txt"].Exists {
				b, e = bounded(filepath.Join(a.Active, "target.txt"), 1<<20)
				if e != nil {
					return nil, e
				}
			}
			out := b
			if compact {
				var summary TargetCompactionSummary
				out, summary, e = compactTargets(out)
				if e != nil {
					return nil, e
				}
				p.TargetCompaction = &summary
			}
			if targets {
				out, e = repairTargets(out)
				if e != nil {
					return nil, e
				}
			}
			if e = a.propose(dir, &p, "target.txt", out); e != nil {
				return nil, e
			}
		}
		if patch != "" {
			if _, e = time.Parse("2006-01-02", patch); e != nil {
				return nil, fail("E_INPUT", "Patch date must be a valid YYYY-MM-DD date.")
			}
			pif, e := a.pif()
			if e != nil {
				return nil, e
			}
			if pif["SECURITY_PATCH"] != patch {
				return nil, fail("E_SELECTION", "Patch repair must match the inspected PIF SECURITY_PATCH. PIF changes need separate authorization.")
			}
			b := []byte{}
			if before["security_patch.txt"].Exists {
				b, e = bounded(filepath.Join(a.Active, "security_patch.txt"), 1<<20)
				if e != nil {
					return nil, e
				}
			}
			out, e := repairPatch(b, patch)
			if e != nil {
				return nil, e
			}
			if e = a.propose(dir, &p, "security_patch.txt", out); e != nil {
				return nil, e
			}
		}
		if len(p.Changes) == 0 {
			return nil, fail("E_SELECTION", "The plan has no selected configuration change.")
		}
		if e = writeJSON(filepath.Join(dir, "plan.json"), p); e != nil {
			return nil, e
		}
		if e = a.history("plan", id, "review"); e != nil {
			return nil, e
		}
		return p.view(), nil
	})
}
func (a *App) propose(dir string, p *Plan, n string, b []byte) error {
	old := p.Active[n]
	if old.Exists && old.SHA256 == hash(b) {
		return nil
	}
	m := old.Metadata
	if !old.Exists {
		m = Metadata{0600, ownerID(), ownerID(), ""}
		dirMeta, e := getMetadata(a.Active)
		if e != nil {
			return e
		}
		m.SELinux = dirMeta.SELinux
	}
	p.Intended[n] = FileState{true, hash(b), int64(len(b)), m}
	p.Changes = append(p.Changes, n)
	preview := map[string]any{"file": n, "old_exists": old.Exists, "old_sha256": old.SHA256, "new_sha256": hash(b), "metadata": m}
	if n == "target.txt" || n == "security_patch.txt" {
		previous := []byte{}
		if old.Exists {
			var e error
			previous, e = bounded(filepath.Join(a.Active, n), 1<<20)
			if e != nil {
				return e
			}
		}
		added := []string{}
		removed := []string{}
		if n == "target.txt" {
			added = targetLineDelta(previous, b)
			removed = targetLineDelta(b, previous)
		} else {
			for _, pair := range [][2]string{{string(previous), string(b)}, {string(b), string(previous)}} {
				changes := []string{}
				for _, line := range strings.Split(pair[1], "\n") {
					if line != "" && !lineIn(line, pair[0]) {
						changes = append(changes, line)
					}
				}
				if len(added) == 0 && pair[0] == string(previous) {
					added = changes
				} else {
					removed = changes
				}
			}
		}
		preview["added_lines"] = added
		preview["removed_lines"] = removed
	}
	p.Preview = append(p.Preview, preview)
	return atomicWrite(filepath.Join(dir, n), b, Metadata{0600, ownerID(), ownerID(), ""})
}
func lineIn(line, s string) bool {
	for _, x := range strings.Split(s, "\n") {
		if x == line {
			return true
		}
	}
	return false
}

var requiredPackages = []string{"com.google.android.apps.walletnfcrel", "com.google.android.gms", "com.android.vending", "com.google.android.gsf"}

func repairTargets(b []byte) ([]byte, error) {
	s := string(b)
	for _, pkg := range requiredPackages {
		found := false
		lines := strings.Split(s, "\n")
		for i, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			v := strings.TrimSpace(line)
			base := strings.TrimRight(v, "!?")
			if base == pkg {
				if found {
					return nil, fail("E_SELECTION", "A required target has duplicate entries. Resolve its selection explicitly.")
				}
				found = true
				if v != pkg+"!" {
					if v == pkg+"?" {
						return nil, fail("E_SELECTION", "A required target uses leaf-hack mode. Review it explicitly before a generate-mode repair.")
					}
					if v != pkg {
						return nil, fail("E_SELECTION", "Unrecognized target flags require review.")
					}
					lines[i] = strings.Replace(line, pkg, pkg+"!", 1)
				}
			}
		}
		s = strings.Join(lines, "\n")
		if !found {
			if s != "" && !strings.HasSuffix(s, "\n") {
				s += "\n"
			}
			s += pkg + "!\n"
		}
	}
	return []byte(s), nil
}
func repairPatch(b []byte, patch string) ([]byte, error) {
	s := string(b)
	lines := strings.Split(s, "\n")
	found := false
	for i, l := range lines {
		v := strings.TrimSpace(l)
		if strings.HasPrefix(v, "all=") {
			if found {
				return nil, fail("E_SELECTION", "Duplicate global patch settings require manual review.")
			}
			found = true
			lines[i] = "all=" + patch
		} else if strings.HasPrefix(v, "system=") || strings.HasPrefix(v, "boot=") || strings.HasPrefix(v, "vendor=") {
			return nil, fail("E_SELECTION", "Per-partition patch settings require a separate reviewed plan.")
		}
	}
	s = strings.Join(lines, "\n")
	if !found {
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		s += "all=" + patch + "\n"
	}
	return []byte(s), nil
}
func (a *App) loadPlan(id string) (Plan, string, error) {
	dir, e := a.object("plans", id)
	if e != nil {
		return Plan{}, dir, e
	}
	var p Plan
	e = readJSON(filepath.Join(dir, "plan.json"), &p)
	if e != nil {
		return p, dir, e
	}
	if p.Schema != 1 || p.ID != id || (p.Type != "apply" && p.Type != "rollback") {
		return p, dir, fail("E_FORMAT", "Unsupported or corrupt plan format.")
	}
	if !validTargetCompaction(p.TargetCompaction) || (p.Type != "apply" && p.TargetCompaction != nil) {
		return p, dir, fail("E_FORMAT", "Target compaction reporting metadata is invalid.")
	}
	if len(p.Active) != 3 || len(p.Intended) != 3 {
		return p, dir, fail("E_FORMAT", "Incomplete configuration-set plan.")
	}
	changed := map[string]bool{}
	for _, name := range p.Changes {
		if !allowedFile(name) || changed[name] {
			return p, dir, fail("E_FORMAT", "Unknown or duplicate change in plan.")
		}
		changed[name] = true
	}
	for _, name := range files {
		old, ok := p.Active[name]
		next, nok := p.Intended[name]
		if !ok || !nok {
			return p, dir, fail("E_FORMAT", "Plan is missing a required file state.")
		}
		if (old != next) != changed[name] {
			return p, dir, fail("E_FORMAT", "Plan changes do not match its file states.")
		}
		for _, st := range []FileState{old, next} {
			if !a.validState(st) {
				return p, dir, fail("E_FORMAT", "Invalid planned file metadata.")
			}
		}
	}
	if len(changed) == 0 {
		return p, dir, fail("E_FORMAT", "Empty plan.")
	}
	if p.Type == "apply" && changed["keybox.xml"] && (len(p.Inputs) == 0 || len(p.Selections) == 0) {
		return p, dir, fail("E_FORMAT", "Keybox replacement must bind validated inputs and explicit selections.")
	}
	return p, dir, nil
}
