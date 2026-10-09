package core

// Stack resources intentionally use a separate registry and journal. They never
// enter the TrickyStore three-file allowlist or imply runtime/payment approval.
import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const stackLimit = 1 << 20

var stackBackendName = regexp.MustCompile(`^hide_my_applist_[a-z]{16}$`)
var stackPackage = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

type StackPlan struct {
	Schema         int                  `json:"schema"`
	ID             string               `json:"id"`
	Time           string               `json:"time"`
	Profile        string               `json:"profile"`
	Resource       string               `json:"resource"`
	Locator        string               `json:"locator"`
	Targets        []string             `json:"targets"`
	HidePackages   []string             `json:"hide_packages"`
	Enabled        bool                 `json:"enabled"`
	Before         FileState            `json:"before"`
	After          FileState            `json:"after"`
	Parent         Metadata             `json:"parent"`
	Protected      map[string]FileState `json:"protected"`
	Capabilities   map[string]string    `json:"capabilities"`
	EvidenceBefore string               `json:"evidence_before"`
	Changes        []map[string]any     `json:"changes"`
}

type stackJournal struct {
	Schema   int       `json:"schema"`
	ID       string    `json:"id"`
	Profile  string    `json:"profile"`
	Resource string    `json:"resource"`
	Locator  string    `json:"locator"`
	State    string    `json:"state"`
	Time     string    `json:"time"`
	Before   FileState `json:"before"`
	After    FileState `json:"after"`
	Parent   Metadata  `json:"parent"`
}

type stackBackup struct {
	Schema          int                  `json:"schema"`
	ID              string               `json:"id"`
	Resource        string               `json:"resource"`
	Locator         string               `json:"locator"`
	Time            string               `json:"time"`
	Before          FileState            `json:"before"`
	Parent          Metadata             `json:"parent"`
	ProtectedBackup string               `json:"protected_backup"`
	Protected       map[string]FileState `json:"protected"`
}

func stackResource(profile string) string {
	switch profile {
	case "hma-scope":
		return "hma-config"
	case "brezygisk-unmount":
		return "brezygisk-unmount"
	}
	return ""
}
func stackWarnings() []string {
	return []string{"Manual reboot and fresh application checks are required for activation and rollback. File readback does not prove runtime adoption.", "Other root writers are outside the helper lock. Conflicts are preserved privately and require review.", "Root-stack configuration is not proof of hardware identity, integrity verdicts or Wallet acceptance."}
}
func (p StackPlan) view() map[string]any {
	return map[string]any{"id": p.ID, "profile": p.Profile, "resource": p.Resource, "changes": p.Changes, "manual_reboot_required": true, "runtime_adoption": "unknown", "private_backup": "created-on-apply", "warnings": stackWarnings()}
}
func (a *App) stackBasePath() string {
	if a.Fake {
		return filepath.Join(filepath.Dir(a.Active), "stack-system", "data")
	}
	return "/data"
}
func (a *App) stackDir() string { return filepath.Join(a.Root, "stack") }
func (a *App) stackInit() error {
	for _, p := range []string{a.stackDir(), filepath.Join(a.stackDir(), "plans"), filepath.Join(a.stackDir(), "backups")} {
		if e := noLinks(p); e != nil {
			return e
		}
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
		if e := setMetadata(p, Metadata{Mode: 0700, UID: ownerID(), GID: ownerID()}); e != nil {
			return e
		}
		if e := syncDir(p); e != nil {
			return e
		}
		if e := syncDir(filepath.Dir(p)); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) stackObject(kind, id string) (string, error) {
	if (kind != "plans" && kind != "backups") || !validID.MatchString(id) {
		return "", fail("E_ID", "Choose a valid stack plan ID.")
	}
	p := filepath.Join(a.stackDir(), kind, id)
	return p, noLinks(p)
}

// No caller-supplied paths. The HMA backend locator is discovered, then bound in
// private plan/journal metadata; it is never rendered to the WebUI.
func (a *App) stackPath(resource, locator string) (string, string, error) {
	base := a.stackBasePath()
	if e := noLinks(base); e != nil {
		return "", "", e
	}
	switch resource {
	case "hma-config":
		parent := filepath.Join(base, "misc")
		if e := noLinks(parent); e != nil {
			return "", "", e
		}
		entries, e := os.ReadDir(parent)
		if e != nil {
			return "", "", fail("E_CAPABILITY", "The supported HMA resource is unavailable.")
		}
		name := ""
		count := 0
		for _, entry := range entries {
			if stackBackendName.MatchString(entry.Name()) {
				count++
				name = entry.Name()
				if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
					return "", "", fail("E_PATH", "The supported HMA backend is unsafe.")
				}
			}
		}
		if count != 1 {
			return "", "", fail("E_CAPABILITY", "Exactly one supported HMA backend directory is required.")
		}
		if locator != "" && name != locator {
			return "", "", fail("E_STALE", "The HMA backend location changed. Create a new review.")
		}
		p := filepath.Join(parent, name, "config.json")
		return p, name, noLinks(p)
	case "brezygisk-unmount":
		if locator != "" {
			return "", "", fail("E_FORMAT", "The marker resource contains an unsupported locator.")
		}
		p := filepath.Join(base, "adb", "brezygisk", "unmount")
		return p, "", noLinks(p)
	}
	return "", "", fail("E_REQUEST", "Choose a supported stack profile.")
}
func (a *App) stackRead(resource, locator string) (FileState, []byte, Metadata, string, error) {
	p, loc, e := a.stackPath(resource, locator)
	if e != nil {
		return FileState{}, nil, Metadata{}, "", e
	}
	parent, e := getMetadata(filepath.Dir(p))
	if e != nil {
		return FileState{}, nil, Metadata{}, "", fail("E_CAPABILITY", "The stack resource parent is unavailable.")
	}
	if !a.Fake {
		uid, gid := 0, 0
		if resource == "hma-config" {
			uid, gid = 1000, 1000
		}
		if parent.UID != uid || parent.GID != gid || parent.Mode&0077 != 0 || parent.SELinux == "" {
			return FileState{}, nil, Metadata{}, "", fail("E_CAPABILITY", "Stack resource parent ownership and access are not verified.")
		}
	}
	b, e := bounded(p, stackLimit)
	if os.IsNotExist(e) && resource == "brezygisk-unmount" {
		return FileState{}, nil, parent, loc, nil
	}
	if e != nil {
		return FileState{}, nil, Metadata{}, "", e
	}
	m, e := getMetadata(p)
	if e != nil {
		return FileState{}, nil, Metadata{}, "", e
	}
	st := FileState{true, hash(b), int64(len(b)), m}
	if !a.validState(st) {
		return FileState{}, nil, Metadata{}, "", fail("E_CAPABILITY", "Stack resource metadata is unsupported.")
	}
	if !a.Fake {
		uid, gid := 0, 0
		if resource == "hma-config" {
			uid, gid = 1000, 1000
		}
		if m.UID != uid || m.GID != gid || (resource == "hma-config" && m.Mode != 0600) || m.SELinux == "" {
			return FileState{}, nil, Metadata{}, "", fail("E_CAPABILITY", "Stack resource ownership, permissions or SELinux metadata are not verified.")
		}
	}
	return st, b, parent, loc, nil
}

var stackPins = map[string]map[string]string{
	"hma-scope":         {"hma_oss_zygisk/classes.dex": "a23261736dad9c0110b2cd481e20cc2f4cd970121a8701571ff023ec296f3a27", "hma_oss_zygisk/manager.apk": "e2f28be0689080ba205de90b9f9f2be13fbcd28b9938f2c52dbe766562a765ac", "hma_oss_zygisk/zygisk/arm64-v8a.so": "dfa7bd47ed7a89610f93c7545999d8c1c998fd83b459ca0a8e84b708f192d7c1"},
	"brezygisk-unmount": {"rezygisk/bin/zygiskd64": "f28aeaaa6a61e282106a07a834ec83554f2d5601d34dc1039605f8da7ad9e196", "rezygisk/bin/zygisk-ptrace64": "fd6e647a7dc5c7593082843aeab49af589b3be9f712c826906a4e0c48c1259ae", "rezygisk/lib64/libzygisk.so": "94819756ff8d2ea51e4368ff3b90dac99f7e16fd92da8fa52f85f6108d72b895"},
}

func (a *App) stackCode(profile string) (map[string]string, error) {
	if stackResource(profile) == "" {
		return nil, fail("E_REQUEST", "Choose a supported stack profile.")
	}
	out := map[string]string{}
	if a.Fake {
		out["stack-code-mode"] = "synthetic"
		return out, nil
	}
	for rel, want := range stackPins[profile] {
		body, e := bounded(filepath.Join(a.Modules, filepath.FromSlash(rel)), 32<<20)
		if e != nil || hash(body) != want {
			return nil, fail("E_CAPABILITY", "The installed stack programs do not match the inspected version.")
		}
		out[rel] = want
	}
	mod := "rezygisk"
	if profile == "hma-scope" {
		mod = "hma_oss_zygisk"
	}
	for _, marker := range []string{"disable", "remove"} {
		_, e := os.Lstat(filepath.Join(a.Modules, mod, marker))
		if !os.IsNotExist(e) {
			return nil, fail("E_CAPABILITY", "The selected stack module is disabled or pending removal.")
		}
	}
	return out, nil
}
func (a *App) stackCapabilities(profile string) (map[string]string, error) {
	out, e := a.capabilities()
	if e != nil {
		return nil, e
	}
	delete(out, "stack_evidence_binding")
	code, e := a.stackCode(profile)
	if e != nil {
		return nil, e
	}
	for k, v := range code {
		out[k] = v
	}
	other, e := a.stackEvidenceExcept(stackResource(profile))
	if e != nil {
		return nil, e
	}
	out["other_stack_evidence"] = other
	pif, e := bounded(filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), 64<<10)
	if e != nil {
		return nil, e
	}
	out["pif_hash"] = hash(pif)
	entries, e := os.ReadDir(a.Modules)
	if e != nil {
		return nil, e
	}
	moduleStates := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(a.Modules, entry.Name())
		if e := noLinks(dir); e != nil {
			return nil, e
		}
		prop, e := bounded(filepath.Join(dir, "module.prop"), 64<<10)
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		state := entry.Name() + ":" + hash(prop)
		for _, marker := range []string{"disable", "remove"} {
			p := filepath.Join(dir, marker)
			if e := noLinks(p); e != nil {
				return nil, e
			}
			_, e := os.Lstat(p)
			if e == nil {
				state += ":" + marker
			} else if !os.IsNotExist(e) {
				return nil, e
			}
		}
		moduleStates = append(moduleStates, state)
	}
	sort.Strings(moduleStates)
	out["module_state_hash"] = hash([]byte(strings.Join(moduleStates, "\n")))
	out["boot"] = "offline"
	out["user"] = "0"
	if !a.Fake {
		out["boot"] = bootID()
		if !validBoot.MatchString(out["boot"]) {
			return nil, fail("E_CAPABILITY", "Current boot identity is unavailable.")
		}
		u, e := run("am", "get-current-user")
		if e != nil || strings.TrimSpace(u) != "0" {
			return nil, fail("E_CAPABILITY", "Only the verified owner user is supported for stack changes.")
		}
	}
	return out, nil
}

// Strict duplicate-key validation covers unknown fields too. Unknown JSON values
// remain RawMessage so unrelated fields and numeric values are preserved.
func stackJSON(body []byte, v any) error {
	return stackJSONCheck(body, v, false)
}
func stackJSONCheck(body []byte, v any, foldKeys bool) error {
	if len(body) == 0 || len(body) > stackLimit || !utf8.Valid(body) {
		return fail("E_FORMAT", "Stack JSON is empty or exceeds its supported bound.")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 200000 {
			return errors.New("bound")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if foldKeys {
					s = strings.ToLower(s)
				}
				if !ok || seen[s] {
					return errors.New("duplicate")
				}
				seen[s] = true
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("format")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return fail("E_FORMAT", "Stack JSON has invalid, duplicate or unsupported structure.")
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("E_FORMAT", "Stack JSON contains trailing data.")
	}
	if e := json.Unmarshal(body, v); e != nil {
		return fail("E_FORMAT", "Stack JSON has unsupported field types.")
	}
	return nil
}
func stackReadJSON(path string, v any) error {
	b, e := bounded(path, stackLimit)
	if e != nil {
		return e
	}
	if e = stackJSONCheck(b, v, true); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return fail("E_FORMAT", "Private stack metadata has unknown or unsupported fields.")
	}
	return nil
}
func stackList(s string, scopes bool) ([]string, error) {
	if s == "" || len(s) > 16384 {
		return nil, fail("E_SELECTION", "Select an explicit bounded package list.")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if len(v) > 255 || !stackPackage.MatchString(v) || seen[v] {
			return nil, fail("E_SELECTION", "Package selections must be valid and unique.")
		}
		if scopes {
			ok := false
			for _, p := range requiredPackages {
				if v == p {
					ok = true
				}
			}
			if !ok {
				return nil, fail("E_SELECTION", "Only the four supported Google scopes may be selected.")
			}
		}
		seen[v] = true
		out = append(out, v)
	}
	limit := 32
	if scopes {
		limit = 4
	}
	if len(out) > limit {
		return nil, fail("E_SELECTION", "Select at most four Google scopes and 32 packages.")
	}
	sort.Strings(out)
	return out, nil
}
func stackForbiddenPackage(pkg string) bool {
	for _, p := range requiredPackages {
		if pkg == p {
			return true
		}
	}
	denied := map[string]bool{"android": true, "android.media": true, "android.uid.system": true, "android.uid.shell": true, "android.uid.systemui": true, "com.android.permissioncontroller": true, "com.android.providers.downloads": true, "com.android.providers.downloads.ui": true, "com.android.providers.media": true, "com.android.providers.media.module": true, "com.android.providers.settings": true, "com.google.android.providers.media.module": true, "com.google.android.permissioncontroller": true, "com.miui.securitycenter": true, "com.android.settings": true, "com.android.systemui": true, "org.frknkrc44.hma_oss": true, "com.tsng.hidemyapplist": true, "io.github.a13e300.ksuwebui": true}
	return denied[pkg]
}
func (a *App) stackInstalled(targets, packages []string) error {
	if a.Fake {
		return nil
	}
	out, e := run("/system/bin/pm", "list", "packages", "--user", "0")
	if e != nil {
		return fail("E_CAPABILITY", "Installed package availability could not be verified.")
	}
	installed := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			installed[strings.TrimPrefix(line, "package:")] = true
		}
	}
	for _, pkg := range append(append([]string{}, targets...), packages...) {
		if !installed[pkg] {
			return fail("E_SELECTION", "A selected scope or hide package is unavailable for the owner user.")
		}
	}
	return nil
}
func stackAppList(obj map[string]json.RawMessage, key string) ([]string, error) {
	raw, ok := obj[key]
	if !ok {
		return []string{}, nil
	}
	var out []string
	if e := json.Unmarshal(raw, &out); e != nil || out == nil || len(out) > 4096 {
		return nil, fail("E_FORMAT", "A selected HMA package set is unsupported.")
	}
	seen := map[string]bool{}
	for _, p := range out {
		if len(p) > 255 || !stackPackage.MatchString(p) || seen[p] {
			return nil, fail("E_FORMAT", "A selected HMA package set is ambiguous.")
		}
		seen[p] = true
	}
	return out, nil
}
func stackBlacklist(obj map[string]json.RawMessage) error {
	if obj == nil {
		return fail("E_FORMAT", "A selected HMA scope is unsupported.")
	}
	if raw, ok := obj["useWhitelist"]; ok {
		literal := string(bytes.TrimSpace(raw))
		if literal != "false" && literal != "true" {
			return fail("E_FORMAT", "A selected HMA whitelist field is not a boolean.")
		}
		var v bool
		if json.Unmarshal(raw, &v) != nil || v {
			return fail("E_SELECTION", "Whitelist scopes require separate review; this profile only adds blacklist entries.")
		}
	}
	return nil
}
func stackHMA(body []byte, targets, hide []string) ([]byte, []map[string]any, error) {
	var root map[string]json.RawMessage
	if e := stackJSON(body, &root); e != nil {
		return nil, nil, e
	}
	if root == nil || string(bytes.TrimSpace(root["configVersion"])) != "93" {
		return nil, nil, fail("E_CAPABILITY", "Only the inspected HMA configuration schema 93 is supported.")
	}
	var scope map[string]json.RawMessage
	if json.Unmarshal(root["scope"], &scope) != nil || scope == nil {
		return nil, nil, fail("E_FORMAT", "HMA scope configuration is unsupported.")
	}
	var defaults map[string]json.RawMessage
	if raw, ok := root["defaultConfig"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if json.Unmarshal(raw, &defaults) != nil || defaults == nil {
			return nil, nil, fail("E_FORMAT", "HMA default configuration is unsupported.")
		}
		if e := stackBlacklist(defaults); e != nil {
			return nil, nil, e
		}
	}
	changes := []map[string]any{}
	for _, target := range targets {
		obj := map[string]json.RawMessage{}
		created := 0
		if raw, ok := scope[target]; ok {
			if json.Unmarshal(raw, &obj) != nil {
				return nil, nil, fail("E_FORMAT", "A selected HMA scope is unsupported.")
			}
		} else {
			created = 1
			obj["useWhitelist"] = json.RawMessage("false")
			for k, v := range defaults {
				obj[k] = append(json.RawMessage{}, v...)
			}
		}
		if e := stackBlacklist(obj); e != nil {
			return nil, nil, e
		}
		existing, e := stackAppList(obj, "extraAppList")
		if e != nil {
			return nil, nil, e
		}
		opposite, e := stackAppList(obj, "extraOppositeAppList")
		if e != nil {
			return nil, nil, e
		}
		opp := map[string]bool{}
		for _, p := range opposite {
			opp[p] = true
		}
		seen := map[string]bool{}
		for _, p := range existing {
			seen[p] = true
		}
		added := 0
		for _, p := range hide {
			if opp[p] {
				return nil, nil, fail("E_SELECTION", "A selected package conflicts with the scope's opposite list.")
			}
			if !seen[p] {
				existing = append(existing, p)
				seen[p] = true
				added++
			}
		}
		if added == 0 {
			continue
		}
		obj["extraAppList"], _ = json.Marshal(existing)
		scope[target], _ = json.Marshal(obj)
		changes = append(changes, map[string]any{"target": target, "added_count": added, "scopes_created": created})
	}
	if len(changes) == 0 {
		return nil, nil, fail("E_SELECTION", "The selected stack profile has no configuration change.")
	}
	root["scope"], _ = json.Marshal(scope)
	out, e := json.MarshalIndent(root, "", "  ")
	if e != nil || len(out)+1 > stackLimit {
		return nil, nil, fail("E_FORMAT", "The proposed HMA configuration exceeds its supported bound.")
	}
	return append(out, '\n'), changes, nil
}

// Combined evidence reads current resource bytes/metadata, never just a saved
// journal ID. Missing installations are explicit absence; unsafe paths fail.
func (a *App) stackEvidenceBinding() (string, error) {
	return a.stackEvidenceExcept("")
}
func (a *App) stackEvidenceExcept(exclude string) (string, error) {
	out := map[string]any{}
	pifPath := filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop")
	pif, e := bounded(pifPath, 64<<10)
	if os.IsNotExist(e) {
		out["pif"] = FileState{}
	} else if e != nil {
		return "", fail("E_CAPABILITY", "PIF evidence is unsafe or unavailable.")
	} else {
		m, e := getMetadata(pifPath)
		if e != nil {
			return "", fail("E_CAPABILITY", "PIF metadata is unavailable.")
		}
		st := FileState{true, hash(pif), int64(len(pif)), m}
		if !a.validState(st) {
			return "", fail("E_CAPABILITY", "PIF metadata is unsupported.")
		}
		out["pif"] = st
	}
	for _, profile := range []string{"hma-scope", "brezygisk-unmount"} {
		resource := stackResource(profile)
		code := map[string]string{}
		for rel := range stackPins[profile] {
			p := filepath.Join(a.Modules, filepath.FromSlash(rel))
			b, e := bounded(p, 32<<20)
			if os.IsNotExist(e) {
				code[rel] = "absent"
			} else if e != nil {
				return "", fail("E_CAPABILITY", "Stack program evidence is unsafe or unavailable.")
			} else {
				code[rel] = hash(b)
			}
		}
		st, b, parent, loc, e := a.stackRead(resource, "")
		if e != nil {
			var ce *Error
			if errors.As(e, &ce) && ce.Code == "E_PATH" {
				return "", fail("E_CAPABILITY", "Stack resource evidence is unsafe.")
			}
			p := filepath.Join(a.stackBasePath(), "misc")
			if resource == "brezygisk-unmount" {
				p = filepath.Join(a.stackBasePath(), "adb", "brezygisk")
			}
			absent := false
			if _, se := os.Lstat(p); os.IsNotExist(se) {
				absent = true
			}
			if resource == "hma-config" && !absent {
				entries, re := os.ReadDir(p)
				if re == nil {
					absent = true
					for _, entry := range entries {
						if stackBackendName.MatchString(entry.Name()) {
							absent = false
						}
					}
				}
			}
			if !absent {
				return "", fail("E_CAPABILITY", "Stack resource evidence is ambiguous or unavailable.")
			}
			out[resource] = map[string]any{"state": "absent", "code": code}
			continue
		}
		if resource == "hma-config" {
			var obj map[string]json.RawMessage
			if e := stackJSON(b, &obj); e != nil || obj == nil || string(bytes.TrimSpace(obj["configVersion"])) != "93" {
				return "", fail("E_CAPABILITY", "HMA evidence has unsupported configuration structure.")
			}
		}
		if resource == exclude {
			out[resource] = map[string]any{"parent": parent, "locator": loc, "code": code}
		} else {
			out[resource] = map[string]any{"file": st, "parent": parent, "locator": loc, "code": code}
		}
	}
	b, _ := json.Marshal(out)
	return hash(b), nil
}
func (a *App) validateStackJournal(j stackJournal) error {
	if j.Schema != 1 || !validID.MatchString(j.ID) || stackResource(j.Profile) != j.Resource || j.Resource == "" || !a.validState(j.Before) || !a.validState(j.After) || j.Before == j.After {
		return fail("E_RECOVERY", "Stack journal is corrupt or unsupported. Preserve private recovery evidence.")
	}
	if _, e := time.Parse(time.RFC3339, j.Time); e != nil {
		return fail("E_RECOVERY", "Stack journal timestamp is unsupported.")
	}
	if !a.validStackParent(j.Parent, j.Resource) {
		return fail("E_RECOVERY", "Stack journal parent metadata is unsupported.")
	}
	if !a.validStackOriginal(j.Before, j.Resource) {
		return fail("E_RECOVERY", "Stack journal original resource metadata is unsupported.")
	}
	if j.Resource == "hma-config" && (!j.After.Exists || j.After.Metadata != j.Before.Metadata) {
		return fail("E_RECOVERY", "HMA journal transition is unsupported.")
	}
	if j.Resource == "brezygisk-unmount" {
		if j.After.Exists {
			want := Metadata{Mode: 0600, UID: ownerID(), GID: ownerID(), SELinux: j.Parent.SELinux}
			if j.Before.Exists || j.After.Size != 0 || j.After.SHA256 != hash(nil) || j.After.Metadata != want {
				return fail("E_RECOVERY", "Marker journal transition is unsupported.")
			}
		} else if !j.Before.Exists {
			return fail("E_RECOVERY", "Marker journal transition is unsupported.")
		}
	}
	if (j.Resource == "hma-config" && !stackBackendName.MatchString(j.Locator)) || (j.Resource == "brezygisk-unmount" && j.Locator != "") {
		return fail("E_RECOVERY", "Stack journal resource binding is unsupported.")
	}
	switch j.State {
	case "applying", "writing", "committed", "restoring", "restored", "recovery-required":
	default:
		return fail("E_RECOVERY", "Stack journal state is unsupported.")
	}
	return nil
}
func (a *App) validStackOriginal(st FileState, resource string) bool {
	if !a.validState(st) {
		return false
	}
	if !st.Exists {
		return resource == "brezygisk-unmount"
	}
	if resource == "hma-config" && st.Metadata.Mode != 0600 {
		return false
	}
	uid, gid := 0, 0
	if resource == "hma-config" {
		uid, gid = 1000, 1000
	}
	if a.Fake {
		uid, gid = ownerID(), ownerID()
	}
	return st.Metadata.UID == uid && st.Metadata.GID == gid && (a.Fake || st.Metadata.SELinux != "")
}
func (a *App) validStackParent(m Metadata, resource string) bool {
	if m.Mode != 0700 || len(m.SELinux) > 256 || (m.SELinux != "" && !validContext.MatchString(m.SELinux)) {
		return false
	}
	uid, gid := 0, 0
	if resource == "hma-config" {
		uid, gid = 1000, 1000
	}
	if a.Fake {
		return m.UID == ownerID() && m.GID == ownerID()
	}
	return m.UID == uid && m.GID == gid && m.SELinux != ""
}
func (a *App) stackUnfinished() bool {
	var j stackJournal
	e := stackReadJSON(filepath.Join(a.Root, "stack-journal.json"), &j)
	if os.IsNotExist(e) {
		return false
	}
	return e != nil || a.validateStackJournal(j) != nil || (j.State != "committed" && j.State != "restored")
}
func (a *App) stackForeignRecovered() error {
	var j Journal
	e := readJSON(filepath.Join(a.Root, "journal.json"), &j)
	if (e != nil && !os.IsNotExist(e)) || (e == nil && (a.validateJournal(j) != nil || (j.State != "committed" && j.State != "restored"))) {
		return fail("E_RECOVERY", "Restore the protected configuration transaction before changing stack resources.")
	}
	var reset resetJournal
	e = readJSON(filepath.Join(a.Root, "reset-journal.json"), &reset)
	if (e != nil && !os.IsNotExist(e)) || (e == nil && (a.validateReset(reset, false) != nil || reset.State != "completed")) {
		return fail("E_RECOVERY", "Complete or inspect the pending reset before changing stack resources.")
	}
	return nil
}
func (a *App) stackStatus() map[string]any {
	profiles := []map[string]any{}
	pending := a.stackUnfinished() || a.stackForeignRecovered() != nil
	for _, profile := range []string{"hma-scope", "brezygisk-unmount"} {
		code := "available"
		reason := "Available for explicit planning."
		if pending {
			code, reason = "recovery_pending", "Recovery is required before another change."
		} else if _, e := a.stackCode(profile); e != nil {
			code, reason = "unsupported_capability", "The installed stack program is unsupported or unavailable."
		} else if _, b, _, _, e := a.stackRead(stackResource(profile), ""); e != nil {
			code, reason = "resource_unavailable", "The supported stack resource is unavailable or unsafe."
		} else if profile == "hma-scope" {
			var obj map[string]json.RawMessage
			if e := stackJSON(b, &obj); e != nil || obj == nil || string(bytes.TrimSpace(obj["configVersion"])) != "93" {
				code, reason = "unsupported_configuration", "The supported configuration schema could not be verified."
			}
		}
		profiles = append(profiles, map[string]any{"id": profile, "resource": stackResource(profile), "available": code == "available", "reason_code": code, "reason": reason})
	}
	var operation any
	var j stackJournal
	e := stackReadJSON(filepath.Join(a.Root, "stack-journal.json"), &j)
	if e == nil && a.validateStackJournal(j) == nil {
		_, be := a.stackLoadBackup(j.ID)
		operation = map[string]any{"id": j.ID, "profile": j.Profile, "state": j.State, "can_verify": be == nil && (j.State == "committed" || j.State == "restored"), "can_rollback": be == nil && j.State != "restored", "backup_available": be == nil}
	} else if !os.IsNotExist(e) {
		operation = map[string]any{"state": "unreadable", "can_verify": false, "can_rollback": false, "backup_available": false}
	}
	return map[string]any{"profiles": profiles, "allowed_targets": append([]string{}, requiredPackages...), "unfinished": pending, "stack_pending": a.stackUnfinished(), "operation": operation, "manual_reboot_required": true, "runtime_adoption": "unknown", "warnings": stackWarnings()}
}

func (a *App) Stack(action, profile, targets, hidePackages, enabled, id string) (any, error) {
	return a.withLock(func() (any, error) {
		if action == "plan" {
			if id != "" {
				return nil, fail("E_REQUEST", "Stack planning does not accept an operation ID.")
			}
		} else if profile != "" || targets != "" || hidePackages != "" || enabled != "" || (action == "status" && id != "") {
			return nil, fail("E_REQUEST", "This stack action accepts only its documented operation ID.")
		}
		switch action {
		case "status":
			return a.stackStatus(), nil
		case "plan":
			return a.stackPlan(profile, targets, hidePackages, enabled)
		case "apply":
			return a.stackApply(id)
		case "verify":
			return a.stackVerify(id)
		case "rollback":
			return a.stackRollback(id)
		default:
			return nil, fail("E_REQUEST", "Stack action must be status, plan, apply, verify or rollback.")
		}
	})
}
func (a *App) stackPlan(profile, targets, hidePackages, enabled string) (any, error) {
	if e := a.requireRecovered(); e != nil {
		return nil, e
	}
	if a.stackUnfinished() {
		return nil, fail("E_RECOVERY", "Restore the unfinished stack transaction first.")
	}
	resource := stackResource(profile)
	if resource == "" {
		return nil, fail("E_SELECTION", "Choose an explicit supported stack profile.")
	}
	caps, e := a.stackCapabilities(profile)
	if e != nil {
		return nil, e
	}
	protected, e := a.snapshot()
	if e != nil {
		return nil, e
	}
	before, body, parent, loc, e := a.stackRead(resource, "")
	if e != nil {
		return nil, e
	}
	evidence, e := a.stackEvidenceBinding()
	if e != nil {
		return nil, e
	}
	p := StackPlan{Schema: 1, Time: a.time(), Profile: profile, Resource: resource, Locator: loc, Before: before, Parent: parent, Protected: protected, Capabilities: caps, EvidenceBefore: evidence}
	out := []byte{}
	if profile == "hma-scope" {
		if enabled != "" {
			return nil, fail("E_SELECTION", "The HMA profile does not accept a global toggle.")
		}
		p.Targets, e = stackList(targets, true)
		if e != nil {
			return nil, e
		}
		p.HidePackages, e = stackList(hidePackages, false)
		if e != nil {
			return nil, e
		}
		for _, pkg := range p.HidePackages {
			if stackForbiddenPackage(pkg) {
				return nil, fail("E_SELECTION", "A selected package is protected or belongs to the helper or supported Google scopes.")
			}
		}
		if e = a.stackInstalled(p.Targets, p.HidePackages); e != nil {
			return nil, e
		}
		out, p.Changes, e = stackHMA(body, p.Targets, p.HidePackages)
		if e != nil {
			return nil, e
		}
		p.After = FileState{true, hash(out), int64(len(out)), before.Metadata}
	} else {
		if targets != "" || hidePackages != "" || (enabled != "true" && enabled != "false") {
			return nil, fail("E_SELECTION", "Choose an explicit marker state without HMA selections.")
		}
		p.Enabled = enabled == "true"
		if before.Exists == p.Enabled {
			return nil, fail("E_SELECTION", "The selected marker intent is already recorded.")
		}
		p.Changes = []map[string]any{{"enabled_before": before.Exists, "enabled_after": p.Enabled}}
		if p.Enabled {
			m := Metadata{Mode: 0600, UID: ownerID(), GID: ownerID(), SELinux: parent.SELinux}
			p.After = FileState{true, hash(out), 0, m}
		}
	}
	if e = a.stackInit(); e != nil {
		return nil, e
	}
	p.ID, e = newID()
	if e != nil {
		return nil, e
	}
	dir, _ := a.stackObject("plans", p.ID)
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	if p.After.Exists {
		if e = atomicWrite(filepath.Join(dir, "intent.bin"), out, Metadata{Mode: 0600, UID: ownerID(), GID: ownerID()}); e != nil {
			return nil, e
		}
	}
	if e = writeJSON(filepath.Join(dir, "plan.json"), p); e != nil {
		return nil, e
	}
	if e = syncDir(dir); e != nil {
		return nil, e
	}
	if e = syncDir(filepath.Dir(dir)); e != nil {
		return nil, e
	}
	return p.view(), nil
}
func (a *App) stackLoadPlan(id string) (StackPlan, string, error) {
	dir, e := a.stackObject("plans", id)
	if e != nil {
		return StackPlan{}, "", e
	}
	var p StackPlan
	if e = stackReadJSON(filepath.Join(dir, "plan.json"), &p); e != nil {
		return p, dir, e
	}
	j := stackJournal{Schema: p.Schema, ID: p.ID, Profile: p.Profile, Resource: p.Resource, Locator: p.Locator, State: "applying", Time: p.Time, Before: p.Before, After: p.After, Parent: p.Parent}
	if p.ID != id || a.validateStackJournal(j) != nil || !validHash.MatchString(p.EvidenceBefore) || len(p.Protected) != 3 || len(p.Capabilities) == 0 {
		return p, dir, fail("E_FORMAT", "Stack plan is corrupt or unsupported.")
	}
	for _, n := range files {
		st, ok := p.Protected[n]
		if !ok || !a.validState(st) {
			return p, dir, fail("E_FORMAT", "Stack plan protected-file binding is incomplete.")
		}
	}
	if p.Profile == "hma-scope" {
		t, e := stackList(strings.Join(p.Targets, ","), true)
		if e != nil || strings.Join(t, ",") != strings.Join(p.Targets, ",") {
			return p, dir, fail("E_FORMAT", "Stack plan scope selection is invalid.")
		}
		h, e := stackList(strings.Join(p.HidePackages, ","), false)
		if e != nil || strings.Join(h, ",") != strings.Join(p.HidePackages, ",") {
			return p, dir, fail("E_FORMAT", "Stack plan package selection is invalid.")
		}
		for _, pkg := range h {
			if stackForbiddenPackage(pkg) {
				return p, dir, fail("E_FORMAT", "Stack plan contains a protected package.")
			}
		}
		if !p.Before.Exists || !p.After.Exists || p.After.Metadata != p.Before.Metadata {
			return p, dir, fail("E_FORMAT", "HMA plan metadata is unsupported.")
		}
	} else if len(p.Targets) != 0 || len(p.HidePackages) != 0 || p.After.Exists != p.Enabled || p.Before.Exists == p.Enabled {
		return p, dir, fail("E_FORMAT", "Marker plan selection is unsupported.")
	}
	if p.Profile == "brezygisk-unmount" && p.After.Exists {
		want := Metadata{Mode: 0600, UID: ownerID(), GID: ownerID(), SELinux: p.Parent.SELinux}
		if p.After.Metadata != want || p.After.Size != 0 || p.After.SHA256 != hash(nil) {
			return p, dir, fail("E_FORMAT", "Marker plan metadata is unsupported.")
		}
	}
	return p, dir, nil
}
func (a *App) stackCheckBase(p StackPlan, allowNewBoot bool) error {
	caps, e := a.stackCapabilities(p.Profile)
	if e != nil {
		return e
	}
	want := map[string]string{}
	for k, v := range p.Capabilities {
		want[k] = v
	}
	if allowNewBoot {
		delete(caps, "boot")
		delete(want, "boot")
	}
	if !sameStrings(caps, want) {
		return fail("E_STALE", "Protected programs, PIF, user or module state changed. Review a new stack plan.")
	}
	st, e := a.snapshot()
	if e != nil {
		return e
	}
	if !equal(st, p.Protected) {
		return fail("E_STALE", "Protected configuration changed. No stack resource was overwritten.")
	}
	if p.Profile == "hma-scope" {
		return a.stackInstalled(p.Targets, p.HidePackages)
	}
	return nil
}
func (a *App) stackCheckResource(p StackPlan, expected FileState) error {
	st, _, parent, _, e := a.stackRead(p.Resource, p.Locator)
	if e != nil {
		return e
	}
	if st != expected || parent != p.Parent {
		return fail("E_STALE", "The stack resource or its metadata changed outside this plan.")
	}
	return nil
}
func (a *App) stackLoadBackup(id string) (stackBackup, error) {
	dir, e := a.stackObject("backups", id)
	if e != nil {
		return stackBackup{}, e
	}
	var b stackBackup
	if e = stackReadJSON(filepath.Join(dir, "backup.json"), &b); e != nil {
		return b, e
	}
	if b.Schema != 1 || b.ID != id || !a.validStackOriginal(b.Before, b.Resource) || !a.validStackParent(b.Parent, b.Resource) || (b.Resource != "hma-config" && b.Resource != "brezygisk-unmount") || (b.Resource == "hma-config" && !stackBackendName.MatchString(b.Locator)) || (b.Resource == "brezygisk-unmount" && b.Locator != "") {
		return b, fail("E_BACKUP", "The private stack backup is corrupt or unsupported.")
	}
	if _, e = time.Parse(time.RFC3339, b.Time); e != nil {
		return b, fail("E_BACKUP", "The private stack backup timestamp is unsupported.")
	}
	if !validID.MatchString(b.ProtectedBackup) || len(b.Protected) != 3 {
		return b, fail("E_BACKUP", "The protected configuration backup association is incomplete.")
	}
	protected, e := a.loadBackup(b.ProtectedBackup)
	if e != nil || protected.Type != "stack-profile" || !equal(protected.Files, b.Protected) {
		return b, fail("E_BACKUP", "The associated protected configuration backup failed verification.")
	}
	p := filepath.Join(dir, "resource.bin")
	if !b.Before.Exists {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return b, fail("E_BACKUP", "The absent-resource backup contains unexpected data.")
		}
		return b, nil
	}
	body, e := bounded(p, stackLimit)
	if e != nil || hash(body) != b.Before.SHA256 || int64(len(body)) != b.Before.Size {
		return b, fail("E_BACKUP", "The private stack backup failed checksum verification.")
	}
	return b, nil
}
func (a *App) stackSaveBackup(p StackPlan) error {
	if e := a.checkpoint("stack-before-backup"); e != nil {
		return e
	}
	if e := enoughSpace(a.Root, uint64(8<<20)+uint64(p.Before.Size)*3); e != nil {
		return e
	}
	path, _, e := a.stackPath(p.Resource, p.Locator)
	if e != nil {
		return e
	}
	if e = enoughSpace(filepath.Dir(path), uint64(8<<20)+uint64(p.After.Size)*2); e != nil {
		return e
	}
	if e = a.stackCheckResource(p, p.Before); e != nil {
		return e
	}
	protected, e := a.backup("stack-profile", p.Protected)
	if e != nil {
		return e
	}
	dir, _ := a.stackObject("backups", p.ID)
	if e = os.Mkdir(dir, 0700); e != nil {
		return e
	}
	if p.Before.Exists {
		body, e := bounded(path, stackLimit)
		if e != nil || hash(body) != p.Before.SHA256 {
			return fail("E_STALE", "Stack resource changed during backup.")
		}
		if e = atomicWrite(filepath.Join(dir, "resource.bin"), body, Metadata{Mode: 0600, UID: ownerID(), GID: ownerID()}); e != nil {
			return e
		}
	}
	b := stackBackup{Schema: 1, ID: p.ID, Resource: p.Resource, Locator: p.Locator, Time: a.time(), Before: p.Before, Parent: p.Parent, ProtectedBackup: protected.ID, Protected: p.Protected}
	if e = writeJSON(filepath.Join(dir, "backup.json"), b); e != nil {
		return e
	}
	if e = syncDir(dir); e != nil {
		return e
	}
	if e = syncDir(filepath.Dir(dir)); e != nil {
		return e
	}
	if _, e = a.stackLoadBackup(p.ID); e != nil {
		return e
	}
	if e = a.stackCheckResource(p, p.Before); e != nil {
		return e
	}
	return a.checkpoint("stack-after-backup")
}
func (a *App) stackWrite(resource, locator string, st FileState, body []byte) error {
	p, _, e := a.stackPath(resource, locator)
	if e != nil {
		return e
	}
	if st.Exists {
		if hash(body) != st.SHA256 || int64(len(body)) != st.Size {
			return fail("E_FORMAT", "Stack write bytes do not match the reviewed state.")
		}
		return atomicWrite(p, body, st.Metadata)
	}
	if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDir(filepath.Dir(p))
}
func stackResult(j stackJournal) map[string]any {
	return map[string]any{"id": j.ID, "profile": j.Profile, "state": j.State, "private_backup": "verified", "manual_reboot_required": true, "runtime_adoption": "unknown", "readback_verified": true, "warnings": stackWarnings()}
}
func (a *App) stackApply(id string) (any, error) {
	if e := a.requireRecovered(); e != nil {
		return nil, e
	}
	if a.stackUnfinished() {
		return nil, fail("E_RECOVERY", "Restore the unfinished stack transaction first.")
	}
	p, dir, e := a.stackLoadPlan(id)
	if e != nil {
		return nil, e
	}
	when, _ := time.Parse(time.RFC3339, p.Time)
	if a.Now().Before(when) || a.Now().Sub(when) > 30*time.Minute {
		return nil, fail("E_STALE", "The stack plan expired. Create a fresh review.")
	}
	if _, e = os.Lstat(filepath.Join(dir, "submitted.json")); !os.IsNotExist(e) {
		return nil, fail("E_DUPLICATE", "This stack plan was already submitted. Inspect its recorded outcome.")
	}
	if e = a.stackCheckBase(p, false); e != nil {
		return nil, e
	}
	if e = a.stackCheckResource(p, p.Before); e != nil {
		return nil, e
	}
	binding, e := a.stackEvidenceBinding()
	if e != nil || binding != p.EvidenceBefore {
		return nil, fail("E_STALE", "Stack evidence changed. Create a fresh review.")
	}
	out := []byte{}
	if p.After.Exists {
		out, e = bounded(filepath.Join(dir, "intent.bin"), stackLimit)
		if e != nil || hash(out) != p.After.SHA256 || int64(len(out)) != p.After.Size {
			return nil, fail("E_STALE", "Proposed stack bytes changed. Create a fresh review.")
		}
	}
	if p.Profile == "hma-scope" {
		_, old, _, _, e := a.stackRead(p.Resource, p.Locator)
		if e != nil {
			return nil, e
		}
		expected, changes, e := stackHMA(old, p.Targets, p.HidePackages)
		if e != nil || !bytes.Equal(expected, out) {
			return nil, fail("E_FORMAT", "Proposed HMA bytes do not match the explicit selection.")
		}
		p.Changes = changes
	} else if p.After.Exists && len(out) != 0 {
		return nil, fail("E_FORMAT", "The marker intent contains unexpected bytes.")
	}
	if e = writeJSON(filepath.Join(dir, "submitted.json"), map[string]string{"time": a.time()}); e != nil {
		return nil, e
	}
	if e = a.stackSaveBackup(p); e != nil {
		return nil, e
	}
	if e = a.stackCheckBase(p, false); e != nil {
		return nil, e
	}
	j := stackJournal{1, p.ID, p.Profile, p.Resource, p.Locator, "applying", a.time(), p.Before, p.After, p.Parent}
	if e = writeJSON(filepath.Join(a.Root, "stack-journal.json"), j); e != nil {
		return nil, e
	}
	runErr := func() error {
		if e := a.checkpoint("stack-before-write"); e != nil {
			return e
		}
		if e := a.stackCheckBase(p, false); e != nil {
			return e
		}
		if e := a.stackCheckResource(p, p.Before); e != nil {
			return e
		}
		binding, e := a.stackEvidenceBinding()
		if e != nil || binding != p.EvidenceBefore {
			return fail("E_STALE", "Stack evidence changed before writing.")
		}
		j.State = "writing"
		if e = writeJSON(filepath.Join(a.Root, "stack-journal.json"), j); e != nil {
			return e
		}
		if e = a.stackWrite(p.Resource, p.Locator, p.After, out); e != nil {
			return e
		}
		if e = a.checkpoint("stack-after-write"); e != nil {
			return e
		}
		if e = a.stackCheckResource(p, p.After); e != nil {
			return e
		}
		if e = a.checkpoint("stack-before-commit"); e != nil {
			return e
		}
		if e = a.stackCheckBase(p, false); e != nil {
			return e
		}
		if e = a.stackCheckResource(p, p.After); e != nil {
			return e
		}
		j.State = "committed"
		if e = writeJSON(filepath.Join(a.Root, "stack-journal.json"), j); e != nil {
			return e
		}
		if e = a.checkpoint("stack-after-commit"); e != nil {
			return e
		}
		if e = a.stackCheckBase(p, false); e != nil {
			return e
		}
		if e = a.stackCheckResource(p, p.After); e != nil {
			return e
		}
		_, e = a.stackLoadBackup(p.ID)
		return e
	}()
	if runErr != nil {
		if e = a.stackRestore(p, &j, false); e != nil {
			j.State = "recovery-required"
			_ = writeJSON(filepath.Join(a.Root, "stack-journal.json"), j)
			return nil, fail("E_RECOVERY", "Stack application failed and restoration is pending. Preserve private recovery evidence.")
		}
		return stackResult(j), fail("E_ROLLED_BACK", "Stack application failed. Original file state was restored; runtime remains unknown and manual reboot is required.")
	}
	return stackResult(j), nil
}
func (a *App) stackConflict(p StackPlan, st FileState) error {
	dir, _ := a.stackObject("backups", p.ID)
	path, _, e := a.stackPath(p.Resource, p.Locator)
	if e != nil {
		return e
	}
	body := []byte{}
	if st.Exists {
		body, e = bounded(path, stackLimit)
		if e != nil || hash(body) != st.SHA256 {
			return fail("E_RECOVERY", "Conflicting stack resource changed during preservation.")
		}
		if e = atomicWrite(filepath.Join(dir, "conflict.bin"), body, Metadata{Mode: 0600, UID: ownerID(), GID: ownerID()}); e != nil {
			return e
		}
	}
	return writeJSON(filepath.Join(dir, "conflict.json"), map[string]any{"schema": 1, "state": st, "time": a.time()})
}

// Explicit rollback preserves its actual current resource independently of the
// immutable original backup. The private association also verifies a fresh
// protected three-file backup; rollback never restores those protected files.
func (a *App) stackRollbackCurrent(p StackPlan, current FileState) error {
	dir, e := a.stackObject("backups", p.ID)
	if e != nil {
		return e
	}
	load := func() error {
		var r stackBackup
		if e := stackReadJSON(filepath.Join(dir, "rollback-current.json"), &r); e != nil {
			return fail("E_BACKUP", "Current stack rollback evidence is unreadable.")
		}
		if r.Schema != 1 || r.ID != p.ID || r.Resource != p.Resource || r.Locator != p.Locator || r.Before != current || r.Parent != p.Parent || !equal(r.Protected, p.Protected) || !validID.MatchString(r.ProtectedBackup) {
			return fail("E_BACKUP", "Current stack rollback evidence has an invalid binding.")
		}
		if _, e := time.Parse(time.RFC3339, r.Time); e != nil {
			return fail("E_BACKUP", "Current stack rollback evidence has an invalid timestamp.")
		}
		b, e := a.loadBackup(r.ProtectedBackup)
		if e != nil || b.Type != "stack-profile" || !equal(b.Files, p.Protected) {
			return fail("E_BACKUP", "Current stack rollback protected backup failed verification.")
		}
		path := filepath.Join(dir, "rollback-current.bin")
		if !current.Exists {
			if _, e := os.Lstat(path); !os.IsNotExist(e) {
				return fail("E_BACKUP", "Absent current stack rollback evidence contains unexpected bytes.")
			}
			return nil
		}
		body, e := bounded(path, stackLimit)
		if e != nil || hash(body) != current.SHA256 || int64(len(body)) != current.Size {
			return fail("E_BACKUP", "Current stack rollback evidence failed checksum verification.")
		}
		return nil
	}
	if _, e = os.Lstat(filepath.Join(dir, "rollback-current.json")); e == nil {
		if e = load(); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e = a.checkpoint("stack-before-rollback-backup"); e != nil {
		return e
	}
	protected, e := a.backup("stack-profile", p.Protected)
	if e != nil {
		return e
	}
	if current.Exists {
		path, _, e := a.stackPath(p.Resource, p.Locator)
		if e != nil {
			return e
		}
		body, e := bounded(path, stackLimit)
		if e != nil || hash(body) != current.SHA256 || int64(len(body)) != current.Size {
			return fail("E_STALE", "Current stack resource changed during rollback backup.")
		}
		if e = atomicWrite(filepath.Join(dir, "rollback-current.bin"), body, Metadata{Mode: 0600, UID: ownerID(), GID: ownerID()}); e != nil {
			return e
		}
	}
	r := stackBackup{Schema: 1, ID: p.ID, Resource: p.Resource, Locator: p.Locator, Time: a.time(), Before: current, Parent: p.Parent, ProtectedBackup: protected.ID, Protected: p.Protected}
	if e = writeJSON(filepath.Join(dir, "rollback-current.json"), r); e != nil {
		return e
	}
	if e = syncDir(dir); e != nil {
		return e
	}
	if e = load(); e != nil {
		return e
	}
	if e = a.stackCheckResource(p, current); e != nil {
		return e
	}
	if e = a.checkpoint("stack-after-rollback-backup"); e != nil {
		return e
	}
	return load()
}
func (a *App) stackRestore(p StackPlan, j *stackJournal, explicit bool) error {
	b, e := a.stackLoadBackup(p.ID)
	if e != nil {
		return e
	}
	if b.Resource != p.Resource || b.Locator != p.Locator || b.Before != p.Before || b.Parent != p.Parent || !equal(b.Protected, p.Protected) {
		return fail("E_BACKUP", "Stack backup binding does not match the reviewed resource.")
	}
	current, _, parent, _, e := a.stackRead(p.Resource, p.Locator)
	if e != nil {
		return e
	}
	if parent != p.Parent {
		return fail("E_RECOVERY", "Stack parent metadata changed. No conflicting resource was overwritten.")
	}
	if current != p.Before && current != p.After {
		if e = a.stackConflict(p, current); e != nil {
			return e
		}
		return fail("E_RECOVERY", "An external stack writer conflict was preserved privately. Automatic restoration stopped.")
	}
	j.State = "restoring"
	if e = writeJSON(filepath.Join(a.Root, "stack-journal.json"), j); e != nil {
		return e
	}
	if e = a.checkpoint("stack-before-restore"); e != nil {
		return e
	}
	// Explicit rollback must still match the operator's reviewed context. Failed
	// Apply compensation instead restores only its own resource, even if another
	// context resource changed and triggered the failed Apply.
	if explicit {
		if e = a.stackCheckBase(p, true); e != nil {
			return e
		}
	}
	if e = a.stackCheckResource(p, current); e != nil {
		return e
	}
	if current != p.Before {
		if explicit {
			if e = a.stackRollbackCurrent(p, current); e != nil {
				return e
			}
			if e = a.stackCheckBase(p, true); e != nil {
				return e
			}
			if e = a.stackCheckResource(p, current); e != nil {
				return e
			}
		}
		body := []byte{}
		if p.Before.Exists {
			dir, _ := a.stackObject("backups", p.ID)
			body, e = bounded(filepath.Join(dir, "resource.bin"), stackLimit)
			if e != nil || hash(body) != p.Before.SHA256 {
				return fail("E_BACKUP", "Stack backup changed before restoration.")
			}
		}
		if e = a.stackWrite(p.Resource, p.Locator, p.Before, body); e != nil {
			return e
		}
	}
	if e = a.checkpoint("stack-after-restore"); e != nil {
		return e
	}
	if e = a.stackCheckResource(p, p.Before); e != nil {
		return e
	}
	if _, e = a.stackLoadBackup(p.ID); e != nil {
		return e
	}
	j.State = "restored"
	return writeJSON(filepath.Join(a.Root, "stack-journal.json"), j)
}
func (a *App) stackRollback(id string) (any, error) {
	if e := a.stackForeignRecovered(); e != nil {
		return nil, e
	}
	p, _, e := a.stackLoadPlan(id)
	if e != nil {
		return nil, e
	}
	var j stackJournal
	if e = stackReadJSON(filepath.Join(a.Root, "stack-journal.json"), &j); e != nil || a.validateStackJournal(j) != nil || j.ID != id || j.Resource != p.Resource || j.Locator != p.Locator || j.Before != p.Before || j.After != p.After {
		return nil, fail("E_RECOVERY", "Choose the current valid stack transaction for restoration.")
	}
	if j.State == "restored" {
		if _, e = a.stackLoadBackup(id); e != nil {
			return nil, e
		}
		if e = a.stackCheckResource(p, p.Before); e != nil {
			return nil, e
		}
		return stackResult(j), nil
	}
	if e = a.stackCheckBase(p, true); e != nil {
		return nil, e
	}
	if e = a.stackRestore(p, &j, true); e != nil {
		j.State = "recovery-required"
		_ = writeJSON(filepath.Join(a.Root, "stack-journal.json"), j)
		return nil, fail("E_RECOVERY", "Stack restoration is pending. Preserve the private backup and conflict evidence.")
	}
	return stackResult(j), nil
}
func (a *App) stackVerify(id string) (any, error) {
	p, _, e := a.stackLoadPlan(id)
	if e != nil {
		return nil, e
	}
	var j stackJournal
	if e = stackReadJSON(filepath.Join(a.Root, "stack-journal.json"), &j); e != nil || a.validateStackJournal(j) != nil || j.ID != id || j.Resource != p.Resource || j.Locator != p.Locator || j.Before != p.Before || j.After != p.After {
		return nil, fail("E_RECOVERY", "A valid recorded stack transaction is required for verification.")
	}
	expected := p.After
	if j.State == "restored" {
		expected = p.Before
	} else if j.State != "committed" {
		return nil, fail("E_RECOVERY", "Stack restoration is pending; file verification cannot establish activation.")
	}
	if e = a.stackCheckBase(p, true); e != nil {
		return nil, e
	}
	if e = a.stackCheckResource(p, expected); e != nil {
		return nil, e
	}
	if _, e = a.stackLoadBackup(id); e != nil {
		return nil, e
	}
	return stackResult(j), nil
}
