package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const Version = "0.2.0"

var files = []string{"keybox.xml", "security_patch.txt", "target.txt"}
var validID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var validHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var validContext = regexp.MustCompile("^u:object_r:[a-zA-Z0-9_]+:s0(:c[0-9]+(,c[0-9]+)*)?\x00?$")

type Error struct{ Code, Message string }

func (e *Error) Error() string        { return e.Message }
func fail(code, message string) error { return &Error{code, message} }

type Result struct {
	Schema  int    `json:"schema"`
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Time    string `json:"time"`
	Data    any    `json:"data,omitempty"`
}

func Response(data any, err error) Result {
	r := Result{Schema: 1, OK: err == nil, Code: "OK", Message: "Completed", Time: time.Now().UTC().Format(time.RFC3339), Data: data}
	if err != nil {
		r.Code = "E_IO"
		r.Message = "Operation failed. Check private storage permissions and available space."
		var e *Error
		if errors.As(err, &e) {
			r.Code = e.Code
			r.Message = e.Message
		}
	}
	return r
}

type App struct {
	Root, Active, Modules, SharedInbox string
	Fake                               bool
	Now                                func() time.Time
	Fault                              func(string) error // Test-only fault hook; never controllable by CLI/environment.
	Adoption                           func() (map[string]any, error)
}

func New(root, active, modules string, fake bool) *App {
	return &App{Root: root, Active: active, Modules: modules, SharedInbox: "/sdcard/keybox_inbox", Fake: fake, Now: time.Now}
}
func (a *App) checkpoint(name string) error {
	if a.Fault != nil {
		return a.Fault(name)
	}
	return nil
}
func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func newID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (a *App) time() string { return a.Now().UTC().Format(time.RFC3339) }
func noLinks(path string) error {
	p := filepath.Clean(path)
	for {
		s, e := os.Lstat(p)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if e == nil && s.Mode()&os.ModeSymlink != 0 {
			return fail("E_PATH", "Symbolic links are not accepted for private or active files.")
		}
		next := filepath.Dir(p)
		if next == p {
			break
		}
		p = next
	}
	return nil
}
func bounded(path string, max int64) ([]byte, error) {
	if e := noLinks(path); e != nil {
		return nil, e
	}
	s, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() > max {
		return nil, fail("E_INPUT", "Expected a regular file within the size limit.")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max || int64(len(b)) != s.Size() {
		return nil, fail("E_INPUT", "Input changed while being read; stage it again.")
	}
	return b, nil
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, append(b, '\n'), Metadata{Mode: 0600, UID: ownerID(), GID: ownerID()})
}
func readJSON(path string, v any) error {
	b, e := bounded(path, 4<<20)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return directorySync(f)
}
func atomicWrite(path string, b []byte, m Metadata) error {
	if e := noLinks(path); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".walletdiag-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = setMetadata(tmp, m); e != nil {
		f.Close()
		return e
	}
	// Persist ownership, permissions and xattrs as well as bytes before rename.
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func (a *App) Init() error {
	if !a.Fake && os.Geteuid() != 0 {
		return fail("E_ROOT", "Run this backend through KernelSU as root.")
	}
	for _, p := range []string{a.Root, filepath.Join(a.Root, "inbox"), filepath.Join(a.Root, "staged"), filepath.Join(a.Root, "plans"), filepath.Join(a.Root, "backups")} {
		if e := noLinks(p); e != nil {
			return e
		}
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
		if e := os.Chmod(p, 0700); e != nil {
			return e
		}
		if !a.Fake {
			if e := os.Chown(p, 0, 0); e != nil {
				return e
			}
		}
		metadata, e := getMetadata(p)
		if e != nil || metadata.Mode != 0700 || (!a.Fake && (metadata.UID != 0 || metadata.GID != 0)) {
			return fail("E_IO", "Private storage ownership or permissions could not be verified.")
		}
	}
	formatPath := filepath.Join(a.Root, "format.json")
	var format struct {
		Schema int    `json:"schema"`
		Kind   string `json:"kind"`
	}
	e := readJSON(formatPath, &format)
	if os.IsNotExist(e) {
		entries, err := os.ReadDir(a.Root)
		if err != nil {
			return err
		}
		freshDirs := map[string]bool{"inbox": true, "staged": true, "plans": true, "backups": true}
		for _, entry := range entries {
			if !entry.IsDir() || !freshDirs[entry.Name()] {
				return fail("E_FORMAT", "Unmarked private data requires explicit migration review; no automatic format stamp was written.")
			}
			children, err := os.ReadDir(filepath.Join(a.Root, entry.Name()))
			if err != nil || len(children) != 0 {
				return fail("E_FORMAT", "Unmarked private data requires explicit migration review; no automatic format stamp was written.")
			}
		}
		format.Schema, format.Kind = 1, "wallet-diagnostic-private-store"
		return writeJSON(formatPath, format)
	}
	if e != nil || format.Schema != 1 || format.Kind != "wallet-diagnostic-private-store" {
		return fail("E_FORMAT", "Private storage has an unsupported or corrupt format. Preserve it; automatic migration is unavailable.")
	}
	return nil
}
func (a *App) object(kind, id string) (string, error) {
	if !validID.MatchString(id) {
		return "", fail("E_ID", "Choose a valid inventory, plan or backup ID.")
	}
	p := filepath.Join(a.Root, kind, id)
	return p, noLinks(p)
}

type Metadata struct {
	Mode    uint32 `json:"mode"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	SELinux string `json:"selinux,omitempty"`
}
type FileState struct {
	Exists   bool     `json:"exists"`
	SHA256   string   `json:"sha256,omitempty"`
	Size     int64    `json:"size"`
	Metadata Metadata `json:"metadata"`
}

func (a *App) validState(st FileState) bool {
	if !st.Exists {
		return st == FileState{}
	}
	if !validHash.MatchString(st.SHA256) || st.Size < 0 || st.Size > 1<<20 || st.Metadata.Mode > 0777 {
		return false
	}
	if !a.Fake && (st.Metadata.UID < 0 || st.Metadata.GID < 0) {
		return false
	}
	if st.Metadata.UID > 1<<30 || st.Metadata.GID > 1<<30 || len(st.Metadata.SELinux) > 256 {
		return false
	}
	return st.Metadata.SELinux == "" || validContext.MatchString(st.Metadata.SELinux)
}

func (a *App) snapshot() (map[string]FileState, error) {
	r := map[string]FileState{}
	if e := noLinks(a.Active); e != nil {
		return nil, e
	}
	for _, name := range files {
		p := filepath.Join(a.Active, name)
		if e := noLinks(p); e != nil {
			return nil, e
		}
		s, e := os.Stat(p)
		if os.IsNotExist(e) {
			r[name] = FileState{}
			continue
		}
		if e != nil {
			return nil, e
		}
		b, e := bounded(p, 1<<20)
		if e != nil {
			return nil, e
		}
		m, e := getMetadata(p)
		if e != nil {
			return nil, e
		}
		r[name] = FileState{true, hash(b), s.Size(), m}
	}
	return r, nil
}
func equal(a, b map[string]FileState) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func (a *App) history(kind, id, state string) error {
	p := filepath.Join(a.Root, "history.json")
	v := []map[string]string{}
	if e := readJSON(p, &v); e != nil && !os.IsNotExist(e) {
		return e
	}
	for _, entry := range v {
		if !validHistory(entry) {
			return fail("E_REPORT", "History has an unsupported record; preserve it for redacted inspection.")
		}
	}
	v = append(v, map[string]string{"time": a.time(), "type": kind, "id": id, "state": state})
	return writeJSON(p, v)
}
func validHistory(v map[string]string) bool {
	if len(v) != 4 || !validID.MatchString(v["id"]) {
		return false
	}
	if _, e := time.Parse(time.RFC3339, v["time"]); e != nil {
		return false
	}
	kinds := map[string]bool{"ingest": true, "plan": true, "apply": true, "rollback": true, "recovery": true, "wallet-reset": true}
	states := map[string]bool{"staged": true, "review": true, "committed-adoption-pending": true, "restored-after-failure": true, "restored": true, "awaiting-manual-reboot": true}
	return kinds[v["type"]] && states[v["state"]]
}
func (a *App) publicHistory() ([]map[string]string, int) {
	var records []map[string]string
	if e := readJSON(filepath.Join(a.Root, "history.json"), &records); e != nil {
		if os.IsNotExist(e) {
			return []map[string]string{}, 0
		}
		return []map[string]string{}, 1
	}
	out := []map[string]string{}
	invalid := 0
	for _, v := range records {
		if !validHistory(v) {
			invalid++
			continue
		}
		out = append(out, map[string]string{"time": v["time"], "type": v["type"], "id": v["id"], "state": v["state"]})
	}
	return out, invalid
}
func ExitCode(code string) int {
	switch code {
	case "OK":
		return 0
	case "E_INPUT", "E_XML", "E_VALIDATION", "E_SELECTION", "E_PATH", "E_ID", "E_REQUEST", "E_API_CONFIG", "E_API_FORMAT", "E_API_SSRF", "E_API_LIMIT":
		return 2
	case "E_BUSY":
		return 3
	case "E_STALE", "E_API_STALE":
		return 4
	case "E_CAPABILITY", "E_ROOT", "E_API_UNAVAILABLE":
		return 5
	case "E_CONFIRM":
		return 6
	case "E_RECOVERY":
		return 7
	default:
		return 1
	}
}
func safeError(e error) error {
	if e == nil {
		return nil
	}
	var x *Error
	if errors.As(e, &x) {
		return x
	}
	return fail("E_VALIDATION", fmt.Sprint("Validation failed; check the input inventory for a redacted explanation."))
}
