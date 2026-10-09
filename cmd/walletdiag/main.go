package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"walletdiagnostic/internal/core"
)

type request struct {
	Command string            `json:"command"`
	Args    map[string]string `json:"args"`
}

const help = `RHSO 0.2.0 — Root Hiding Stack Optimizer and Wallet diagnostics, no daemon
Persistent private state: /data/adb/wallet_diagnostic
Commands (optional --json; all results are redacted):
  help | init | status | diagnose | backups
  ingest --path /data/adb/wallet_diagnostic/inbox/input.xml
  validate --id INPUT_ID
  plan --selections INPUT_ID:0:0:ecdsa,OTHER_ID:0:0:rsa
       [--targets true] [--compact-targets true] [--patch YYYY-MM-DD]
  apply --id PLAN_ID
  verify [--wallet-ready true] [--tap-confirmed true]
         [--reviewed-user NUMERIC_ANDROID_USER] (required for personal declarations)
  trust --action status|refresh (Google public feeds; no key uploads)
  rollback --id previous|last-verified|BACKUP_ID
  api --action status|config|import [--path ROOT_PRIVATE_JSON_FILE]
      (configured HTTPS raw-XML feeds; supplied provider route unverified)
  stack --action status|plan|apply|verify|rollback
        [--profile hma-scope|brezygisk-unmount] [--id PLAN_ID]
        [--targets GOOGLE_PACKAGE_CSV] [--hide-packages PACKAGE_CSV]
        [--enabled true|false] (reviewed settings; manual activation required)
  watch [--days 14] (read-only, no schedule)
  recovery --action status|restore|release-lock
  reset --action preview|status|confirm|resume|complete
        --confirmation 'EXACT PHRASE FROM PREVIEW' --review-hash SHA256
  export (redacted support summary only)
Use the reviewed plan before Apply. No ordinary command clears data or reboots.
No bootloader, partition-writing or other attestation-engine functionality.
`

func parse(args []string) (request, error) {
	r := request{Command: "help", Args: map[string]string{}}
	if len(args) == 0 {
		return r, nil
	}
	r.Command = args[0]
	if r.Command == "request" {
		if len(args) != 2 || len(args[1]) > 16384 {
			return r, fmt.Errorf("bad request")
		}
		b, e := base64.RawURLEncoding.DecodeString(args[1])
		if e != nil {
			return r, e
		}
		if e = uniqueJSON(b); e != nil {
			return r, e
		}
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.DisallowUnknownFields()
		if e = d.Decode(&r); e != nil {
			return r, e
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return r, fmt.Errorf("trailing request")
		}
		if r.Args == nil {
			r.Args = map[string]string{}
		}
		return r, validateRequest(&r)
	}
	for i := 1; i < len(args); i++ {
		if args[i] == "--json" {
			continue
		}
		if !strings.HasPrefix(args[i], "--") || i+1 >= len(args) {
			return r, fmt.Errorf("invalid option")
		}
		k := strings.TrimPrefix(args[i], "--")
		if _, ok := r.Args[k]; ok {
			return r, fmt.Errorf("duplicate option")
		}
		i++
		r.Args[k] = args[i]
	}
	return r, validateRequest(&r)
}
func uniqueJSON(b []byte) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	var value func() error
	value = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				s = strings.ToLower(s)
				if !ok || seen[s] {
					return fmt.Errorf("ambiguous JSON")
				}
				seen[s] = true
				if e = value(); e != nil {
					return e
				}
			}
		} else if delim == '[' {
			for d.More() {
				if e = value(); e != nil {
					return e
				}
			}
		} else {
			return fmt.Errorf("invalid JSON")
		}
		_, e = d.Token()
		return e
	}
	if e := value(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func validateRequest(r *request) error {
	options := map[string][]string{"help": {}, "init": {}, "status": {}, "diagnose": {}, "export": {}, "backups": {}, "ingest": {"path"}, "validate": {"id"}, "plan": {"selections", "targets", "compact-targets", "patch"}, "apply": {"id"}, "verify": {"wallet-ready", "tap-confirmed", "reviewed-user"}, "trust": {"action"}, "rollback": {"id"}, "api": {"action", "path"}, "stack": {"action", "profile", "targets", "hide-packages", "enabled", "id"}, "watch": {"days"}, "recovery": {"action"}, "reset": {"action", "confirmation", "review-hash"}}
	allowed, ok := options[r.Command]
	if !ok {
		return fmt.Errorf("unknown command")
	}
	if v, ok := r.Args["review_hash"]; ok {
		if _, duplicate := r.Args["review-hash"]; duplicate {
			return fmt.Errorf("duplicate alias")
		}
		r.Args["review-hash"] = v
		delete(r.Args, "review_hash")
	}
	for k, v := range r.Args {
		found := false
		for _, x := range allowed {
			if k == x {
				found = true
			}
		}
		if !found || len(v) > 8192 || strings.ContainsRune(v, 0) {
			return fmt.Errorf("invalid argument")
		}
		if ((k == "targets" && r.Command == "plan") || k == "compact-targets" || k == "enabled" || k == "wallet-ready" || k == "tap-confirmed") && v != "true" && v != "false" {
			return fmt.Errorf("invalid boolean")
		}
	}
	return nil
}
func main() {
	// INT/TERM cannot terminate a backend between writes. SIGKILL/power loss remains journal-recoverable.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	r, e := parse(os.Args[1:])
	var data any
	a := core.New("/data/adb/wallet_diagnostic", "/data/adb/tricky_store", "/data/adb/modules", false)
	if e != nil {
		e = &core.Error{Code: "E_REQUEST", Message: "Invalid command request. Run help for exact options."}
	} else {
		switch r.Command {
		case "help":
			data = map[string]string{"help": help}
		case "init":
			e = a.Init()
			data = map[string]string{"state": "private-storage-ready"}
		case "status":
			data, e = a.Status()
		case "diagnose", "export":
			data, e = a.Diagnose()
		case "ingest":
			data, e = a.Ingest(r.Args["path"])
		case "validate":
			data, e = a.Validate(r.Args["id"])
		case "plan":
			data, e = a.Plan(r.Args["selections"], r.Args["targets"] == "true", r.Args["patch"], r.Args["compact-targets"] == "true")
		case "apply":
			data, e = a.Apply(r.Args["id"])
		case "verify":
			data, e = a.Verify(r.Args["wallet-ready"] == "true", r.Args["tap-confirmed"] == "true", r.Args["reviewed-user"])
		case "trust":
			data, e = a.Trust(r.Args["action"])
		case "backups":
			data, e = a.Backups()
		case "rollback":
			data, e = a.Rollback(r.Args["id"])
		case "watch":
			days := 14
			if r.Args["days"] != "" {
				days, e = strconv.Atoi(r.Args["days"])
			}
			if e == nil {
				data, e = a.Watch(days)
			}
		case "recovery":
			data, e = a.Recovery(r.Args["action"])
		case "reset":
			data, e = a.Reset(r.Args["action"], r.Args["confirmation"], r.Args["review-hash"])
		case "api":
			data, e = a.API(r.Args["action"], r.Args["path"])
		case "stack":
			data, e = a.Stack(r.Args["action"], r.Args["profile"], r.Args["targets"], r.Args["hide-packages"], r.Args["enabled"], r.Args["id"])
		default:
			e = &core.Error{Code: "E_REQUEST", Message: "Unknown command. Run help."}
		}
	}
	response := core.Response(data, e)
	asJSON := len(os.Args) > 1 && os.Args[1] == "request"
	for _, arg := range os.Args[1:] {
		if arg == "--json" {
			asJSON = true
		}
	}
	if !asJSON {
		human(response)
		os.Exit(core.ExitCode(response.Code))
	}
	b, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		b = []byte(`{"schema":1,"ok":false,"code":"E_REPORT","message":"Redacted reporting failed"}`)
	}
	fmt.Println(string(b))
	os.Exit(core.ExitCode(response.Code))
}
func human(r core.Result) {
	if d, ok := r.Data.(map[string]string); ok {
		if v := d["help"]; v != "" {
			fmt.Print(v)
			return
		}
	}
	fmt.Println(r.Code + ": " + r.Message)
	if st, ok := r.Data.(core.Stage); ok {
		fmt.Println("Staged input: " + st.ID)
		fmt.Println("Next: validate --id " + st.ID)
		return
	}
	if d, ok := r.Data.(map[string]any); ok {
		if v, ok := d["algorithms"].([]string); ok {
			fmt.Println("Algorithms: " + strings.Join(v, ", "))
		}
		for _, k := range []string{"id", "backup", "state", "adoption", "engine_health", "wallet_acceptance", "wallet_readiness", "tap_to_pay", "evidence_time", "message", "next_step"} {
			if v, ok := d[k].(string); ok {
				fmt.Println(strings.ReplaceAll(k, "_", " ") + ": " + v)
			}
		}
		if f, ok := d["findings"].([]core.Finding); ok {
			for _, v := range f {
				fmt.Println(v.Kind + ": " + v.Title + " — " + v.Evidence)
			}
		}
		if _, ok := d["preview"]; ok {
			fmt.Println("Review exact changes and warnings with --json before applying this plan.")
		}
		fmt.Println("Use --json for the complete redacted result.")
	}
}
