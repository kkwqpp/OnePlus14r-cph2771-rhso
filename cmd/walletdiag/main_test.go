package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func encoded(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func TestParseKnownForms(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		command string
		key     string
		value   string
	}{
		{"default help", nil, "help", "", ""},
		{"status json", []string{"status", "--json"}, "status", "", ""},
		{"spaced private inbox", []string{"ingest", "--path", "/data/adb/wallet_diagnostic/inbox/with space.xml"}, "ingest", "path", "/data/adb/wallet_diagnostic/inbox/with space.xml"},
		{"explicit selectors", []string{"plan", "--selections", strings.Repeat("a", 32) + ":0:1:rsa", "--targets", "false"}, "plan", "targets", "false"},
		{"target compaction only", []string{"plan", "--compact-targets", "true"}, "plan", "compact-targets", "true"},
		{"private API source config", []string{"api", "--action", "config", "--path", "/data/adb/wallet_diagnostic/inbox/source.json"}, "api", "path", "/data/adb/wallet_diagnostic/inbox/source.json"},
		{"HMA stack target list", []string{"stack", "--action", "plan", "--profile", "hma-scope", "--targets", "com.google.android.gms,com.android.vending"}, "stack", "targets", "com.google.android.gms,com.android.vending"},
		{"bridge target compaction", []string{"request", encoded(`{"command":"plan","args":{"compact-targets":"false"}}`)}, "plan", "compact-targets", "false"},
		{"user verified readiness", []string{"verify", "--wallet-ready", "true", "--tap-confirmed", "false"}, "verify", "wallet-ready", "true"},
		{"bridge json", []string{"request", encoded(`{"command":"ingest","args":{"path":"/data/adb/wallet_diagnostic/inbox/quote $(not-executed).xml"}}`)}, "ingest", "path", "/data/adb/wallet_diagnostic/inbox/quote $(not-executed).xml"},
		{"empty args", []string{"request", encoded(`{"command":"status","args":{}}`)}, "status", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, e := parse(tt.argv)
			if e != nil {
				t.Fatalf("unexpected parse error: %v", e)
			}
			if r.Command != tt.command {
				t.Fatalf("command = %q", r.Command)
			}
			if tt.key != "" && r.Args[tt.key] != tt.value {
				t.Fatalf("argument was changed")
			}
		})
	}
}
func TestParseRejectsUnsafeOrAmbiguousForms(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{"malformed base64", []string{"request", "!"}},
		{"padded base64", []string{"request", "e30="}},
		{"empty encoded request", []string{"request", ""}},
		{"oversized encoded request", []string{"request", strings.Repeat("a", 16385)}},
		{"extra bridge argument", []string{"request", encoded(`{"command":"status","args":{}}`), "extra"}},
		{"unknown top field", []string{"request", encoded(`{"command":"status","args":{},"shell":"id"}`)}},
		{"non-string bridge args", []string{"request", encoded(`{"command":"ingest","args":{"path":42}}`)}},
		{"trailing document", []string{"request", encoded(`{"command":"status","args":{}} {"command":"reset","args":{}}`)}},
		{"missing command", []string{"request", encoded(`{"args":{}}`)}},
		{"unknown command", []string{"shell", "--path", "id"}},
		{"unknown native flag", []string{"status", "--surprise", "x"}},
		{"wrong command native flag", []string{"status", "--path", "/ignored"}},
		{"unknown bridge arg", []string{"request", encoded(`{"command":"status","args":{"surprise":"x"}}`)}},
		{"wrong command bridge arg", []string{"request", encoded(`{"command":"status","args":{"path":"/ignored"}}`)}},
		{"duplicate flag", []string{"ingest", "--path", "one", "--path", "two"}},
		{"missing flag value", []string{"ingest", "--path"}},
		{"positional input", []string{"ingest", "/private/file.xml"}},
		{"ambiguous boolean", []string{"plan", "--targets", "yes"}},
		{"ambiguous compaction boolean", []string{"plan", "--compact-targets", "1"}},
		{"ambiguous stack boolean", []string{"stack", "--enabled", "yes"}},
		{"API token in request", []string{"api", "--action", "config", "--token", "never-accepted"}},
		{"API URL in request", []string{"api", "--url", "https://never-accepted.example/"}},
		{"ambiguous confirmed boolean", []string{"verify", "--tap-confirmed", "1"}},
		{"duplicate json command", []string{"request", encoded(`{"command":"status","command":"reset","args":{}}`)}},
		{"duplicate json args", []string{"request", encoded(`{"command":"ingest","args":{"path":"one","path":"two"}}`)}},
		{"case-folded duplicate json command", []string{"request", encoded(`{"command":"status","Command":"reset","args":{}}`)}},
		{"duplicate reset aliases", []string{"reset", "--review_hash", "one", "--review-hash", "two"}},
		{"nul argument", []string{"ingest", "--path", "bad\x00path"}},
		{"oversized native argument", []string{"ingest", "--path", strings.Repeat("x", 8193)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, e := parse(tt.argv); e == nil {
				t.Fatal("unsafe or ambiguous form accepted")
			}
		})
	}
}
