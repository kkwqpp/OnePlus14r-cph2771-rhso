package keybox

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxPublicRoots = 128 << 10
const MaxPublicStatus = 2 << 20

// PublicFeeds contains only Google's public catalog, never local serials or keys.
// The catalog has no documented detached signature; authenticated acquisition
// and freshness are responsibilities of the caller, not this parser.
type PublicFeeds struct {
	roots   []*x509.Certificate
	entries map[string]string
}

type PublicKeyCheck struct {
	KeyboxIndex            int    `json:"keybox_index"`
	KeyIndex               int    `json:"key_index"`
	Algorithm              string `json:"algorithm"`
	GoogleRootKey          bool   `json:"google_root_key"`
	Revocation             string `json:"revocation"`
	ListedCertificateCount int    `json:"listed_certificate_count"`
}

var publicSerial = regexp.MustCompile(`^[a-f1-9][a-f0-9]*$`)

func ParsePublicFeeds(rootBody, statusBody []byte) (*PublicFeeds, error) {
	if len(rootBody) == 0 || len(rootBody) > MaxPublicRoots || len(statusBody) == 0 || len(statusBody) > MaxPublicStatus {
		return nil, fail("E_PUBLIC_LIMIT")
	}
	if e := publicUniqueJSON(rootBody); e != nil {
		return nil, e
	}
	if e := publicUniqueJSON(statusBody); e != nil {
		return nil, e
	}
	var roots []string
	if e := json.Unmarshal(rootBody, &roots); e != nil || len(roots) < 1 || len(roots) > 8 {
		return nil, fail("E_PUBLIC_SCHEMA")
	}
	f := &PublicFeeds{entries: map[string]string{}}
	for _, body := range roots {
		if !strings.HasPrefix(strings.TrimSpace(body), "-----BEGIN CERTIFICATE-----") {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		p, rest := pem.Decode([]byte(body))
		if p == nil || p.Type != "CERTIFICATE" || len(p.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		c, e := x509.ParseCertificate(p.Bytes)
		if e != nil {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		// Check the catalog's own root signature. Do not impose this helper's
		// private-input CA/date profile as a universal Android verifier policy.
		if c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		for _, old := range f.roots {
			if bytes.Equal(old.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) {
				return nil, fail("E_PUBLIC_SCHEMA")
			}
		}
		f.roots = append(f.roots, c)
	}
	var top map[string]json.RawMessage
	var entries map[string]json.RawMessage
	if json.Unmarshal(statusBody, &top) != nil || len(top) != 1 || top["entries"] == nil || json.Unmarshal(top["entries"], &entries) != nil || entries == nil || len(entries) > 50000 {
		return nil, fail("E_PUBLIC_SCHEMA")
	}
	for serial, raw := range entries {
		if !publicSerial.MatchString(serial) {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		values := map[string]string{}
		for name, value := range entry {
			if name != "status" && name != "reason" && name != "comment" && name != "expires" {
				return nil, fail("E_PUBLIC_SCHEMA")
			}
			var text string
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &text) != nil {
				return nil, fail("E_PUBLIC_SCHEMA")
			}
			values[name] = text
		}
		if values["status"] != "REVOKED" && values["status"] != "SUSPENDED" {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		if reason, ok := values["reason"]; ok && reason != "UNSPECIFIED" && reason != "KEY_COMPROMISE" && reason != "CA_COMPROMISE" && reason != "SUPERSEDED" && reason != "SOFTWARE_FLAW" {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		if utf8.RuneCountInString(values["comment"]) > 140 {
			return nil, fail("E_PUBLIC_SCHEMA")
		}
		if date, ok := values["expires"]; ok {
			if _, e := time.Parse("2006-01-02", date); e != nil {
				return nil, fail("E_PUBLIC_SCHEMA")
			}
		}
		f.entries[serial] = values["status"]
	}
	return f, nil
}

func publicUniqueJSON(b []byte) error {
	if !utf8.Valid(b) {
		return fail("E_PUBLIC_SCHEMA")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return fail("E_PUBLIC_SCHEMA")
		}
		tokens++
		if tokens > 400000 {
			return fail("E_PUBLIC_LIMIT")
		}
		t, e := d.Token()
		if e != nil {
			return fail("E_PUBLIC_SCHEMA")
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
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return fail("E_PUBLIC_SCHEMA")
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return fail("E_PUBLIC_SCHEMA")
		}
		_, e = d.Token()
		if e != nil {
			return fail("E_PUBLIC_SCHEMA")
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("E_PUBLIC_SCHEMA")
	}
	return nil
}

// CheckPublic matches serials locally against the complete downloaded list.
// Results expose indexes/flags only. A recognized Google key and an absent
// entry do not establish genuine hardware, fresh attestation or Wallet approval.
func (d *Document) CheckPublic(f *PublicFeeds) ([]PublicKeyCheck, error) {
	if d == nil || f == nil || len(f.roots) == 0 {
		return nil, fail("E_PUBLIC_SCHEMA")
	}
	out := []PublicKeyCheck{}
	for bi, b := range d.boxes {
		for ki, k := range b.keys {
			check := PublicKeyCheck{KeyboxIndex: bi, KeyIndex: ki, Algorithm: k.algorithm, Revocation: "unknown"}
			certs := []*x509.Certificate{}
			for _, body := range k.certificatePEMs {
				p, _ := pem.Decode([]byte(body))
				if p == nil {
					return nil, fail("E_PUBLIC_SCHEMA")
				}
				c, e := x509.ParseCertificate(p.Bytes)
				if e != nil {
					return nil, fail("E_PUBLIC_SCHEMA")
				}
				certs = append(certs, c)
			}
			if len(certs) == 0 {
				return nil, fail("E_PUBLIC_SCHEMA")
			}
			for _, root := range f.roots {
				if bytes.Equal(certs[len(certs)-1].RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) {
					check.GoogleRootKey = true
				}
			}
			// Google's serial list is meaningful only within Google's issuing
			// hierarchy. Software/unrelated roots can reuse the same integers.
			if !check.GoogleRootKey {
				out = append(out, check)
				continue
			}
			check.Revocation = "not-listed-as-of-feed"
			for _, c := range certs {
				if state, ok := f.entries[c.SerialNumber.Text(16)]; ok {
					check.ListedCertificateCount++
					if state == "REVOKED" {
						check.Revocation = "listed-revoked"
					} else if check.Revocation != "listed-revoked" {
						check.Revocation = "listed-suspended"
					}
				}
			}
			out = append(out, check)
		}
	}
	return out, nil
}

func (f *PublicFeeds) Inventory() (int, int) {
	if f == nil {
		return 0, 0
	}
	return len(f.roots), len(f.entries)
}
