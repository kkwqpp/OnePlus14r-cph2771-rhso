package keybox

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Every key, certificate, subject and status identifier here is newly generated
// synthetic data. No local input, Google feed or phone material is read.
type publicFixture struct {
	fixture
	rootKey crypto.Signer
	root    *x509.Certificate
	certs   []*x509.Certificate
}

func newPublicFixture(t *testing.T, algorithm string, parameter int, serialBase int64) publicFixture {
	t.Helper()
	rootKey := newSigner(t, "ecdsa", 256)
	rootPEM, root := certificate(t, serialBase, "Synthetic private root subject", rootKey, nil, nil, testNow.Add(48*time.Hour))
	intermediateKey := newSigner(t, "ecdsa", 256)
	intermediatePEM, intermediate := certificate(t, serialBase+1, "Synthetic private intermediate subject", intermediateKey, root, rootKey, testNow.Add(36*time.Hour))
	signer := newSigner(t, algorithm, parameter)
	leafPEM, leaf := certificate(t, serialBase+2, "Synthetic private leaf subject", signer, intermediate, intermediateKey, testNow.Add(24*time.Hour))
	privateDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal("synthetic private encoding failed")
	}
	return publicFixture{
		fixture: fixture{algorithm: algorithm, private: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})), certs: []string{leafPEM, intermediatePEM, rootPEM}},
		rootKey: rootKey, root: root, certs: []*x509.Certificate{leaf, intermediate, root},
	}
}

func publicRootsJSON(t *testing.T, roots ...string) []byte {
	t.Helper()
	body, err := json.Marshal(roots)
	if err != nil {
		t.Fatal("synthetic roots encoding failed")
	}
	return body
}

func publicStatusJSON(t *testing.T, entries map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		t.Fatal("synthetic status encoding failed")
	}
	return body
}

func publicErrorCode(t *testing.T, root, status []byte, expected string) {
	t.Helper()
	feed, err := ParsePublicFeeds(root, status)
	if err == nil || feed != nil {
		t.Fatal("public feed with invalid contract was accepted")
	}
	safe, ok := err.(*Error)
	if !ok || safe.Code != expected {
		t.Fatalf("expected safe error %s, got %v", expected, err)
	}
	for _, forbidden := range []string{"private-status-sentinel", "Synthetic private", "BEGIN", "deadbeef"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatal("public feed error exposed input data")
		}
	}
}

func TestPublicFeedExactStatusSchema(t *testing.T) {
	f := newPublicFixture(t, "ecdsa", 256, 0x123456789a1)
	root := publicRootsJSON(t, f.fixture.certs[2])
	valid := map[string]any{"a": map[string]any{"status": "REVOKED", "reason": "KEY_COMPROMISE", "comment": strings.Repeat("界", 140), "expires": "2028-02-29"}, "f": map[string]any{"status": "SUSPENDED"}}
	feed, err := ParsePublicFeeds(root, publicStatusJSON(t, valid))
	if err != nil {
		t.Fatal("documented Unicode comment or optional fields rejected", err)
	}
	if roots, entries := feed.Inventory(); roots != 1 || entries != 2 {
		t.Fatal("public feed inventory lost an entry")
	}
	for _, reason := range []string{"UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"} {
		if _, err := ParsePublicFeeds(root, publicStatusJSON(t, map[string]any{"a": map[string]any{"status": "REVOKED", "reason": reason}})); err != nil {
			t.Fatal("documented reason rejected", err)
		}
	}
	// Schema serials have no artificial length limit. The bounded document
	// already constrains resource use; a valid longer hex key stays valid.
	t.Run("schema_valid_long_serial", func(t *testing.T) {
		if _, err := ParsePublicFeeds(root, publicStatusJSON(t, map[string]any{strings.Repeat("a", 81): map[string]any{"status": "REVOKED"}})); err != nil {
			t.Fatal("schema-valid long serial was rejected", err)
		}
	})
	cases := []struct {
		name string
		body string
	}{
		{"missing_entries", `{}`},
		{"null_entries", `{"entries":null}`},
		{"array_entries", `{"entries":[]}`},
		{"unknown_top", `{"entries":{},"private-status-sentinel":true}`},
		{"case_changed_top", `{"ENTRIES":{}}`},
		{"case_changed_status", `{"entries":{"a":{"Status":"REVOKED"}}}`},
		{"case_changed_reason", `{"entries":{"a":{"status":"REVOKED","Reason":"UNSPECIFIED"}}}`},
		{"case_changed_comment", `{"entries":{"a":{"status":"REVOKED","Comment":""}}}`},
		{"case_changed_expiry", `{"entries":{"a":{"status":"REVOKED","Expires":"2028-02-29"}}}`},
		{"zero_serial", `{"entries":{"0":{"status":"REVOKED"}}}`},
		{"padded_serial", `{"entries":{"00a":{"status":"REVOKED"}}}`},
		{"uppercase_serial", `{"entries":{"A":{"status":"REVOKED"}}}`},
		{"negative_serial", `{"entries":{"-a":{"status":"REVOKED"}}}`},
		{"empty_serial", `{"entries":{"":{"status":"REVOKED"}}}`},
		{"wrong_serial_chars", `{"entries":{"g":{"status":"REVOKED"}}}`},
		{"missing_status", `{"entries":{"a":{}}}`},
		{"null_entry", `{"entries":{"a":null}}`},
		{"wrong_entry_type", `{"entries":{"a":[]}}`},
		{"null_status", `{"entries":{"a":{"status":null}}}`},
		{"unknown_status", `{"entries":{"a":{"status":"VALID"}}}`},
		{"lowercase_status", `{"entries":{"a":{"status":"revoked"}}}`},
		{"unknown_reason", `{"entries":{"a":{"status":"REVOKED","reason":"private-status-sentinel"}}}`},
		{"empty_reason", `{"entries":{"a":{"status":"REVOKED","reason":""}}}`},
		{"null_reason", `{"entries":{"a":{"status":"REVOKED","reason":null}}}`},
		{"null_comment", `{"entries":{"a":{"status":"REVOKED","comment":null}}}`},
		{"null_expiry", `{"entries":{"a":{"status":"REVOKED","expires":null}}}`},
		{"empty_expiry", `{"entries":{"a":{"status":"REVOKED","expires":""}}}`},
		{"bad_date", `{"entries":{"a":{"status":"REVOKED","expires":"2026-02-29"}}}`},
		{"timestamp_not_date", `{"entries":{"a":{"status":"REVOKED","expires":"2028-02-29T00:00:00Z"}}}`},
		{"unknown_entry_field", `{"entries":{"deadbeef":{"status":"REVOKED","private-status-sentinel":true}}}`},
		{"long_ascii_comment", fmt.Sprintf(`{"entries":{"a":{"status":"REVOKED","comment":%q}}}`, strings.Repeat("x", 141))},
		{"long_unicode_comment", fmt.Sprintf(`{"entries":{"a":{"status":"REVOKED","comment":%q}}}`, strings.Repeat("界", 141))},
		{"wrong_comment_type", `{"entries":{"a":{"status":"REVOKED","comment":123}}}`},
		{"trailing_document", `{"entries":{}} {"entries":{}}`},
		{"trailing_text", `{"entries":{}}private-status-sentinel`},
		{"truncated", `{"entries":{"a":{"status":"REVOKED"}}`},
		{"invalid_utf8", "{\"entries\":{\"a\":{\"status\":\"REVOKED\",\"comment\":\"\xff\"}}}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { publicErrorCode(t, root, []byte(tc.body), "E_PUBLIC_SCHEMA") })
	}
}

func TestPublicFeedDuplicateJSONAndBounds(t *testing.T) {
	f := newPublicFixture(t, "ecdsa", 256, 0x223456789a1)
	root := publicRootsJSON(t, f.fixture.certs[2])
	empty := []byte(`{"entries":{}}`)
	for name, body := range map[string]string{
		"duplicate_top":      `{"entries":{},"entries":{}}`,
		"escaped_duplicate":  `{"entries":{},"\u0065ntries":{}}`,
		"duplicate_serial":   `{"entries":{"a":{"status":"REVOKED"},"a":{"status":"SUSPENDED"}}}`,
		"escaped_serial":     `{"entries":{"a":{"status":"REVOKED"},"\u0061":{"status":"SUSPENDED"}}}`,
		"duplicate_status":   `{"entries":{"a":{"status":"REVOKED","status":"SUSPENDED"}}}`,
		"duplicate_optional": `{"entries":{"a":{"status":"REVOKED","comment":"private-status-sentinel","comment":""}}}`,
		"case_alias_top":     `{"entries":{},"Entries":{}}`,
		"case_alias_status":  `{"entries":{"a":{"status":"REVOKED","Status":"SUSPENDED"}}}`,
		"too_deep":           strings.Repeat("[", 10) + "0" + strings.Repeat("]", 10),
	} {
		t.Run(name, func(t *testing.T) { publicErrorCode(t, root, []byte(body), "E_PUBLIC_SCHEMA") })
	}
	publicErrorCode(t, nil, empty, "E_PUBLIC_LIMIT")
	publicErrorCode(t, root, nil, "E_PUBLIC_LIMIT")
	publicErrorCode(t, bytes.Repeat([]byte(" "), MaxPublicRoots+1), empty, "E_PUBLIC_LIMIT")
	publicErrorCode(t, root, bytes.Repeat([]byte(" "), MaxPublicStatus+1), "E_PUBLIC_LIMIT")
	// Valid trailing whitespace reaches the byte boundary without changing the
	// schema. This catches off-by-one rejection without allocating secrets.
	rootBoundary := append(append([]byte(nil), root...), bytes.Repeat([]byte(" "), MaxPublicRoots-len(root))...)
	statusBoundary := append(append([]byte(nil), empty...), bytes.Repeat([]byte(" "), MaxPublicStatus-len(empty))...)
	if _, err := ParsePublicFeeds(rootBoundary, statusBoundary); err != nil {
		t.Fatal("exact byte bound rejected", err)
	}
	entries := make(map[string]any, 50001)
	for i := 1; i <= 50001; i++ {
		entries[fmt.Sprintf("%x", i)] = map[string]any{"status": "REVOKED"}
	}
	publicErrorCode(t, root, publicStatusJSON(t, entries), "E_PUBLIC_SCHEMA")
	var nilFeed *PublicFeeds
	if roots, entries := nilFeed.Inventory(); roots != 0 || entries != 0 {
		t.Fatal("nil inventory is not empty")
	}
}

func TestPublicRootCatalogRejectsMalformedPEM(t *testing.T) {
	f := newPublicFixture(t, "ecdsa", 256, 0x323456789a1)
	root := f.fixture.certs[2]
	empty := []byte(`{"entries":{}}`)
	block, _ := pem.Decode([]byte(root))
	badSignature := append([]byte(nil), block.Bytes...)
	badSignature[len(badSignature)-1] ^= 1
	badRoot := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: badSignature}))
	withHeaders := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes, Headers: map[string]string{"private-status-sentinel": "value"}}))
	cases := map[string][]byte{
		"null": []byte("null"), "empty_array": []byte("[]"), "object": []byte(`{"roots":[]}`), "number": []byte("1"),
		"null_element": []byte("[null]"), "not_pem": publicRootsJSON(t, "private-status-sentinel"),
		"private_type": publicRootsJSON(t, f.private), "invalid_der": publicRootsJSON(t, "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"),
		"prefix_junk": publicRootsJSON(t, "private-status-sentinel\n"+root), "suffix_junk": publicRootsJSON(t, root+"private-status-sentinel"),
		"extra_block": publicRootsJSON(t, root+root), "headers": publicRootsJSON(t, withHeaders), "signature": publicRootsJSON(t, badRoot),
		"duplicate_key": publicRootsJSON(t, root, root), "trailing_document": append(publicRootsJSON(t, root), []byte("[]")...),
		"root_count_limit": publicRootsJSON(t, root, root, root, root, root, root, root, root, root),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) { publicErrorCode(t, body, empty, "E_PUBLIC_SCHEMA") })
	}
	// Catalog verification intentionally does not borrow private-import date,
	// CA or key-usage policy. A catalog root is independently authenticated by
	// the caller, and these parser checks do not manufacture hardware proof.
	template := &x509.Certificate{SerialNumber: big.NewInt(0x323456789ff), Subject: pkix.Name{CommonName: "Synthetic expired catalog root"}, NotBefore: testNow.Add(-72 * time.Hour), NotAfter: testNow.Add(-48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.rootKey.Public(), f.rootKey)
	if err != nil {
		t.Fatal("synthetic expired root generation failed")
	}
	if _, err := ParsePublicFeeds(publicRootsJSON(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), empty); err != nil {
		t.Fatal("catalog parser applied private-input date or CA policy", err)
	}
}

func TestPublicCheckRecognizesReissuedRootBySPKI(t *testing.T) {
	f := newPublicFixture(t, "ecdsa", 256, 0x423456789a1)
	doc, err := Parse(documentXML([]fixture{f.fixture}), testNow)
	if err != nil {
		t.Fatal("synthetic document rejected", err)
	}
	reissued, cert := certificate(t, 0x423456789ff, f.root.Subject.CommonName, f.rootKey, nil, nil, testNow.Add(72*time.Hour))
	if bytes.Equal(f.root.Raw, cert.Raw) || !bytes.Equal(f.root.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		t.Fatal("fixture does not exercise DER-different same-key root reissue")
	}
	feed, err := ParsePublicFeeds(publicRootsJSON(t, reissued), []byte(`{"entries":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	checks, err := doc.CheckPublic(feed)
	if err != nil || len(checks) != 1 || !checks[0].GoogleRootKey || checks[0].Revocation != "not-listed-as-of-feed" || checks[0].ListedCertificateCount != 0 {
		t.Fatal("same-key reissued anchor recognition failed")
	}
	s := doc.Summary().(RedactedSummary)
	if s.Trust != "unknown" || s.Revocation != "unknown" || s.EngineAdoption != "not_assessed" || s.WalletAcceptance != "not_assessed" {
		t.Fatal("public check manufactured full attestation or Wallet proof")
	}
}

func TestPublicCheckEveryCertificateAndRevokedPrecedence(t *testing.T) {
	f := newPublicFixture(t, "ecdsa", 256, 0x523456789a1)
	doc, err := Parse(documentXML([]fixture{f.fixture}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	rootJSON := publicRootsJSON(t, f.fixture.certs[2])
	// Expired entry metadata must not delete a listed result: it is a source
	// list-maintenance hint, rather than the cache freshness deadline.
	for index, cert := range f.certs {
		for _, status := range []string{"REVOKED", "SUSPENDED"} {
			t.Run(fmt.Sprintf("certificate_%d_%s", index, status), func(t *testing.T) {
				feed, err := ParsePublicFeeds(rootJSON, publicStatusJSON(t, map[string]any{cert.SerialNumber.Text(16): map[string]any{"status": status, "expires": "2020-01-01", "comment": "private-status-sentinel"}}))
				if err != nil {
					t.Fatal(err)
				}
				checks, err := doc.CheckPublic(feed)
				want := "listed-revoked"
				if status == "SUSPENDED" {
					want = "listed-suspended"
				}
				if err != nil || len(checks) != 1 || !checks[0].GoogleRootKey || checks[0].ListedCertificateCount != 1 || checks[0].Revocation != want {
					t.Fatal("listed certificate result was lost or misclassified")
				}
				assertPublicRedaction(t, checks, f)
			})
		}
	}
	for revokedIndex := range f.certs {
		entries := map[string]any{}
		for i, cert := range f.certs {
			status := "SUSPENDED"
			if i == revokedIndex {
				status = "REVOKED"
			}
			entries[cert.SerialNumber.Text(16)] = map[string]any{"status": status}
		}
		feed, err := ParsePublicFeeds(rootJSON, publicStatusJSON(t, entries))
		if err != nil {
			t.Fatal(err)
		}
		checks, err := doc.CheckPublic(feed)
		if err != nil || checks[0].Revocation != "listed-revoked" || checks[0].ListedCertificateCount != 3 {
			t.Fatal("REVOKED did not take precedence independently of certificate order")
		}
		assertPublicRedaction(t, checks, f)
	}
}

func TestPublicCheckIndexesUnknownRootAndSafeErrors(t *testing.T) {
	a := newPublicFixture(t, "ecdsa", 256, 0x623456789a1)
	b := newPublicFixture(t, "rsa", 2048, 0x723456789a1)
	c := newPublicFixture(t, "ecdsa", 384, 0x823456789a1)
	doc, err := Parse(documentXML([]fixture{a.fixture, b.fixture}, []fixture{c.fixture}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := ParsePublicFeeds(publicRootsJSON(t, a.fixture.certs[2], c.fixture.certs[2]), []byte(`{"entries":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	checks, err := doc.CheckPublic(feed)
	if err != nil || len(checks) != 3 {
		t.Fatal("public result lost a key")
	}
	for i, want := range []struct {
		box, key  int
		algorithm string
		known     bool
	}{{0, 0, "ecdsa", true}, {0, 1, "rsa", false}, {1, 0, "ecdsa", true}} {
		got := checks[i]
		revocation := "unknown"
		if want.known {
			revocation = "not-listed-as-of-feed"
		}
		if got.KeyboxIndex != want.box || got.KeyIndex != want.key || got.Algorithm != want.algorithm || got.GoogleRootKey != want.known || got.Revocation != revocation || got.ListedCertificateCount != 0 {
			t.Fatal("public result confused selection index, root recognition or list absence")
		}
	}
	assertPublicRedaction(t, checks, a, b, c)
	// These invalid internal values simulate damaged acquisition/caller state;
	// no parse/library error or input text should cross the public boundary.
	for _, broken := range []*Document{nil, {boxes: []box{{keys: []key{{algorithm: "ecdsa", certificatePEMs: []string{"private-status-sentinel"}}}}}}} {
		out, err := broken.CheckPublic(feed)
		if err == nil || out != nil || err.Error() != "keybox validation failed (E_PUBLIC_SCHEMA)" {
			t.Fatal("damaged document did not fail with a fixed safe error")
		}
	}
	for _, missing := range []*PublicFeeds{nil, {}} {
		out, err := doc.CheckPublic(missing)
		if err == nil || out != nil || err.Error() != "keybox validation failed (E_PUBLIC_SCHEMA)" {
			t.Fatal("missing public evidence did not fail safely")
		}
	}
}

func TestPublicCheckUnknownRootSerialCollisionsRemainUnknown(t *testing.T) {
	// Serial numbers are scoped to issuers. Independent issuers deliberately
	// reuse every synthetic serial; the Google-context catalog must apply only
	// to its recognized root, not a software or unrelated certificate chain.
	known := newPublicFixture(t, "ecdsa", 256, 0x923456789a1)
	unknown := newPublicFixture(t, "ecdsa", 256, 0x923456789a1)
	if bytes.Equal(known.root.RawSubjectPublicKeyInfo, unknown.root.RawSubjectPublicKeyInfo) {
		t.Fatal("independent root fixture unexpectedly reused a signing key")
	}
	doc, err := Parse(documentXML([]fixture{known.fixture}, []fixture{unknown.fixture}), testNow)
	if err != nil {
		t.Fatal("independent chain fixture rejected", err)
	}
	for _, status := range []string{"REVOKED", "SUSPENDED"} {
		t.Run(status, func(t *testing.T) {
			entries := map[string]any{}
			for _, cert := range known.certs {
				entries[cert.SerialNumber.Text(16)] = map[string]any{"status": status}
			}
			feed, err := ParsePublicFeeds(publicRootsJSON(t, known.fixture.certs[2]), publicStatusJSON(t, entries))
			if err != nil {
				t.Fatal("valid collision catalog rejected", err)
			}
			checks, err := doc.CheckPublic(feed)
			if err != nil || len(checks) != 2 {
				t.Fatal("collision check failed or lost explicit input indexes")
			}
			listed := "listed-revoked"
			if status == "SUSPENDED" {
				listed = "listed-suspended"
			}
			if !checks[0].GoogleRootKey || checks[0].Revocation != listed || checks[0].ListedCertificateCount != 3 || checks[0].KeyboxIndex != 0 {
				t.Fatal("recognized issuer context lost its actual listed result")
			}
			if checks[1].GoogleRootKey || checks[1].Revocation != "unknown" || checks[1].ListedCertificateCount != 0 || checks[1].KeyboxIndex != 1 {
				t.Fatal("unknown issuer serial collision manufactured a Google revocation verdict")
			}
			assertPublicRedaction(t, checks, known, unknown)
		})
	}
}

func assertPublicRedaction(t *testing.T, checks []PublicKeyCheck, fixtures ...publicFixture) {
	t.Helper()
	body, err := json.Marshal(checks)
	if err != nil {
		t.Fatal("public result encoding failed")
	}
	text := string(body)
	for _, forbidden := range []string{"BEGIN", "PRIVATE KEY", "CERTIFICATE", "Synthetic private", "owner-secret-device-id", "private-status-sentinel", "hardware_valid", "wallet_passed"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("public result exposed private data or acceptance proof")
		}
	}
	for _, f := range fixtures {
		for _, cert := range f.certs {
			if strings.Contains(text, cert.SerialNumber.Text(16)) || strings.Contains(text, cert.SerialNumber.String()) || strings.Contains(text, cert.Subject.CommonName) {
				t.Fatal("public result exposed a certificate identity")
			}
		}
	}
}
