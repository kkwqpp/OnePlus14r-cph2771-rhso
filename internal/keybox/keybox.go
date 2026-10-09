// Package keybox validates and explicitly merges local TrickyStore keybox XML.
// It performs no I/O, network requests, active configuration changes, or trust
// establishment. Secret material is deliberately held in unexported fields.
package keybox

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MaxInput        = 1 << 20
	maxBoxes        = 16
	maxKeys         = 8
	maxCertificates = 8
	maxTokens       = 4096
	maxDepth        = 8
	// OutputDeviceID is helper metadata, never a claimed hardware identity.
	OutputDeviceID = "WalletDiagnosticHelper"
)

// Error carries a fixed code and safe message; parser/library errors and input
// values are never incorporated, including certificate subjects and DeviceID.
type Error struct {
	Code string `json:"code"`
}

func (e *Error) Error() string { return "keybox validation failed (" + e.Code + ")" }
func fail(code string) error   { return &Error{Code: code} }

// Selection requires an explicit source, Keybox, key, and declared algorithm.
// Every index is zero-based. No implicit choice is made for duplicate keys.
type Selection struct {
	Source    int    `json:"source"`
	Keybox    int    `json:"keybox"`
	Key       int    `json:"key"`
	Algorithm string `json:"algorithm"`
}

type KeySummary struct {
	Index            int      `json:"index"`
	Algorithm        string   `json:"algorithm"`
	Parameter        string   `json:"parameter"`
	PrivateKeyFormat string   `json:"private_key_format"`
	CertificateCount int      `json:"certificate_count"`
	ValidUntil       string   `json:"valid_until"`
	Warnings         []string `json:"warnings"`
}
type BoxSummary struct {
	Index    int          `json:"index"`
	Keys     []KeySummary `json:"keys"`
	Warnings []string     `json:"warnings"`
}
type RedactedSummary struct {
	StructuralValid              bool         `json:"structural_valid"`
	CryptographicConsistent      bool         `json:"cryptographic_consistent"`
	Trust                        string       `json:"trust"`
	Revocation                   string       `json:"revocation"`
	EngineAdoption               string       `json:"engine_adoption"`
	WalletAcceptance             string       `json:"wallet_acceptance"`
	ValidatedAt                  string       `json:"validated_at"`
	HelperParameterPolicy        string       `json:"helper_parameter_policy"`
	EngineParameterCompatibility string       `json:"engine_parameter_compatibility"`
	Keyboxes                     []BoxSummary `json:"keyboxes"`
	Warnings                     []string     `json:"warnings"`
	DeviceIDPolicy               string       `json:"device_id_policy"`
	MetadataDeviceID             string       `json:"metadata_device_id,omitempty"`
}

type key struct {
	algorithm       string
	privatePEM      string
	certificatePEMs []string
	parameter       string
	privateFormat   string
	validUntil      time.Time
	warnings        []string
}
type box struct {
	deviceID string
	keys     []key
	warnings []string
}
type Document struct {
	boxes       []box
	validatedAt time.Time
	merged      bool
}

// Summary never includes original DeviceIDs, PEM, subjects, serials, or keys.
func (d *Document) Summary() any {
	s := RedactedSummary{StructuralValid: true, CryptographicConsistent: true,
		Trust: "unknown", Revocation: "unknown", EngineAdoption: "not_assessed",
		WalletAcceptance: "not_assessed", HelperParameterPolicy: "RSA 2048–4096; EC P-256/P-384",
		EngineParameterCompatibility: "unverified", Keyboxes: []BoxSummary{},
		Warnings:       []string{"trust_not_established", "revocation_unknown", "engine_compatibility_requires_verification"},
		DeviceIDPolicy: "source_metadata_redacted"}
	if d == nil {
		s.StructuralValid = false
		s.CryptographicConsistent = false
		return s
	}
	s.ValidatedAt = d.validatedAt.UTC().Format(time.RFC3339)
	if d.merged {
		s.DeviceIDPolicy = "fixed_helper_metadata_no_hardware_identity"
		s.MetadataDeviceID = OutputDeviceID
	}
	if len(d.boxes) > 1 {
		s.Warnings = append(s.Warnings, "multiple_keyboxes_explicit_selection_required")
	}
	for i, b := range d.boxes {
		bs := BoxSummary{Index: i, Keys: []KeySummary{}, Warnings: append([]string{}, b.warnings...)}
		for j, k := range b.keys {
			bs.Keys = append(bs.Keys, KeySummary{Index: j, Algorithm: k.algorithm, Parameter: k.parameter, PrivateKeyFormat: k.privateFormat, CertificateCount: len(k.certificatePEMs), ValidUntil: k.validUntil.UTC().Format(time.RFC3339), Warnings: append([]string{}, k.warnings...)})
		}
		s.Keyboxes = append(s.Keyboxes, bs)
	}
	return s
}

// These formatting hooks prevent accidental ordinary logging of Document PEM.
func (d *Document) MarshalJSON() ([]byte, error)  { return json.Marshal(d.Summary()) }
func (d *Document) String() string                { data, _ := d.MarshalJSON(); return string(data) }
func (d *Document) GoString() string              { return d.String() }
func (d *Document) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, d.String()) }

type element struct {
	name     string
	attrs    map[string]string
	children []*element
	text     strings.Builder
}

var xmlDeclaration = regexp.MustCompile(`^version\s*=\s*["']1\.0["'](?:\s+encoding\s*=\s*["'](?:UTF-8|utf-8)["'])?(?:\s+standalone\s*=\s*["'](?:yes|no)["'])?\s*$`)

// parseXML uses encoding/xml in strict mode and permits no entities, DTD,
// directives, namespaces, or processing instructions other than a UTF-8 prolog.
func parseXML(data []byte) (*element, error) {
	if len(data) == 0 || len(data) > MaxInput {
		return nil, fail("E_SIZE")
	}
	if bytes.Contains(data, []byte{'&'}) {
		return nil, fail("E_XML_ENTITY")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	var root *element
	var stack []*element
	tokens := 0
	declaration := false
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fail("E_XML")
		}
		tokens++
		if tokens > maxTokens {
			return nil, fail("E_LIMIT")
		}
		switch t := t.(type) {
		case xml.Directive:
			return nil, fail("E_XML_DIRECTIVE")
		case xml.ProcInst:
			if root != nil || declaration || t.Target != "xml" || !xmlDeclaration.Match(t.Inst) {
				return nil, fail("E_XML_PROCESSING")
			}
			declaration = true
		case xml.Comment:
			if len(t) > 4096 {
				return nil, fail("E_LIMIT")
			}
		case xml.StartElement:
			if t.Name.Space != "" || len(stack) >= maxDepth {
				return nil, fail("E_SCHEMA")
			}
			n := &element{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				if a.Name.Space != "" {
					return nil, fail("E_SCHEMA")
				}
				if _, ok := n.attrs[a.Name.Local]; ok {
					return nil, fail("E_SCHEMA")
				}
				n.attrs[a.Name.Local] = a.Value
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, fail("E_SCHEMA")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fail("E_XML")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(t)) != 0 {
					return nil, fail("E_XML")
				}
			} else {
				_, _ = stack[len(stack)-1].text.Write(t)
			}
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, fail("E_XML")
	}
	return root, nil
}
func shape(e *element, name string, attrs ...string) bool {
	if e == nil || e.name != name || len(e.attrs) != len(attrs) {
		return false
	}
	for _, a := range attrs {
		if _, ok := e.attrs[a]; !ok {
			return false
		}
	}
	return true
}
func container(e *element) bool { return strings.TrimSpace(e.text.String()) == "" }
func count(e *element, name string, max int) (int, error) {
	if !shape(e, name) || len(e.children) != 0 {
		return 0, fail("E_SCHEMA")
	}
	t := strings.TrimSpace(e.text.String())
	if t == "" || len(t) > 3 {
		return 0, fail("E_COUNT")
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return 0, fail("E_COUNT")
		}
	}
	n, err := strconv.Atoi(t)
	if err != nil || n < 1 || n > max {
		return 0, fail("E_COUNT")
	}
	return n, nil
}

// Parse validates all records. Ambiguous valid duplicates are retained for
// review and explicit Merge selection; it does not choose a record or key.
func Parse(data []byte, now time.Time) (*Document, error) {
	if now.IsZero() {
		return nil, fail("E_TIME")
	}
	r, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if !shape(r, "AndroidAttestation") || !container(r) || len(r.children) < 2 {
		return nil, fail("E_SCHEMA")
	}
	n, err := count(r.children[0], "NumberOfKeyboxes", maxBoxes)
	if err != nil {
		return nil, err
	}
	if len(r.children) != n+1 {
		return nil, fail("E_COUNT")
	}
	d := &Document{validatedAt: now.UTC()}
	for _, e := range r.children[1:] {
		if !shape(e, "Keybox", "DeviceID") || !container(e) || len(e.children) < 1 || len(e.children) > maxKeys {
			return nil, fail("E_SCHEMA")
		}
		id := e.attrs["DeviceID"]
		if len(id) == 0 || len(id) > 256 {
			return nil, fail("E_SCHEMA")
		}
		b := box{deviceID: id, warnings: []string{}}
		if placeholder(id) {
			b.warnings = append(b.warnings, "metadata_placeholder_indicator")
		}
		seen := map[string]bool{}
		for _, ke := range e.children {
			if !shape(ke, "Key", "algorithm") || !container(ke) || len(ke.children) != 2 {
				return nil, fail("E_SCHEMA")
			}
			alg := ke.attrs["algorithm"]
			if alg != "rsa" && alg != "ecdsa" {
				return nil, fail("E_ALGORITHM")
			}
			pe, ce := ke.children[0], ke.children[1]
			if !shape(pe, "PrivateKey", "format") || pe.attrs["format"] != "pem" || len(pe.children) != 0 || !shape(ce, "CertificateChain") || !container(ce) || len(ce.children) < 2 {
				return nil, fail("E_SCHEMA")
			}
			cn, err := count(ce.children[0], "NumberOfCertificates", maxCertificates)
			if err != nil {
				return nil, err
			}
			if len(ce.children) != cn+1 {
				return nil, fail("E_COUNT")
			}
			k := key{algorithm: alg, privatePEM: strings.Trim(pe.text.String(), " \t\r\n"), warnings: []string{}}
			for _, c := range ce.children[1:] {
				if !shape(c, "Certificate", "format") || c.attrs["format"] != "pem" || len(c.children) != 0 {
					return nil, fail("E_SCHEMA")
				}
				k.certificatePEMs = append(k.certificatePEMs, strings.Trim(c.text.String(), " \t\r\n"))
			}
			if err = validateKey(&k, now); err != nil {
				return nil, err
			}
			if seen[alg] {
				b.warnings = appendUnique(b.warnings, "duplicate_algorithm_explicit_selection_required")
			}
			seen[alg] = true
			b.keys = append(b.keys, k)
		}
		d.boxes = append(d.boxes, b)
	}
	return d, nil
}

func completePEM(value string, private bool) (*pem.Block, error) {
	code := "E_CERT_PEM"
	if private {
		code = "E_PRIVATE_PEM"
	}
	v := []byte(normalizePEMWhitespace(value))
	if !bytes.HasPrefix(v, []byte("-----BEGIN ")) {
		return nil, fail(code)
	}
	if bytes.Count(v, []byte("-----BEGIN ")) != 1 || bytes.Count(v, []byte("-----END ")) != 1 {
		return nil, fail(code)
	}
	b, rest := pem.Decode(v)
	if b == nil || len(bytes.TrimSpace(rest)) != 0 || len(b.Headers) != 0 {
		return nil, fail(code)
	}
	if !bytes.HasPrefix(v, []byte("-----BEGIN "+b.Type+"-----")) || !bytes.HasSuffix(v, []byte("-----END "+b.Type+"-----")) {
		return nil, fail(code)
	}
	return b, nil
}

// XML may indent the PEM framing and base64 lines. Removing ASCII spaces/tabs
// at line edges cannot repair missing data, invent framing, or alter base64.
// Complete framing, one block, expected type and no extra data remain mandatory.
func normalizePEMWhitespace(value string) string {
	lines := strings.Split(strings.Trim(value, " \t\r\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.Trim(line, " \t")
	}
	return strings.Trim(strings.Join(lines, "\n"), " \t\r\n")
}
func validateKey(k *key, now time.Time) error {
	canonical := normalizePEMWhitespace(k.privatePEM)
	if canonical != k.privatePEM {
		k.warnings = appendUnique(k.warnings, "private_key_pem_whitespace_normalized")
	}
	k.privatePEM = canonical
	p, err := completePEM(k.privatePEM, true)
	if err != nil {
		return err
	}
	var parsed any
	switch p.Type {
	case "EC PRIVATE KEY":
		k.privateFormat = "sec1"
		parsed, err = x509.ParseECPrivateKey(p.Bytes)
	case "RSA PRIVATE KEY":
		k.privateFormat = "pkcs1"
		parsed, err = x509.ParsePKCS1PrivateKey(p.Bytes)
	case "PRIVATE KEY":
		k.privateFormat = "pkcs8"
		k.warnings = appendUnique(k.warnings, "pkcs8_requires_traditional_pem_for_installed_engine")
		parsed, err = x509.ParsePKCS8PrivateKey(p.Bytes)
	default:
		return fail("E_PRIVATE_KEY")
	}
	if err != nil {
		return fail("E_PRIVATE_KEY")
	}
	var signer crypto.Signer
	switch pk := parsed.(type) {
	case *rsa.PrivateKey:
		if k.algorithm != "rsa" {
			return fail("E_ALGORITHM_MISMATCH")
		}
		if pk.N.BitLen() < 2048 || pk.N.BitLen() > 4096 || pk.E < 3 || pk.E%2 == 0 || len(pk.Primes) != 2 {
			return fail("E_PARAMETERS")
		}
		if pk.Validate() != nil {
			return fail("E_PRIVATE_KEY")
		}
		k.parameter = strconv.Itoa(pk.N.BitLen())
		signer = pk
	case *ecdsa.PrivateKey:
		if k.algorithm != "ecdsa" {
			return fail("E_ALGORITHM_MISMATCH")
		}
		if pk.Curve.Params().Name != "P-256" && pk.Curve.Params().Name != "P-384" {
			return fail("E_PARAMETERS")
		}
		k.parameter = pk.Curve.Params().Name
		signer = pk
	default:
		return fail("E_PARAMETERS")
	}
	var certs []*x509.Certificate
	for i, value := range k.certificatePEMs {
		canonical := normalizePEMWhitespace(value)
		if canonical != value {
			k.warnings = appendUnique(k.warnings, "certificate_pem_whitespace_normalized")
		}
		k.certificatePEMs[i] = canonical
		b, err := completePEM(value, false)
		if err != nil {
			return err
		}
		if b.Type != "CERTIFICATE" {
			return fail("E_CERT_PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return fail("E_CERTIFICATE")
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return fail("E_CERT_TIME")
		}
		if len(c.UnhandledCriticalExtensions) != 0 {
			return fail("E_CERT_CRITICAL")
		}
		if k.validUntil.IsZero() || c.NotAfter.Before(k.validUntil) {
			k.validUntil = c.NotAfter
		}
		if placeholder(c.Subject.CommonName) || placeholder(c.Issuer.CommonName) {
			k.warnings = appendUnique(k.warnings, "certificate_placeholder_indicator")
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return fail("E_COUNT")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fail("E_PRIVATE_KEY")
	}
	if !bytes.Equal(public, certs[0].RawSubjectPublicKeyInfo) {
		return fail("E_KEY_MISMATCH")
	}
	seen := map[string]bool{}
	for i, c := range certs {
		identity := string(c.Raw)
		if seen[identity] {
			return fail("E_CHAIN_DUPLICATE")
		}
		seen[identity] = true
		if i+1 < len(certs) {
			if !bytes.Equal(c.RawIssuer, certs[i+1].RawSubject) {
				return fail("E_CHAIN_ORDER")
			}
			if c.CheckSignatureFrom(certs[i+1]) != nil {
				return fail("E_CHAIN_SIGNATURE")
			}
			if certs[i+1].MaxPathLenZero && i > 0 {
				return fail("E_CHAIN_CONSTRAINT")
			}
			if certs[i+1].MaxPathLen >= 0 && certs[i+1].BasicConstraintsValid && i > certs[i+1].MaxPathLen {
				return fail("E_CHAIN_CONSTRAINT")
			}
		}
	}
	last := certs[len(certs)-1]
	if !bytes.Equal(last.RawSubject, last.RawIssuer) {
		return fail("E_CHAIN_INCOMPLETE")
	}
	if last.CheckSignatureFrom(last) != nil {
		return fail("E_CHAIN_SIGNATURE")
	}
	if len(certs) == 1 {
		k.warnings = appendUnique(k.warnings, "single_self_signed_certificate_placeholder_possible")
	}
	k.warnings = appendUnique(k.warnings, "self_signed_anchor_does_not_establish_trust")
	return nil
}
func placeholder(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, p := range []string{"placeholder", "default", "software", "test", "dummy", "example"} {
		if strings.Contains(v, p) {
			return true
		}
	}
	return false
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}

// The inspected installed TrickyStore parser requires a PEMKeyPair: traditional
// EC SEC1/RSA PKCS1 qualify, whereas bare PKCS8 becomes a different object type.
// Normalization changes encoding only, never the mathematical key or its chain.
func normalizeTraditional(k *key) error {
	if k.privateFormat != "pkcs8" {
		return nil
	}
	b, err := completePEM(k.privatePEM, true)
	if err != nil {
		return err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return fail("E_PRIVATE_KEY")
	}
	var output *pem.Block
	switch pk := parsed.(type) {
	case *rsa.PrivateKey:
		output = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}
		k.privateFormat = "pkcs1"
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			return fail("E_PRIVATE_KEY")
		}
		output = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		k.privateFormat = "sec1"
	default:
		return fail("E_PARAMETERS")
	}
	k.privatePEM = strings.TrimSpace(string(pem.EncodeToMemory(output)))
	warnings := []string{}
	for _, w := range k.warnings {
		if w != "pkcs8_requires_traditional_pem_for_installed_engine" {
			warnings = append(warnings, w)
		}
	}
	k.warnings = appendUnique(warnings, "private_key_encoding_normalized_for_installed_engine")
	return nil
}

// Merge preserves each selected key's complete PEM/chain and emits one key per
// algorithm. It never infers DeviceID or silently resolves duplicates.
func Merge(inputs []*Document, selected []Selection, now time.Time) (*Document, error) {
	if now.IsZero() {
		return nil, fail("E_TIME")
	}
	if len(selected) < 1 || len(selected) > 2 {
		return nil, fail("E_SELECTION")
	}
	result := &Document{validatedAt: now.UTC(), merged: true, boxes: []box{{deviceID: OutputDeviceID, warnings: []string{}}}}
	seen := map[string]bool{}
	for _, s := range selected {
		if s.Algorithm != "ecdsa" && s.Algorithm != "rsa" {
			return nil, fail("E_SELECTION")
		}
		if seen[s.Algorithm] {
			return nil, fail("E_SELECTION_CONFLICT")
		}
		seen[s.Algorithm] = true
		if s.Source < 0 || s.Source >= len(inputs) || inputs[s.Source] == nil || s.Keybox < 0 || s.Keybox >= len(inputs[s.Source].boxes) {
			return nil, fail("E_SELECTION")
		}
		b := inputs[s.Source].boxes[s.Keybox]
		if s.Key < 0 || s.Key >= len(b.keys) {
			return nil, fail("E_SELECTION")
		}
		k := b.keys[s.Key]
		if k.algorithm != s.Algorithm {
			return nil, fail("E_SELECTION_ALGORITHM")
		}
		k.certificatePEMs = append([]string{}, k.certificatePEMs...)
		k.warnings = append([]string{}, k.warnings...)
		if err := validateKey(&k, now); err != nil {
			return nil, err
		}
		if err := normalizeTraditional(&k); err != nil {
			return nil, err
		}
		result.boxes[0].keys = append(result.boxes[0].keys, k)
	}
	sort.Slice(result.boxes[0].keys, func(i, j int) bool { return result.boxes[0].keys[i].algorithm < result.boxes[0].keys[j].algorithm })
	return result, nil
}

// XML returns SECRET MATERIAL solely for private staging/transaction use.
// Never send its result to logs, JSON responses, reports, or UI previews.
func (d *Document) XML() ([]byte, error) {
	if d == nil || len(d.boxes) == 0 {
		return nil, fail("E_SCHEMA")
	}
	var out bytes.Buffer
	out.WriteString(xml.Header)
	enc := xml.NewEncoder(&out)
	enc.Indent("", "  ")
	start := func(name string, attrs ...xml.Attr) error {
		return enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
	}
	end := func(name string) error { return enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: name}}) }
	value := func(name, value string, attrs ...xml.Attr) error {
		if err := start(name, attrs...); err != nil {
			return err
		}
		if err := enc.EncodeToken(xml.CharData(value)); err != nil {
			return err
		}
		return end(name)
	}
	if err := start("AndroidAttestation"); err != nil {
		return nil, fail("E_XML_OUTPUT")
	}
	if err := value("NumberOfKeyboxes", strconv.Itoa(len(d.boxes))); err != nil {
		return nil, fail("E_XML_OUTPUT")
	}
	for _, b := range d.boxes {
		if err := start("Keybox", xml.Attr{Name: xml.Name{Local: "DeviceID"}, Value: b.deviceID}); err != nil {
			return nil, fail("E_XML_OUTPUT")
		}
		for _, k := range b.keys {
			if err := start("Key", xml.Attr{Name: xml.Name{Local: "algorithm"}, Value: k.algorithm}); err != nil {
				return nil, fail("E_XML_OUTPUT")
			}
			if err := value("PrivateKey", "\n"+k.privatePEM+"\n", xml.Attr{Name: xml.Name{Local: "format"}, Value: "pem"}); err != nil {
				return nil, fail("E_XML_OUTPUT")
			}
			if err := start("CertificateChain"); err != nil {
				return nil, fail("E_XML_OUTPUT")
			}
			if err := value("NumberOfCertificates", strconv.Itoa(len(k.certificatePEMs))); err != nil {
				return nil, fail("E_XML_OUTPUT")
			}
			for _, c := range k.certificatePEMs {
				if err := value("Certificate", "\n"+c+"\n", xml.Attr{Name: xml.Name{Local: "format"}, Value: "pem"}); err != nil {
					return nil, fail("E_XML_OUTPUT")
				}
			}
			if err := end("CertificateChain"); err != nil {
				return nil, fail("E_XML_OUTPUT")
			}
			if err := end("Key"); err != nil {
				return nil, fail("E_XML_OUTPUT")
			}
		}
		if err := end("Keybox"); err != nil {
			return nil, fail("E_XML_OUTPUT")
		}
	}
	if err := end("AndroidAttestation"); err != nil {
		return nil, fail("E_XML_OUTPUT")
	}
	if enc.Flush() != nil {
		return nil, fail("E_XML_OUTPUT")
	}
	if out.Len() > MaxInput {
		return nil, fail("E_SIZE")
	}
	return out.Bytes(), nil
}
