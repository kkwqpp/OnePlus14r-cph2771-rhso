package keybox

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

var testNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

type fixture struct {
	algorithm string
	private   string
	certs     []string
}

func newSigner(t *testing.T, algorithm string, parameter int) crypto.Signer {
	t.Helper()
	var signer crypto.Signer
	var err error
	switch algorithm {
	case "rsa":
		signer, err = rsa.GenerateKey(rand.Reader, parameter)
	case "ecdsa":
		var curve elliptic.Curve
		switch parameter {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		signer, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil || signer == nil {
		t.Fatal("synthetic key generation failed")
	}
	return signer
}
func certificate(t *testing.T, serial int64, name string, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer, until time.Time) (string, *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: testNow.Add(-time.Hour), NotAfter: until, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 5}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal("synthetic certificate generation failed")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("synthetic certificate parse failed")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), c
}
func newFixture(t *testing.T, algorithm string, parameter int) fixture {
	t.Helper()
	rootKey := newSigner(t, "ecdsa", 256)
	rootPEM, root := certificate(t, 1, "Sensitive root identity", rootKey, nil, nil, testNow.Add(48*time.Hour))
	signer := newSigner(t, algorithm, parameter)
	leafPEM, _ := certificate(t, 2, "Sensitive signing identity", signer, root, rootKey, testNow.Add(24*time.Hour))
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal("synthetic private encoding failed")
	}
	return fixture{algorithm: algorithm, private: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), certs: []string{leafPEM, rootPEM}}
}
func keyXML(f fixture) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<Key algorithm=\"%s\"><PrivateKey format=\"pem\">%s</PrivateKey><CertificateChain><NumberOfCertificates>%d</NumberOfCertificates>", f.algorithm, f.private, len(f.certs))
	for _, c := range f.certs {
		fmt.Fprintf(&b, "<Certificate format=\"pem\">%s</Certificate>", c)
	}
	b.WriteString("</CertificateChain></Key>")
	return b.String()
}
func documentXML(boxes ...[]fixture) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>%d</NumberOfKeyboxes>", len(boxes))
	for _, keys := range boxes {
		b.WriteString("<Keybox DeviceID=\"owner-secret-device-id\">")
		for _, f := range keys {
			b.WriteString(keyXML(f))
		}
		b.WriteString("</Keybox>")
	}
	b.WriteString("</AndroidAttestation>")
	return []byte(b.String())
}
func expectCode(t *testing.T, data []byte, code string) {
	t.Helper()
	d, err := Parse(data, testNow)
	if err == nil || d != nil {
		t.Fatal("expected safe validation rejection")
	}
	e, ok := err.(*Error)
	if !ok || e.Code != code {
		t.Fatalf("expected %s, received safe error %v", code, err)
	}
}

func TestAlgorithmsAndMerge(t *testing.T) {
	e := newFixture(t, "ecdsa", 256)
	r := newFixture(t, "rsa", 2048)
	p := newFixture(t, "ecdsa", 384)
	for _, f := range []fixture{e, r, p} {
		d, err := Parse(documentXML([]fixture{f}), testNow)
		if err != nil {
			t.Fatal(err)
		}
		s := d.Summary().(RedactedSummary)
		if len(s.Keyboxes) != 1 || s.Keyboxes[0].Keys[0].Algorithm != f.algorithm || !s.CryptographicConsistent || s.Trust != "unknown" || s.Revocation != "unknown" {
			t.Fatal("unexpected redacted summary")
		}
	}
	a, err := Parse(documentXML([]fixture{e}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(documentXML([]fixture{r}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Merge([]*Document{a, b}, []Selection{{Source: 0, Keybox: 0, Key: 0, Algorithm: "ecdsa"}, {Source: 1, Keybox: 0, Key: 0, Algorithm: "rsa"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.boxes) != 1 || len(m.boxes[0].keys) != 2 || m.boxes[0].deviceID != OutputDeviceID {
		t.Fatal("merge shape incorrect")
	}
	for i, source := range []fixture{e, r} {
		original, _ := pem.Decode([]byte(source.private))
		signer, err := x509.ParsePKCS8PrivateKey(original.Bytes)
		if err != nil {
			t.Fatal("fixture parse")
		}
		merged, _ := pem.Decode([]byte(m.boxes[0].keys[i].privatePEM))
		var output crypto.Signer
		if i == 0 {
			output, err = x509.ParseECPrivateKey(merged.Bytes)
			if merged.Type != "EC PRIVATE KEY" {
				t.Fatal("EC output is incompatible with installed engine")
			}
		} else {
			output, err = x509.ParsePKCS1PrivateKey(merged.Bytes)
			if merged.Type != "RSA PRIVATE KEY" {
				t.Fatal("RSA output is incompatible with installed engine")
			}
		}
		if err != nil {
			t.Fatal("normalized private encoding invalid")
		}
		a, _ := x509.MarshalPKIXPublicKey(signer.(crypto.Signer).Public())
		b, _ := x509.MarshalPKIXPublicKey(output.Public())
		if !bytes.Equal(a, b) {
			t.Fatal("merge changed selected mathematical key")
		}
	}
	for i, c := range e.certs {
		if m.boxes[0].keys[0].certificatePEMs[i] != strings.TrimSpace(c) {
			t.Fatal("merge changed selected chain")
		}
	}
	x, err := m.XML()
	if err != nil {
		t.Fatal(err)
	}
	round, err := Parse(x, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(round.boxes[0].keys) != 2 {
		t.Fatal("output did not round trip")
	}
	s := m.Summary().(RedactedSummary)
	if s.MetadataDeviceID != OutputDeviceID || s.DeviceIDPolicy != "fixed_helper_metadata_no_hardware_identity" {
		t.Fatal("merge metadata decision missing")
	}
}

func TestExplicitDuplicateSelection(t *testing.T) {
	a := newFixture(t, "ecdsa", 256)
	b := newFixture(t, "ecdsa", 384)
	d, err := Parse(documentXML([]fixture{a, b}, []fixture{a}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Summary().(RedactedSummary)
	if len(s.Keyboxes) != 2 || len(s.Keyboxes[0].Keys) != 2 || len(s.Keyboxes[0].Warnings) == 0 {
		t.Fatal("ambiguous inventory missing")
	}
	m, err := Merge([]*Document{d}, []Selection{{Source: 0, Keybox: 0, Key: 1, Algorithm: "ecdsa"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if m.boxes[0].keys[0].parameter != "P-384" {
		t.Fatal("wrong duplicate selected")
	}
	cases := []struct {
		selected []Selection
		code     string
	}{
		{nil, "E_SELECTION"},
		{[]Selection{{Source: -1, Algorithm: "ecdsa"}}, "E_SELECTION"},
		{[]Selection{{Source: 0, Keybox: 7, Algorithm: "ecdsa"}}, "E_SELECTION"},
		{[]Selection{{Source: 0, Keybox: 0, Key: 7, Algorithm: "ecdsa"}}, "E_SELECTION"},
		{[]Selection{{Source: 0, Algorithm: "rsa"}}, "E_SELECTION_ALGORITHM"},
		{[]Selection{{Source: 0, Algorithm: "ecdsa"}, {Source: 0, Key: 1, Algorithm: "ecdsa"}}, "E_SELECTION_CONFLICT"},
	}
	for _, tc := range cases {
		_, err := Merge([]*Document{d}, tc.selected, testNow)
		e, ok := err.(*Error)
		if !ok || e.Code != tc.code {
			t.Fatalf("selection: expected %s; got %v", tc.code, err)
		}
	}
	_, err = Merge([]*Document{d}, []Selection{{Source: 0, Algorithm: "ecdsa"}}, testNow.Add(72*time.Hour))
	if e, ok := err.(*Error); !ok || e.Code != "E_CERT_TIME" {
		t.Fatal("merge must recheck validity at plan time")
	}
}

func TestHostileXMLAndPEM(t *testing.T) {
	f := newFixture(t, "ecdsa", 256)
	valid := string(documentXML([]fixture{f}))
	cases := []struct{ name, data, code string }{
		{"DTD", "<!DOCTYPE AndroidAttestation SYSTEM \"file:///private\">" + valid, "E_XML_DIRECTIVE"},
		{"XXE", "<!DOCTYPE AndroidAttestation [<!ENTITY secret SYSTEM \"file:///private\">]>" + strings.Replace(valid, "owner-secret-device-id", "&secret;", 1), "E_XML_ENTITY"},
		{"entity", strings.Replace(valid, "owner-secret-device-id", "owner&amp;id", 1), "E_XML_ENTITY"},
		{"unknown", strings.Replace(valid, "</Keybox>", "<Unexpected/></Keybox>", 1), "E_SCHEMA"},
		{"attribute", strings.Replace(valid, "<Keybox ", "<Keybox extra=\"x\" ", 1), "E_SCHEMA"},
		{"namespace", strings.Replace(valid, "<AndroidAttestation>", "<AndroidAttestation xmlns=\"urn:x\">", 1), "E_SCHEMA"},
		{"duplicateAttribute", strings.Replace(valid, "<Keybox ", "<Keybox DeviceID=\"extra\" ", 1), "E_SCHEMA"},
		{"count", strings.Replace(valid, "<NumberOfCertificates>2", "<NumberOfCertificates>3", 1), "E_COUNT"},
		{"boxes", strings.Replace(valid, "<NumberOfKeyboxes>1", "<NumberOfKeyboxes>2", 1), "E_COUNT"},
		{"algorithm", strings.Replace(valid, "algorithm=\"ecdsa\"", "algorithm=\"ECDSA\"", 1), "E_ALGORITHM"},
		{"format", strings.Replace(valid, "format=\"pem\"", "format=\"der\"", 1), "E_SCHEMA"},
		{"processing", strings.Replace(valid, "?>", "?><?run command?>", 1), "E_XML_PROCESSING"},
		{"encoding", strings.Replace(valid, "version=\"1.0\"", "version=\"1.0\" encoding=\"ISO-8859-1\"", 1), "E_XML"},
		{"secondRoot", valid + "<AndroidAttestation/>", "E_SCHEMA"},
		{"truncated", valid[:len(valid)-10], "E_XML"},
		{"bareKeybox", strings.Replace(strings.Replace(valid, "<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes>", "", 1), "</AndroidAttestation>", "", 1), "E_SCHEMA"},
		{"privatePrefix", strings.Replace(valid, f.private, "garbage\n"+f.private, 1), "E_PRIVATE_PEM"},
		{"privateDouble", strings.Replace(valid, f.private, f.private+f.private, 1), "E_PRIVATE_PEM"},
		{"privateTruncated", strings.Replace(valid, "-----END PRIVATE KEY-----", "", 1), "E_PRIVATE_PEM"},
		{"certificatePrefix", strings.Replace(valid, f.certs[0], "garbage\n"+f.certs[0], 1), "E_CERT_PEM"},
		{"certificateDouble", strings.Replace(valid, f.certs[0], f.certs[0]+f.certs[0], 1), "E_CERT_PEM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { expectCode(t, []byte(tc.data), tc.code) })
	}
	expectCode(t, bytes.Repeat([]byte{'x'}, MaxInput+1), "E_SIZE")
	expectCode(t, []byte{}, "E_SIZE")
	expectCode(t, []byte("<AndroidAttestation>"+strings.Repeat("<!--x-->", maxTokens)+"</AndroidAttestation>"), "E_LIMIT")
	if _, err := Parse([]byte(valid), time.Time{}); err == nil {
		t.Fatal("zero time accepted")
	}
}

func TestCryptographicRejections(t *testing.T) {
	f := newFixture(t, "ecdsa", 256)
	other := newFixture(t, "ecdsa", 256)
	mismatch := f
	mismatch.private = other.private
	expectCode(t, documentXML([]fixture{mismatch}), "E_KEY_MISMATCH")
	badOrder := f
	badOrder.certs = []string{f.certs[1], f.certs[0]}
	expectCode(t, documentXML([]fixture{badOrder}), "E_KEY_MISMATCH")
	badSignature := f
	badSignature.certs = []string{f.certs[0], other.certs[1]}
	expectCode(t, documentXML([]fixture{badSignature}), "E_CHAIN_SIGNATURE")
	incomplete := f
	incomplete.certs = []string{f.certs[0]}
	expectCode(t, documentXML([]fixture{incomplete}), "E_CHAIN_INCOMPLETE")
	duplicate := f
	duplicate.certs = []string{f.certs[0], f.certs[1], f.certs[1]}
	expectCode(t, documentXML([]fixture{duplicate}), "E_CHAIN_DUPLICATE")
	wrongAlgorithm := f
	wrongAlgorithm.algorithm = "rsa"
	expectCode(t, documentXML([]fixture{wrongAlgorithm}), "E_ALGORITHM_MISMATCH")
	for _, tc := range []struct {
		algorithm string
		parameter int
	}{{"rsa", 1024}, {"ecdsa", 521}, {"ed25519", 0}} {
		bad := newFixture(t, tc.algorithm, tc.parameter)
		if tc.algorithm == "ed25519" {
			bad.algorithm = "ecdsa"
		}
		expectCode(t, documentXML([]fixture{bad}), "E_PARAMETERS")
	}
	if _, err := Parse(documentXML([]fixture{f}), testNow.Add(72*time.Hour)); err == nil {
		t.Fatal("expired chain accepted")
	}
	if _, err := Parse(documentXML([]fixture{f}), testNow.Add(-72*time.Hour)); err == nil {
		t.Fatal("not-yet-valid chain accepted")
	}
}

func TestSecretRedaction(t *testing.T) {
	f := newFixture(t, "ecdsa", 256)
	d, err := Parse(documentXML([]fixture{f}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{string(data), fmt.Sprintf("%v", d), fmt.Sprintf("%+v", d), fmt.Sprintf("%#v", d), fmt.Sprintf("%+v", Error{Code: "E_XML"})}
	for _, out := range outputs {
		for _, secret := range []string{"owner-secret-device-id", "Sensitive root identity", "Sensitive signing identity", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", strings.TrimSpace(f.private)} {
			if strings.Contains(out, secret) {
				t.Fatal("redaction leaked synthetic secret")
			}
		}
	}
	if !strings.Contains(string(data), "\"trust\":\"unknown\"") || !strings.Contains(string(data), "\"wallet_acceptance\":\"not_assessed\"") {
		t.Fatal("uncertainty not separated")
	}
}

func TestTraditionalPrivateKeyPEM(t *testing.T) {
	for _, alg := range []string{"ecdsa", "rsa"} {
		parameter := 256
		if alg == "rsa" {
			parameter = 2048
		}
		f := newFixture(t, alg, parameter)
		block, _ := pem.Decode([]byte(f.private))
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal("fixture parse")
		}
		if alg == "rsa" {
			f.private = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk.(*rsa.PrivateKey))}))
		} else {
			der, err := x509.MarshalECPrivateKey(pk.(*ecdsa.PrivateKey))
			if err != nil {
				t.Fatal("fixture encode")
			}
			f.private = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		}
		if _, err = Parse(documentXML([]fixture{f}), testNow); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIndentedPEMOnlyNormalizesASCIIWhitespace(t *testing.T) {
	f := newFixture(t, "ecdsa", 256)
	indent := func(value string) string {
		lines := strings.Split(strings.TrimSpace(value), "\n")
		for i, line := range lines {
			lines[i] = " \t    " + line + "\t "
		}
		return "\n" + strings.Join(lines, "\n") + "\n"
	}
	f.private = indent(f.private)
	for i, c := range f.certs {
		f.certs[i] = indent(c)
	}
	d, err := Parse(documentXML([]fixture{f}), testNow)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Merge([]*Document{d}, []Selection{{Source: 0, Algorithm: "ecdsa"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range append([]string{m.boxes[0].keys[0].privatePEM}, m.boxes[0].keys[0].certificatePEMs...) {
		for _, line := range strings.Split(value, "\n") {
			if line != strings.Trim(line, " \t") {
				t.Fatal("output retained PEM indentation")
			}
		}
	}
	output, err := m.XML()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(output, testNow); err != nil {
		t.Fatal(err)
	}
	truncated := f
	truncated.private = strings.Replace(truncated.private, "-----END PRIVATE KEY-----", "", 1)
	expectCode(t, documentXML([]fixture{truncated}), "E_PRIVATE_PEM")
	double := f
	double.private += f.private
	expectCode(t, documentXML([]fixture{double}), "E_PRIVATE_PEM")
	junk := f
	junk.private = "unexpected data\n" + f.private
	expectCode(t, documentXML([]fixture{junk}), "E_PRIVATE_PEM")
	unicode := f
	unicode.private = "\u00a0" + strings.TrimSpace(f.private)
	expectCode(t, documentXML([]fixture{unicode}), "E_PRIVATE_PEM")
}

func FuzzParseNeverLeaks(f *testing.F) {
	f.Add([]byte("<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///private'>]><x>&y;</x>"))
	f.Add([]byte("<AndroidAttestation><NumberOfKeyboxes>0</NumberOfKeyboxes></AndroidAttestation>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Parse(data, testNow)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatal("unsafe error type")
			}
			if d != nil {
				t.Fatal("partial invalid document returned")
			}
		}
	})
}
