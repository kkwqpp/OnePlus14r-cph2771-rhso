package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"walletdiagnostic/internal/keybox"
)

// All URLs, authentication, certificates and keys are synthetic test fixtures.
// DNS and numeric dialing are injected only into the private test seam; there
// are no external HTTP requests, device inputs or command-line bypasses.
const apiTestMarker = "synthetic-sensitive-api-material"

func apiTestConfig() apiConfiguration {
	return apiConfiguration{Schema: 1, URL: "https://source.example.com/feed?token=" + apiTestMarker, ProvenanceDeclaration: apiTestMarker, Auth: apiAuthentication{Mode: "BEARER", Token: apiTestMarker}}
}

func apiTestApp(t *testing.T) (*App, map[string]FileState, []byte) {
	t.Helper()
	dir := t.TempDir()
	a := New(filepath.Join(dir, "private"), filepath.Join(dir, "active"), filepath.Join(dir, "modules"), true)
	a.Now = func() time.Time { return coreTestNow }
	if err := a.Init(); err != nil {
		t.Fatal("private fixture initialization failed")
	}
	if err := os.MkdirAll(a.Active, 0700); err != nil {
		t.Fatal("active fixture initialization failed")
	}
	for _, name := range files {
		testWrite(t, filepath.Join(a.Active, name), []byte("preserve-"+name))
	}
	if err := os.MkdirAll(filepath.Join(a.Modules, "playintegrityfix"), 0700); err != nil {
		t.Fatal("PIF fixture initialization failed")
	}
	pif := []byte("preserve-private-PIF-fixture")
	testWrite(t, filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), pif)
	old, err := a.snapshot()
	if err != nil {
		t.Fatal("fixture snapshot failed")
	}
	return a, old, pif
}

func apiTestUnchanged(t *testing.T, a *App, old map[string]FileState, pif []byte) {
	t.Helper()
	requireSnapshot(t, a, old)
	got, err := os.ReadFile(filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"))
	if err != nil || !bytes.Equal(got, pif) {
		t.Fatal("API operation changed PIF")
	}
}

func apiTestPrivateConfig(t *testing.T, a *App, config apiConfiguration) string {
	t.Helper()
	p := filepath.Join(a.Root, "inbox", "private-source.json")
	if err := writeJSON(p, config); err != nil {
		t.Fatal("private synthetic configuration write failed")
	}
	return p
}

func apiTestConfigure(t *testing.T, a *App, config apiConfiguration) map[string]any {
	t.Helper()
	v, err := a.API("config", apiTestPrivateConfig(t, a, config))
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	return v.(map[string]any)
}

func apiTestRedacted(t *testing.T, v any, err error) {
	t.Helper()
	b, e := json.Marshal(Response(v, err))
	if e != nil || bytes.Contains(b, []byte(apiTestMarker)) || bytes.Contains(b, []byte("source.example.com")) || bytes.Contains(b, []byte("private-source.json")) {
		t.Fatal("source URL, path, provenance or authentication escaped a public response")
	}
}

type apiTLSFixture struct {
	server  *httptest.Server
	base    *http.Client
	client  *http.Client
	lookups atomic.Int32
	dials   atomic.Int32
}

func newAPITLSFixture(t *testing.T, handler http.Handler) *apiTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TLS fixture generation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(700), Subject: pkix.Name{CommonName: "synthetic-source"}, DNSNames: []string{"source.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal("TLS fixture certificate generation failed")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("TLS fixture certificate parse failed")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	f := &apiTLSFixture{base: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}
	f.server = httptest.NewUnstartedServer(handler)
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.client, err = guardedAPIClient(f.base, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		f.lookups.Add(1)
		if host != "source.example.com" {
			return nil, errors.New("unexpected synthetic host")
		}
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}, func(ctx context.Context, network, address string) (net.Conn, error) {
		f.dials.Add(1)
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "8.8.8.8" {
			return nil, errors.New("dial must use checked numeric address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal("guarded synthetic TLS client initialization failed")
	}
	return f
}

func (f *apiTLSFixture) config() apiConfiguration {
	c := apiTestConfig()
	_, port, _ := net.SplitHostPort(f.server.Listener.Addr().String())
	c.URL = "https://source.example.com:" + port + "/feed?token=" + apiTestMarker
	return c
}

func TestAPISourceConfigLifecycleAndRedaction(t *testing.T) {
	a, old, pif := apiTestApp(t)
	v, err := a.API("status", "")
	if err != nil || v.(map[string]any)["state"] != "unconfigured" {
		t.Fatal("absent private configuration status is inaccurate")
	}
	_, err = a.withLock(func() (any, error) { return a.importAPISource(nil) })
	requireCode(t, err, "E_API_UNAVAILABLE")
	status := apiTestConfigure(t, a, apiTestConfig())
	if status["configured"] != true || status["state"] != "configured" || status["available"] != false || status["auth_configured"] != true || status["provider_contract_verified"] != false || status["exact_endpoint_available"] != false || !validID.MatchString(status["source_generation"].(string)) {
		t.Fatal("configured status implied provider verification or fake network capability")
	}
	apiTestRedacted(t, status, nil)
	private, err := bounded(filepath.Join(a.Root, "api-source.json"), maxAPIConfiguration)
	if err != nil || !bytes.Contains(private, []byte(apiTestMarker)) {
		t.Fatal("private configuration was not retained for the private request")
	}
	if status["source_generation"] == hash(private) {
		t.Fatal("generation exposed a private configuration digest")
	}
	var stored apiPrivateState
	if err := readJSON(filepath.Join(a.Root, "api-source.json"), &stored); err != nil {
		t.Fatal("private source state read failed")
	}
	if stored.Config.URL != apiTestConfig().URL {
		t.Fatal("saved source was changed without review")
	}
	bad := apiTestConfig()
	bad.Auth.Mode = "CUSTOM"
	_, err = a.API("config", apiTestPrivateConfig(t, a, bad))
	requireCode(t, err, "E_API_CONFIG")
	apiTestRedacted(t, nil, err)
	after, err := bounded(filepath.Join(a.Root, "api-source.json"), maxAPIConfiguration)
	if err != nil || !bytes.Equal(after, private) {
		t.Fatal("rejected configuration replaced the existing source")
	}
	_, err = a.API("import", "")
	requireCode(t, err, "E_CAPABILITY")
	apiTestRedacted(t, nil, err)
	status2 := apiTestConfigure(t, a, apiTestConfig())
	if status2["source_generation"] == status["source_generation"] {
		t.Fatal("explicit reconfiguration reused a reviewed generation")
	}
	apiTestUnchanged(t, a, old, pif)
}

func TestAPISourceStrictPrivateJSON(t *testing.T) {
	good, err := json.Marshal(apiTestConfig())
	if err != nil {
		t.Fatal("fixture JSON encoding failed")
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"duplicate-url", bytes.Replace(good, []byte(`"url":`), []byte(`"url":"https://example.com/","url":`), 1)},
		{"case-fold-duplicate", bytes.Replace(good, []byte(`"url":`), []byte(`"URL":"https://example.com/","url":`), 1)},
		{"nested-case-fold-duplicate", bytes.Replace(good, []byte(`"mode":`), []byte(`"Mode":"NONE","mode":`), 1)},
		{"unknown-field", bytes.Replace(good, []byte(`"schema":1`), []byte(`"schema":1,"token":"`+apiTestMarker+`"`), 1)},
		{"unknown-auth-field", bytes.Replace(good, []byte(`"mode":`), []byte(`"custom":"`+apiTestMarker+`","mode":`), 1)},
		{"trailing-object", append(append([]byte(nil), good...), []byte(` {}`)...)},
		{"null-optional-auth", bytes.Replace(good, []byte(`"mode":`), []byte(`"key":null,"mode":`), 1)},
		{"null-top", []byte(`null`)}, {"array", []byte(`[]`)}, {"truncated", good[:len(good)-1]},
		{"invalid-UTF8", []byte{0xff}}, {"oversized", bytes.Repeat([]byte(" "), maxAPIConfiguration+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config apiConfiguration
			err := decodeAPIJSON(tc.body, &config)
			requireCode(t, err, "E_API_CONFIG")
			apiTestRedacted(t, nil, err)
		})
	}
	var config apiConfiguration
	if err := decodeAPIJSON(good, &config); err != nil || config.validate() != nil {
		t.Fatal("supported private JSON was rejected")
	}
}

func TestAPISourceConfigurationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*apiConfiguration)
	}{
		{"schema", func(c *apiConfiguration) { c.Schema = 2 }},
		{"missing-provenance", func(c *apiConfiguration) { c.ProvenanceDeclaration = "" }},
		{"HTTP", func(c *apiConfiguration) { c.URL = "http://source.example.com/" }},
		{"embedded-credentials", func(c *apiConfiguration) { c.URL = "https://user:password@source.example.com/" }},
		{"fragment", func(c *apiConfiguration) { c.URL += "#fragment" }},
		{"empty-fragment", func(c *apiConfiguration) { c.URL += "#" }},
		{"opaque", func(c *apiConfiguration) { c.URL = "https:opaque" }},
		{"empty-port", func(c *apiConfiguration) { c.URL = "https://source.example.com:/" }},
		{"oversized-port", func(c *apiConfiguration) { c.URL = "https://source.example.com:65536/" }},
		{"bad-label", func(c *apiConfiguration) { c.URL = "https://-bad.example.com/" }},
		{"label-too-long", func(c *apiConfiguration) { c.URL = "https://" + strings.Repeat("a", 64) + ".example.com/" }},
		{"loopback-literal", func(c *apiConfiguration) { c.URL = "https://127.0.0.1/" }},
		{"metadata-literal", func(c *apiConfiguration) { c.URL = "https://169.254.169.254/" }},
		{"IPv6-loopback", func(c *apiConfiguration) { c.URL = "https://[::1]/" }},
		{"IPv6-transition", func(c *apiConfiguration) { c.URL = "https://[2002:7f00:1::]/" }},
		{"URL-newline", func(c *apiConfiguration) { c.URL += "\n" }},
		{"bearer-whitespace", func(c *apiConfiguration) { c.Auth.Token = "two tokens" }},
		{"bearer-extra-field", func(c *apiConfiguration) { c.Auth.Key = apiTestMarker }},
		{"NONE-extra-auth", func(c *apiConfiguration) { c.Auth.Mode = "NONE" }},
		{"unknown-auth-mode", func(c *apiConfiguration) { c.Auth.Mode = "CUSTOM" }},
		{"basic-colon-username", func(c *apiConfiguration) {
			c.Auth = apiAuthentication{Mode: "BASIC", Username: "user:name", Password: apiTestMarker}
		}},
		{"basic-empty-password", func(c *apiConfiguration) { c.Auth = apiAuthentication{Mode: "BASIC", Username: "user"} }},
		{"API-key-reserved-header", func(c *apiConfiguration) {
			c.Auth = apiAuthentication{Mode: "API_KEY", Header: "Authorization", Key: apiTestMarker}
		}},
		{"API-key-proxy-header", func(c *apiConfiguration) {
			c.Auth = apiAuthentication{Mode: "API_KEY", Header: "Proxy-Authorization", Key: apiTestMarker}
		}},
		{"API-key-invalid-header", func(c *apiConfiguration) {
			c.Auth = apiAuthentication{Mode: "API_KEY", Header: "X-Key\r\nCookie", Key: apiTestMarker}
		}},
		{"auth-newline", func(c *apiConfiguration) { c.Auth.Token += "\r\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := apiTestConfig()
			tc.change(&c)
			err := c.validate()
			requireCode(t, err, "E_API_CONFIG")
			apiTestRedacted(t, nil, err)
		})
	}
}

func TestAPISourcePrivatePathsRecoveryAndCorruptStatus(t *testing.T) {
	a, old, pif := apiTestApp(t)
	path := apiTestPrivateConfig(t, a, apiTestConfig())
	for _, p := range []string{"", "private-source.json", filepath.Join(a.Root, "private-source.json"), filepath.Join(a.Root, "inbox", "nested", "private-source.json"), filepath.Join(a.Root, "inbox", "not-JSON.xml"), filepath.Join(a.Root, "inbox", "bad..name.json")} {
		_, err := a.API("config", p)
		requireCode(t, err, "E_PATH")
		apiTestRedacted(t, nil, err)
	}
	for _, request := range []struct{ action, path string }{{"status", path}, {"import", path}, {"unknown", ""}} {
		_, err := a.API(request.action, request.path)
		requireCode(t, err, "E_REQUEST")
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal("fixture mode change failed")
	}
	_, err := a.API("config", path)
	requireCode(t, err, "E_API_CONFIG")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal("fixture mode restoration failed")
	}
	apiTestConfigure(t, a, apiTestConfig())
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(a.Root, "inbox"), 0777); err != nil {
			t.Fatal("fixture directory mode change failed")
		}
		_, err = a.configureAPISource(path)
		requireCode(t, err, "E_API_CONFIG")
		if err := os.Chmod(filepath.Join(a.Root, "inbox"), 0700); err != nil {
			t.Fatal("fixture directory mode restoration failed")
		}
	}
	symlink := filepath.Join(a.Root, "inbox", "linked.json")
	if err := os.Symlink(path, symlink); err == nil {
		_, err = a.API("config", symlink)
		requireCode(t, err, "E_API_CONFIG")
	}
	if err := writeJSON(filepath.Join(a.Root, "reset-journal.json"), finalResetFixture()); err != nil {
		t.Fatal("pending reset fixture write failed")
	}
	v, err := a.API("status", "")
	if err != nil || v.(map[string]any)["available"] != false {
		t.Fatal("read-only API status was blocked or implied import availability")
	}
	for _, action := range []string{"config", "import"} {
		_, err = a.API(action, map[string]string{"config": path}[action])
		requireCode(t, err, "E_RECOVERY")
	}
	if err := os.Remove(filepath.Join(a.Root, "reset-journal.json")); err != nil {
		t.Fatal("reset fixture removal failed")
	}
	testWrite(t, filepath.Join(a.Root, "api-source.json"), []byte(apiTestMarker))
	v, err = a.API("status", "")
	if err != nil || v.(map[string]any)["state"] != "invalid" {
		t.Fatal("corrupt source status was inaccurately reported")
	}
	apiTestRedacted(t, v, err)
	_, err = a.withLock(func() (any, error) { return a.importAPISource(nil) })
	requireCode(t, err, "E_API_CONFIG")
	apiTestRedacted(t, nil, err)
	apiTestUnchanged(t, a, old, pif)
}

func TestAPISourceSingleGETAndPrivateImmutableStage(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, auth := range []apiAuthentication{{Mode: "NONE"}, {Mode: "BEARER", Token: apiTestMarker}, {Mode: "BASIC", Username: "synthetic-user", Password: apiTestMarker}, {Mode: "API_KEY", Header: "X-Synthetic-Key", Key: apiTestMarker}} {
		t.Run(auth.Mode, func(t *testing.T) {
			var calls atomic.Int32
			var requestOK atomic.Bool
			f := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				ok := r.Method == http.MethodGet && r.URL.Path == "/feed" && r.URL.Query().Get("token") == apiTestMarker && r.Header.Get("Cookie") == "" && r.Header.Get("Accept-Encoding") == "identity" && r.Header.Get("Accept") == "application/xml, text/xml" && r.Header.Get("User-Agent") == "WalletDiagnostic-configured-source/1"
				switch auth.Mode {
				case "NONE":
					ok = ok && r.Header.Get("Authorization") == ""
				case "BEARER":
					ok = ok && r.Header.Get("Authorization") == "Bearer "+apiTestMarker
				case "BASIC":
					u, p, valid := r.BasicAuth()
					ok = ok && valid && u == auth.Username && p == auth.Password
				case "API_KEY":
					ok = ok && r.Header.Get(auth.Header) == auth.Key && r.Header.Get("Authorization") == ""
				}
				requestOK.Store(ok)
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				_, _ = w.Write(fixture)
			}))
			a, old, pif := apiTestApp(t)
			config := f.config()
			config.Auth = auth
			apiTestConfigure(t, a, config)
			v, err := a.withLock(func() (any, error) { return a.importAPISource(f.client) })
			if err != nil || !requestOK.Load() || calls.Load() != 1 || f.lookups.Load() != 1 || f.dials.Load() != 1 {
				t.Fatal("configured import failed its single verified GET contract")
			}
			stage, ok := v.(Stage)
			if !ok || stage.Bytes != len(fixture) || stage.SHA256 != hash(fixture) || !validID.MatchString(stage.ID) {
				t.Fatal("import did not return ordinary immutable staging metadata")
			}
			apiTestRedacted(t, v, err)
			staged, err := bounded(filepath.Join(a.Root, "staged", stage.ID, "input.xml"), keybox.MaxInput)
			if err != nil || !bytes.Equal(staged, fixture) {
				t.Fatal("staged bytes differed from accepted raw XML")
			}
			if _, err := os.Stat(filepath.Join(a.Root, "verification.json")); !os.IsNotExist(err) {
				t.Fatal("import performed verification without an explicit request")
			}
			if _, err := os.Stat(filepath.Join(a.Root, "journal.json")); !os.IsNotExist(err) {
				t.Fatal("import created a live transaction without explicit Plan/Apply")
			}
			validated, err := a.Validate(stage.ID)
			if err != nil {
				t.Fatal("separate mandatory synthetic validation failed")
			}
			requireRedacted(t, Response(validated, err))
			apiTestUnchanged(t, a, old, pif)
		})
	}
}

func TestAPISourcePublicAddressPolicy(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "10.1.2.3", "172.31.2.3", "192.168.1.1", "169.254.169.254", "100.64.1.1", "192.0.0.8", "192.0.2.1", "192.88.99.1", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "fe80::1", "fe80::1%eth0", "fc00::1", "ff02::1", "64:ff9b::a00:1", "2001:db8::1", "2001::1", "2002:7f00:1::", "3fff::1"} {
		t.Run(address, func(t *testing.T) {
			if apiPublicAddress(netip.MustParseAddr(address)) {
				t.Fatal("non-public or unsupported transition address was accepted")
			}
		})
	}
	for _, address := range []string{"8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !apiPublicAddress(netip.MustParseAddr(address)) {
			t.Fatal("supported public unicast was rejected")
		}
	}
}

func TestAPISourceDNSGuardsBeforeCredentials(t *testing.T) {
	base := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	for _, tc := range []struct {
		name    string
		answers []net.IPAddr
		err     error
		code    string
	}{
		{"private", []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil, "E_API_SSRF"},
		{"mixed-rebinding", []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("169.254.169.254")}}, nil, "E_API_SSRF"},
		{"IPv6-zone", []net.IPAddr{{IP: net.ParseIP("2606:4700:4700::1111"), Zone: "eth0"}}, nil, "E_API_SSRF"},
		{"empty", nil, nil, "E_API_SSRF"},
		{"oversized", make([]net.IPAddr, 17), nil, "E_API_SSRF"},
		{"DNS-error", nil, &net.DNSError{Err: apiTestMarker, Name: apiTestMarker}, "E_API_DNS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dials := 0
			client, err := guardedAPIClient(base, func(context.Context, string) ([]net.IPAddr, error) { return tc.answers, tc.err }, func(context.Context, string, string) (net.Conn, error) {
				dials++
				return nil, errors.New("forbidden dial")
			})
			if err != nil {
				t.Fatal("guarded fixture client rejected")
			}
			_, err = fetchAPISource(client, apiTestConfig())
			requireCode(t, err, tc.code)
			apiTestRedacted(t, nil, err)
			if dials != 0 {
				t.Fatal("credentials could reach a rejected destination")
			}
		})
	}
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	_, err := guardedAPIClient(insecure, func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }, func(context.Context, string, string) (net.Conn, error) { return nil, nil })
	requireCode(t, err, "E_API_TLS")
}

func TestAPISourceRejectsResponseFormatsWithoutStage(t *testing.T) {
	for _, tc := range []struct {
		name, media, encoding, body, code string
		status                            int
	}{
		{"redirect", "application/xml", "", "<Keybox/>", "E_API_HTTP", 302},
		{"auth-failure", "application/xml", "", apiTestMarker, "E_API_HTTP", 401},
		{"server-failure", "application/xml", "", apiTestMarker, "E_API_HTTP", 503},
		{"HTML-MIME", "text/html", "", "<Keybox/>", "E_API_FORMAT", 200},
		{"ZIP-MIME", "application/zip", "", "PK archive", "E_API_FORMAT", 200},
		{"missing-MIME", "", "", "<Keybox/>", "E_API_FORMAT", 200},
		{"wrong-charset", "application/xml; charset=utf-16", "", "<Keybox/>", "E_API_FORMAT", 200},
		{"gzip", "application/xml", "gzip", "<Keybox/>", "E_API_FORMAT", 200},
		{"CBOX", "application/xml", "", "CBOX" + apiTestMarker, "E_API_FORMAT", 200},
		{"ZIP-disguised", "application/xml", "", "PK\x03\x04", "E_API_FORMAT", 200},
		{"HTML-disguised", "application/xml", "", "<html/>", "E_API_FORMAT", 200},
		{"DTD", "application/xml", "", "<!DOCTYPE Keybox [<!ENTITY secret SYSTEM 'file:///private'>]><Keybox/>", "E_API_FORMAT", 200},
		{"entity", "application/xml", "", "<Keybox>&unknown;</Keybox>", "E_API_FORMAT", 200},
		{"truncated", "application/xml", "", "<Keybox>", "E_API_FORMAT", 200},
		{"multiple-roots", "application/xml", "", "<Keybox/><Keybox/>", "E_API_FORMAT", 200},
		{"namespace", "application/xml", "", "<Keybox xmlns='urn:unsupported'/>", "E_API_FORMAT", 200},
		{"empty", "application/xml", "", "", "E_API_LIMIT", 200},
		{"oversized", "application/xml", "", strings.Repeat("x", keybox.MaxInput+1), "E_API_LIMIT", 200},
		{"too-many-tokens", "application/xml", "", "<Keybox>" + strings.Repeat("<a/>", 2049) + "</Keybox>", "E_API_LIMIT", 200},
		{"too-deep", "application/xml", "", strings.Repeat("<Keybox>", 34) + strings.Repeat("</Keybox>", 34), "E_API_LIMIT", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			f := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header()["Content-Type"] = []string{tc.media}
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.Header().Set("Retry-After", "1")
				w.Header().Set("Location", "https://another.example.com/private")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			a, old, pif := apiTestApp(t)
			apiTestConfigure(t, a, f.config())
			_, err := a.withLock(func() (any, error) { return a.importAPISource(f.client) })
			requireCode(t, err, tc.code)
			apiTestRedacted(t, nil, err)
			entries, err := os.ReadDir(filepath.Join(a.Root, "staged"))
			if err != nil || len(entries) != 0 {
				t.Fatal("rejected response created a staged input")
			}
			if calls.Load() != 1 {
				t.Fatal("response triggered a redirect or automatic retry")
			}
			apiTestUnchanged(t, a, old, pif)
		})
	}
}

func TestAPISourceTLSAndTimeoutAreNotBypassed(t *testing.T) {
	f := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Keybox/>")
	}))
	config := f.config()
	transport := f.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	client := *f.client
	client.Transport = transport
	_, err := fetchAPISource(&client, config)
	requireCode(t, err, "E_API_TLS")
	apiTestRedacted(t, nil, err)
	var calls atomic.Int32
	timeout := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Keybox/>")
	}))
	timeout.client.Timeout = 25 * time.Millisecond
	_, err = fetchAPISource(timeout.client, timeout.config())
	requireCode(t, err, "E_API_HTTP")
	apiTestRedacted(t, nil, err)
	if calls.Load() != 1 {
		t.Fatal("timeout automatically retried")
	}
}

func TestAPISourceConfigurationRaceAndLateRecoveryRefuseStaging(t *testing.T) {
	f := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, "<Keybox/>")
	}))
	for _, tc := range []struct {
		name, code string
		mutate     func(*testing.T, *App)
	}{
		{"generation-changed", "E_API_STALE", func(t *testing.T, a *App) {
			s, _, err := a.loadAPISource()
			if err != nil {
				t.Fatal("private fixture read failed")
			}
			s.Generation = strings.Repeat("b", 32)
			if err := writeJSON(filepath.Join(a.Root, "api-source.json"), s); err != nil {
				t.Fatal("fixture update failed")
			}
		}},
		{"same-generation-body-changed", "E_API_STALE", func(t *testing.T, a *App) {
			s, _, err := a.loadAPISource()
			if err != nil {
				t.Fatal("private fixture read failed")
			}
			s.Config.Auth.Token += "-changed"
			if err := writeJSON(filepath.Join(a.Root, "api-source.json"), s); err != nil {
				t.Fatal("fixture update failed")
			}
		}},
		{"corrupt", "E_API_STALE", func(t *testing.T, a *App) {
			testWrite(t, filepath.Join(a.Root, "api-source.json"), []byte(apiTestMarker))
		}},
		{"removed", "E_API_STALE", func(t *testing.T, a *App) {
			if err := os.Remove(filepath.Join(a.Root, "api-source.json")); err != nil {
				t.Fatal("fixture removal failed")
			}
		}},
		{"pending-reset", "E_RECOVERY", func(t *testing.T, a *App) {
			if err := writeJSON(filepath.Join(a.Root, "reset-journal.json"), finalResetFixture()); err != nil {
				t.Fatal("fixture reset write failed")
			}
		}},
		{"corrupt-stack-journal", "E_RECOVERY", func(t *testing.T, a *App) {
			testWrite(t, filepath.Join(a.Root, "stack-journal.json"), []byte(apiTestMarker))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, old, pif := apiTestApp(t)
			apiTestConfigure(t, a, f.config())
			a.Fault = func(point string) error {
				if point == "before-api-stage" {
					tc.mutate(t, a)
				}
				return nil
			}
			_, err := a.withLock(func() (any, error) { return a.importAPISource(f.client) })
			requireCode(t, err, tc.code)
			apiTestRedacted(t, nil, err)
			entries, err := os.ReadDir(filepath.Join(a.Root, "staged"))
			if err != nil || len(entries) != 0 {
				t.Fatal("stale source or late reset created a staged input")
			}
			apiTestUnchanged(t, a, old, pif)
		})
	}
}

func TestAPISourceProxyCookieAndHostnameVerification(t *testing.T) {
	var requests atomic.Int32
	f := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Keybox/>")
	}))
	var proxies atomic.Int32
	base := *f.base
	transport := base.Transport.(*http.Transport).Clone()
	transport.Proxy = func(*http.Request) (*url.URL, error) { proxies.Add(1); return nil, errors.New(apiTestMarker) }
	base.Transport = transport
	base.Jar = apiSyntheticJar{}
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "8.8.8.8" {
			return nil, errors.New("non-numeric dial")
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}
	client, err := guardedAPIClient(&base, lookup, dial)
	if err != nil {
		t.Fatal("guarded transport failed")
	}
	if client.Jar != nil {
		t.Fatal("configured import retained ambient cookies")
	}
	if _, err = fetchAPISource(client, f.config()); err != nil || proxies.Load() != 0 || requests.Load() != 1 {
		t.Fatal("transport consulted ambient proxy or failed verified HTTPS")
	}
	config := f.config()
	config.URL = strings.Replace(config.URL, "source.example.com", "wrong.example.com", 1)
	_, err = fetchAPISource(client, config)
	requireCode(t, err, "E_API_TLS")
	apiTestRedacted(t, nil, err)
	if requests.Load() != 1 {
		t.Fatal("credentials were sent before hostname verification")
	}
}

type apiSyntheticJar struct{}

func (apiSyntheticJar) SetCookies(*url.URL, []*http.Cookie) {}
func (apiSyntheticJar) Cookies(*url.URL) []*http.Cookie {
	return []*http.Cookie{{Name: "Cookie", Value: apiTestMarker}}
}

func TestAPISourceStreamingBoundsAndAmbiguousHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		handler    http.HandlerFunc
	}{
		{"unknown-length-oversized", "E_API_LIMIT", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, strings.Repeat("x", keybox.MaxInput+1))
		}},
		{"partial-body", "E_API_HTTP", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("Content-Length", "400")
			_, _ = io.WriteString(w, "<Keybox/>")
		}},
		{"conflicting-types", "E_API_FORMAT", func(w http.ResponseWriter, r *http.Request) {
			w.Header()["Content-Type"] = []string{"application/xml", "text/html"}
			_, _ = io.WriteString(w, "<Keybox/>")
		}},
		{"duplicate-encodings", "E_API_FORMAT", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.Header()["Content-Encoding"] = []string{"identity", "gzip"}
			_, _ = io.WriteString(w, "<Keybox/>")
		}},
		{"oversized-headers", "E_API_HTTP", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("X-Synthetic-Header", strings.Repeat("a", 34<<10))
			_, _ = io.WriteString(w, "<Keybox/>")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPITLSFixture(t, tc.handler)
			a, old, pif := apiTestApp(t)
			apiTestConfigure(t, a, f.config())
			_, err := a.withLock(func() (any, error) { return a.importAPISource(f.client) })
			requireCode(t, err, tc.code)
			apiTestRedacted(t, nil, err)
			entries, err := os.ReadDir(filepath.Join(a.Root, "staged"))
			if err != nil || len(entries) != 0 {
				t.Fatal("rejected stream created a staged input")
			}
			apiTestUnchanged(t, a, old, pif)
		})
	}
}

func TestAPISourceStatusAndSupportNeverContainPrivateConfiguration(t *testing.T) {
	a, old, pif := apiTestApp(t)
	apiTestConfigure(t, a, apiTestConfig())
	for _, action := range []string{"status", "diagnose"} {
		var v any
		var err error
		if action == "status" {
			v, err = a.Status()
		} else {
			v, err = a.Diagnose()
		}
		apiTestRedacted(t, v, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(apiPrivateState) apiPrivateState
	}{
		{"schema", func(s apiPrivateState) apiPrivateState { s.Schema = 99; return s }},
		{"generation", func(s apiPrivateState) apiPrivateState { s.Generation = apiTestMarker; return s }},
		{"invalid-url", func(s apiPrivateState) apiPrivateState {
			s.Config.URL = "http://private.invalid/" + apiTestMarker
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiTestConfigure(t, a, apiTestConfig())
			s, _, err := a.loadAPISource()
			if err != nil {
				t.Fatal("private fixture state read failed")
			}
			if err := writeJSON(filepath.Join(a.Root, "api-source.json"), tc.mutate(s)); err != nil {
				t.Fatal("corrupt source fixture write failed")
			}
			v, err := a.API("status", "")
			if err != nil || v.(map[string]any)["state"] != "invalid" || v.(map[string]any)["available"] != false {
				t.Fatal("invalid source appeared usable")
			}
			apiTestRedacted(t, v, err)
		})
	}
	apiTestUnchanged(t, a, old, pif)
}

func TestAPISourcePrivateIOFailureIsRedactedAndStopsStaging(t *testing.T) {
	f := newAPITLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Keybox/>")
	}))
	a, old, pif := apiTestApp(t)
	apiTestConfigure(t, a, f.config())
	a.Fault = func(point string) error {
		if point == "before-api-stage" {
			return &os.PathError{Op: "write", Path: apiTestMarker, Err: errors.New(apiTestMarker)}
		}
		return nil
	}
	_, err := a.withLock(func() (any, error) { return a.importAPISource(f.client) })
	requireCode(t, err, "E_IO")
	apiTestRedacted(t, nil, err)
	entries, err := os.ReadDir(filepath.Join(a.Root, "staged"))
	if err != nil || len(entries) != 0 {
		t.Fatal("private I/O failure did not stop staging")
	}
	apiTestUnchanged(t, a, old, pif)
}

func TestAPISourceCorruptStackJournalBlocksWritesButAllowsStatus(t *testing.T) {
	a, old, pif := apiTestApp(t)
	status := apiTestConfigure(t, a, apiTestConfig())
	// Reading API status does not invoke Android or perform a network request.
	a.Fake = false
	v, err := a.API("status", "")
	if err != nil || v.(map[string]any)["available"] != true {
		t.Fatal("healthy configured source status is inaccurate")
	}
	testWrite(t, filepath.Join(a.Root, "stack-journal.json"), []byte(apiTestMarker))
	v, err = a.API("status", "")
	if err != nil || v.(map[string]any)["state"] != "configured" || v.(map[string]any)["available"] != false {
		t.Fatal("corrupt stack recovery blocked read-only status or permitted import")
	}
	apiTestRedacted(t, v, err)
	a.Fake = true
	for _, action := range []string{"config", "import"} {
		path := ""
		if action == "config" {
			path = filepath.Join(a.Root, "inbox", "private-source.json")
		}
		_, err = a.API(action, path)
		requireCode(t, err, "E_RECOVERY")
		apiTestRedacted(t, nil, err)
	}
	fresh, _, err := a.loadAPISource()
	if err != nil || fresh.Generation != status["source_generation"] {
		t.Fatal("blocked operation replaced private source state")
	}
	apiTestUnchanged(t, a, old, pif)
}
