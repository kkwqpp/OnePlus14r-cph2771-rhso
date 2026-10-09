package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"walletdiagnostic/internal/keybox"
)

const maxAPIConfiguration = 16 << 10

// These types are private storage codecs, never API response values. In
// particular, configured URLs, declarations and authentication are not logged,
// returned to the WebUI, or included in a support export.
type apiAuthentication struct {
	Mode     string `json:"mode"`
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Header   string `json:"header,omitempty"`
	Key      string `json:"key,omitempty"`
}
type apiConfiguration struct {
	Schema                int               `json:"schema"`
	URL                   string            `json:"url"`
	ProvenanceDeclaration string            `json:"provenance_declaration"`
	Auth                  apiAuthentication `json:"auth"`
}
type apiPrivateState struct {
	Schema     int              `json:"schema"`
	Generation string           `json:"generation"`
	Config     apiConfiguration `json:"config"`
}

var apiHeaderName = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)
var apiHostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var apiConfigFilename = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,95}\.json$`)
var errAPIAddress = errors.New("configured source address is unsupported")

func apiTextOK(s string, max int, empty bool) bool {
	if (!empty && s == "") || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func (c apiConfiguration) validate() error {
	bad := func() error {
		return fail("E_API_CONFIG", "Private source configuration is invalid or unsupported; no credential details are displayed.")
	}
	if c.Schema != 1 || !apiTextOK(c.URL, 2048, false) || !apiTextOK(c.ProvenanceDeclaration, 512, false) || strings.TrimSpace(c.ProvenanceDeclaration) == "" {
		return bad()
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.User != nil || strings.Contains(c.URL, "#") || u.Fragment != "" || u.RawFragment != "" {
		return bad()
	}
	host := u.Hostname()
	if ip, e := netip.ParseAddr(host); e == nil {
		if !apiPublicAddress(ip) {
			return bad()
		}
	} else {
		if len(host) > 253 {
			return bad()
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if !apiHostLabel.MatchString(label) {
				return bad()
			}
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return bad()
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return bad()
		}
	}
	a := c.Auth
	for _, value := range []string{a.Token, a.Username, a.Password, a.Header, a.Key} {
		if !apiTextOK(value, 8192, true) {
			return bad()
		}
	}
	switch a.Mode {
	case "NONE":
		if a.Token+a.Username+a.Password+a.Header+a.Key != "" {
			return bad()
		}
	case "BEARER":
		if a.Token == "" || strings.ContainsAny(a.Token, " \t") || a.Username+a.Password+a.Header+a.Key != "" {
			return bad()
		}
	case "BASIC":
		if a.Username == "" || a.Password == "" || len(a.Username) > 256 || strings.Contains(a.Username, ":") || a.Token+a.Header+a.Key != "" {
			return bad()
		}
	case "API_KEY":
		if a.Key == "" || strings.TrimSpace(a.Key) != a.Key || !apiHeaderName.MatchString(a.Header) || a.Token+a.Username+a.Password != "" {
			return bad()
		}
		switch strings.ToLower(a.Header) {
		case "authorization", "cookie", "cookie2", "host", "connection", "content-length", "transfer-encoding", "accept", "accept-encoding", "user-agent", "referer", "origin", "te", "trailer", "upgrade":
			return bad()
		}
		if strings.HasPrefix(strings.ToLower(a.Header), "proxy-") {
			return bad()
		}
	default:
		return fail("E_API_CONFIG", "The generic adapter supports NONE, BEARER, BASIC and API_KEY authentication only; CUSTOM and encrypted formats are unsupported.")
	}
	return nil
}

// Reject duplicate fields at every depth before decoding either private codec.
func decodeAPIJSON(body []byte, dst any) error {
	if len(body) == 0 || len(body) > maxAPIConfiguration || !utf8.Valid(body) {
		return fail("E_API_CONFIG", "Private source configuration is empty, oversized or unsupported.")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if depth > 6 || tokens > 256 {
			return errors.New("configuration structure exceeds bound")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if t == nil {
			return errors.New("null configuration value")
		}
		if del, ok := t.(json.Delim); ok {
			if del != '{' {
				return errors.New("unsupported configuration structure")
			}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				if !ok || seen[strings.ToLower(name)] {
					return errors.New("duplicate configuration field")
				}
				seen[strings.ToLower(name)] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := value(0); e != nil {
		return fail("E_API_CONFIG", "Private source JSON is invalid or ambiguous.")
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("E_API_CONFIG", "Private source JSON contains trailing data.")
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if e := d.Decode(dst); e != nil {
		return fail("E_API_CONFIG", "Private source JSON has unsupported fields or types.")
	}
	return nil
}

func apiPrivateFile(path string) error {
	if e := noLinks(path); e != nil {
		return fail("E_API_CONFIG", "Private source configuration is not a safe file.")
	}
	m, e := getMetadata(path)
	if e != nil || m.Mode != 0600 || m.UID != ownerID() || m.GID != ownerID() {
		return fail("E_API_CONFIG", "Source configuration must be a root-owned private mode-0600 file.")
	}
	return nil
}

func apiPrivateDirectory(path string) error {
	if e := noLinks(path); e != nil {
		return fail("E_API_CONFIG", "Private source storage is not a safe directory.")
	}
	s, e := os.Stat(path)
	if e != nil || !s.IsDir() {
		return fail("E_API_CONFIG", "Private source storage is unavailable.")
	}
	m, e := getMetadata(path)
	if e != nil || m.Mode != 0700 || m.UID != ownerID() || m.GID != ownerID() {
		return fail("E_API_CONFIG", "Source storage must be a root-owned private mode-0700 directory.")
	}
	return nil
}

func (a *App) loadAPISource() (apiPrivateState, string, error) {
	var s apiPrivateState
	path := filepath.Join(a.Root, "api-source.json")
	b, e := bounded(path, maxAPIConfiguration)
	if e != nil {
		return s, "", e
	}
	if e = apiPrivateDirectory(a.Root); e != nil {
		return s, "", e
	}
	if e = apiPrivateFile(path); e != nil {
		return s, "", e
	}
	if e = decodeAPIJSON(b, &s); e != nil {
		return s, "", e
	}
	if s.Schema != 1 || !validID.MatchString(s.Generation) {
		return s, "", fail("E_API_CONFIG", "Private source inventory is invalid or unsupported.")
	}
	if e = s.Config.validate(); e != nil {
		return s, "", e
	}
	return s, hash(b), nil
}

func (a *App) apiSourceStatus() map[string]any {
	out := map[string]any{"api_status": "generic-https-raw-xml", "state": "unconfigured", "configured": false, "available": false, "auth_configured": false, "exact_endpoint_available": false, "provider_contract_verified": false, "supported_format": "raw-xml", "message": "The original supplied endpoint remains unverified and unavailable. A separately configured HTTPS raw-XML source requires an operator provenance declaration; no provider identity or hardware trust is inferred."}
	s, _, e := a.loadAPISource()
	if e != nil {
		if !os.IsNotExist(e) {
			out["state"] = "invalid"
		}
		return out
	}
	out["state"], out["configured"] = "configured", true
	out["available"] = !a.Fake && !a.unfinished()
	out["auth_configured"] = s.Config.Auth.Mode != "NONE"
	out["source_generation"] = s.Generation
	return out
}

func (a *App) API(action, path string) (any, error) {
	if action == "" || action == "status" {
		if path != "" {
			return nil, fail("E_REQUEST", "A configuration path is accepted only for API config.")
		}
		return a.apiSourceStatus(), nil
	}
	if action != "config" && action != "import" {
		return nil, fail("E_REQUEST", "API actions are status, config or import.")
	}
	return a.withLock(func() (any, error) {
		if e := a.requireRecovered(); e != nil {
			return nil, e
		}
		if action == "config" {
			return a.configureAPISource(path)
		}
		if path != "" {
			return nil, fail("E_REQUEST", "A configuration path is accepted only for API config.")
		}
		if a.Fake {
			return nil, fail("E_CAPABILITY", "Network import is disabled in the fake-engine test backend.")
		}
		client, e := publicHTTPClient()
		if e != nil {
			return nil, fail("E_API_TLS", "System HTTPS verification capability is unavailable; it was not bypassed.")
		}
		client, e = guardedAPIClient(client, net.DefaultResolver.LookupIPAddr, (&net.Dialer{Timeout: 8 * time.Second}).DialContext)
		if e != nil {
			return nil, e
		}
		return a.importAPISource(client)
	})
}

// The caller holds the same operation lock used by ingest/configuration writes.
func (a *App) configureAPISource(path string) (any, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, fail("E_PATH", "Choose a clean absolute private-inbox JSON configuration path.")
	}
	base := filepath.Join(a.Root, "inbox")
	rel, e := filepath.Rel(base, path)
	if e != nil || filepath.Dir(rel) != "." || !apiConfigFilename.MatchString(rel) || strings.Contains(rel, "..") {
		return nil, fail("E_PATH", "API configuration is accepted only from the root-private inbox.")
	}
	for _, dir := range []string{a.Root, base} {
		if e = apiPrivateDirectory(dir); e != nil {
			return nil, e
		}
	}
	if e = apiPrivateFile(path); e != nil {
		return nil, e
	}
	body, e := bounded(path, maxAPIConfiguration)
	if e != nil {
		return nil, fail("E_API_CONFIG", "Private source configuration could not be read safely.")
	}
	var config apiConfiguration
	if e = decodeAPIJSON(body, &config); e != nil {
		return nil, e
	}
	if e = config.validate(); e != nil {
		return nil, e
	}
	generation, e := newID()
	if e != nil {
		return nil, e
	}
	if e = writeJSON(filepath.Join(a.Root, "api-source.json"), apiPrivateState{1, generation, config}); e != nil {
		return nil, e
	}
	return a.apiSourceStatus(), nil
}

// Conservative public-unicast policy. Special translation/tunnel, documentation
// and benchmarking ranges are unsupported, including IPv6 transition routes
// that could otherwise reach a forbidden embedded IPv4 destination.
func apiPublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is4() {
		for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
			if netip.MustParsePrefix(cidr).Contains(ip) {
				return false
			}
		}
		return true
	}
	if !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, cidr := range []string{"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

type apiLookup func(context.Context, string) ([]net.IPAddr, error)
type apiDial func(context.Context, string, string) (net.Conn, error)

// Test seams accept synthetic DNS/dial implementations; neither is exposed to
// CLI/environment. Production dials an already checked numeric address, never a
// second hostname lookup. Any forbidden answer rejects the entire resolution.
func guardedAPIClient(base *http.Client, lookup apiLookup, dial apiDial) (*http.Client, error) {
	t, ok := base.Transport.(*http.Transport)
	if !ok || t.TLSClientConfig == nil || t.TLSClientConfig.InsecureSkipVerify || lookup == nil || dial == nil {
		return nil, fail("E_API_TLS", "A verified HTTPS transport is required.")
	}
	t = t.Clone()
	t.Proxy = nil
	t.DisableKeepAlives = true
	t.DisableCompression = true
	t.TLSClientConfig = t.TLSClientConfig.Clone()
	t.TLSClientConfig.ServerName = ""
	t.TLSClientConfig.MinVersion = tls.VersionTLS12
	t.ResponseHeaderTimeout = 8 * time.Second
	t.MaxResponseHeaderBytes = 32 << 10
	t.DialTLS = nil
	t.DialTLSContext = nil
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errAPIAddress
		}
		var answers []net.IPAddr
		if ip, e := netip.ParseAddr(host); e == nil {
			answers = []net.IPAddr{{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}}
		} else {
			answers, e = lookup(ctx, host)
			if e != nil {
				return nil, e
			}
		}
		if len(answers) == 0 || len(answers) > 16 {
			return nil, errAPIAddress
		}
		for _, answer := range answers {
			ip, ok := netip.AddrFromSlice(answer.IP)
			if !ok || answer.Zone != "" || !apiPublicAddress(ip) {
				return nil, errAPIAddress
			}
		}
		ip, _ := netip.AddrFromSlice(answers[0].IP)
		return dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
	}
	return &http.Client{Transport: t, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func rawAPIXML(body []byte) error {
	if len(body) == 0 || len(body) > keybox.MaxInput {
		return fail("E_API_LIMIT", "Source response is empty or exceeds the private XML bound.")
	}
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return fail("E_API_FORMAT", "Only raw UTF-8 keybox XML is supported; encrypted, archive and HTML formats are rejected.")
	}
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = true
	depth, roots, tokens := 0, 0, 0
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return fail("E_API_FORMAT", "Source response is not complete supported raw XML.")
		}
		tokens++
		if tokens > 4096 || depth > 32 {
			return fail("E_API_LIMIT", "Source XML exceeds the structural inspection bound.")
		}
		switch v := t.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots != 1 || v.Name.Space != "" || (v.Name.Local != "AndroidAttestation" && v.Name.Local != "Keybox") {
					return fail("E_API_FORMAT", "Source XML has an unsupported wrapper.")
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.Directive:
			return fail("E_API_FORMAT", "XML directives and external entities are not supported.")
		case xml.ProcInst:
			if v.Target != "xml" || roots != 0 {
				return fail("E_API_FORMAT", "Unsupported XML processing instruction.")
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(v)) != 0 {
				return fail("E_API_FORMAT", "Unexpected data outside the XML wrapper.")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return fail("E_API_FORMAT", "Source response does not contain a complete keybox XML wrapper.")
	}
	return nil
}

func fetchAPISource(client *http.Client, config apiConfiguration) ([]byte, error) {
	if e := config.validate(); e != nil {
		return nil, e
	}
	req, e := http.NewRequest(http.MethodGet, config.URL, nil)
	if e != nil {
		return nil, fail("E_API_CONFIG", "Source request could not be prepared safely.")
	}
	req.Header.Set("Accept", "application/xml, text/xml")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "WalletDiagnostic-configured-source/1")
	switch config.Auth.Mode {
	case "BEARER":
		req.Header.Set("Authorization", "Bearer "+config.Auth.Token)
	case "BASIC":
		req.SetBasicAuth(config.Auth.Username, config.Auth.Password)
	case "API_KEY":
		req.Header.Set(config.Auth.Header, config.Auth.Key)
	}
	resp, e := client.Do(req)
	if e != nil {
		var dns *net.DNSError
		var cert *tls.CertificateVerificationError
		switch {
		case errors.Is(e, errAPIAddress):
			return nil, fail("E_API_SSRF", "Source DNS/address policy rejected the destination; no private-network request was made.")
		case errors.As(e, &dns):
			return nil, fail("E_API_DNS", "Configured source DNS resolution failed; no credentials or response details are displayed.")
		case errors.As(e, &cert):
			return nil, fail("E_API_TLS", "Configured source TLS verification failed; verification was not bypassed.")
		default:
			return nil, fail("E_API_HTTP", "Configured source request failed or timed out; no retry was made.")
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fail("E_API_HTTP", "Configured source returned a non-success response; no redirect or retry was used.")
	}
	if len(resp.Header.Values("Content-Type")) != 1 || len(resp.Header.Values("Content-Encoding")) > 1 {
		return nil, fail("E_API_FORMAT", "Configured source has ambiguous format headers.")
	}
	media, params, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || (media != "application/xml" && media != "text/xml") || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") && !strings.EqualFold(params["charset"], "us-ascii")) || (resp.Header.Get("Content-Encoding") != "" && !strings.EqualFold(resp.Header.Get("Content-Encoding"), "identity")) {
		return nil, fail("E_API_FORMAT", "Configured source must return uncompressed raw XML with a supported content type.")
	}
	if resp.ContentLength > keybox.MaxInput {
		return nil, fail("E_API_LIMIT", "Configured source response exceeds the private XML bound.")
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, keybox.MaxInput+1))
	if e != nil {
		return nil, fail("E_API_HTTP", "Configured source response could not be read completely.")
	}
	if e = rawAPIXML(body); e != nil {
		return nil, e
	}
	return body, nil
}

// The caller holds the operation lock. Import only stages; the user's separate
// Validate, selection, plan review and Apply remain mandatory.
func (a *App) importAPISource(client *http.Client) (any, error) {
	if e := a.requireRecovered(); e != nil {
		return nil, e
	}
	s, digest, e := a.loadAPISource()
	if os.IsNotExist(e) {
		return nil, fail("E_API_UNAVAILABLE", "No private generic source is configured; the original endpoint remains unverified and unavailable.")
	}
	if e != nil {
		return nil, fail("E_API_CONFIG", "Private source configuration is unreadable, invalid or unsupported.")
	}
	body, e := fetchAPISource(client, s.Config)
	if e != nil {
		return nil, e
	}
	if e = a.checkpoint("before-api-stage"); e != nil {
		return nil, e
	}
	fresh, nowDigest, e := a.loadAPISource()
	if e != nil || fresh.Generation != s.Generation || nowDigest != digest {
		return nil, fail("E_API_STALE", "Private source configuration changed during import; no input was staged.")
	}
	if e = a.requireRecovered(); e != nil {
		return nil, e
	}
	return a.stageBytes(body)
}
