package core

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"walletdiagnostic/internal/keybox"
)

const publicRootsURL = "https://android.googleapis.com/attestation/root"
const publicStatusURL = "https://android.googleapis.com/attestation/status"

var publicDelta = regexp.MustCompile(`^[0-9]+$`)

type publicSnapshot struct {
	Body      []byte `json:"body"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
}
type publicCache struct {
	Schema    int            `json:"schema"`
	CheckedAt string         `json:"checked_at"`
	Roots     publicSnapshot `json:"roots"`
	Status    publicSnapshot `json:"status"`
}

func publicHTTPClient() (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if runtime.GOOS == "android" {
		// Android 14+ moved the system store into the Conscrypt APEX. Go's
		// standard Android directory list still includes the legacy path.
		store, resolveErr := filepath.EvalSymlinks("/apex/com.android.conscrypt/cacerts")
		if resolveErr == nil && store != "/apex/com.android.conscrypt/cacerts" && !regexp.MustCompile(`^/apex/com\.android\.conscrypt@[0-9]+/cacerts$`).MatchString(store) {
			return nil, fail("E_PUBLIC_FEED", "System TLS trust-store alias has an unrecognized target.")
		}
		entries, e := os.ReadDir(store)
		if e == nil {
			m, e := getMetadata(store)
			if e != nil || m.UID != 0 || m.Mode&0022 != 0 {
				return nil, fail("E_PUBLIC_FEED", "System TLS trust-store ownership or write protection is unverified.")
			}
			if len(entries) > 1000 {
				return nil, fail("E_PUBLIC_FEED", "System TLS trust store exceeds its inspection bound.")
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				b, e := bounded(filepath.Join(store, entry.Name()), 16<<10)
				if e != nil {
					return nil, fail("E_PUBLIC_FEED", "System TLS trust store could not be read safely.")
				}
				pool.AppendCertsFromPEM(b)
			}
		}
	}
	t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DisableKeepAlives: true, ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	return &http.Client{Transport: t, Timeout: 12 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// Public cache lifetime follows response freshness, including intermediary Age
// and apparent age. No usable lifetime is invented when headers are absent.
func publicExpiry(h http.Header, now time.Time) time.Time {
	maxAge := int64(-1)
	noCache := false
	if len(h.Values("Date")) != 1 || len(h.Values("Age")) > 1 || len(h.Values("Expires")) > 1 {
		return now
	}
	for _, part := range strings.Split(strings.Join(h.Values("Cache-Control"), ","), ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "no-store" || part == "no-cache" || strings.HasPrefix(part, "no-cache=") {
			noCache = true
		}
		if strings.HasPrefix(part, "max-age=") {
			raw := strings.TrimPrefix(part, "max-age=")
			if strings.HasPrefix(raw, "\"") && strings.HasSuffix(raw, "\"") && len(raw) > 1 {
				raw = raw[1 : len(raw)-1]
			}
			if !publicDelta.MatchString(raw) {
				return now
			}
			v, e := strconv.ParseInt(raw, 10, 64)
			if e != nil || v < 0 || maxAge != -1 {
				return now
			}
			maxAge = v
		}
	}
	if noCache {
		return now
	}
	date, e := http.ParseTime(h.Get("Date"))
	if e != nil || date.After(now.Add(5*time.Minute)) {
		return now
	}
	age := int64(0)
	if raw := h.Get("Age"); len(h.Values("Age")) > 0 {
		if !publicDelta.MatchString(raw) {
			return now
		}
		v, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || v < 0 {
			return now
		}
		age = v
	}
	apparent := int64(now.Sub(date).Seconds())
	if apparent > age {
		age = apparent
	}
	lifetime := maxAge
	if expires, e := http.ParseTime(h.Get("Expires")); e == nil {
		expiresLifetime := int64(expires.Sub(date).Seconds())
		if lifetime < 0 || expiresLifetime < lifetime {
			lifetime = expiresLifetime
		}
	}
	if lifetime > 86400 {
		lifetime = 86400
	}
	until := now
	if remaining := lifetime - age; remaining > 0 {
		until = now.Add(time.Duration(remaining) * time.Second)
	}
	return until.UTC()
}

func fetchPublic(client *http.Client, url string, max int, now time.Time) (publicSnapshot, error) {
	if url != publicRootsURL && url != publicStatusURL {
		return publicSnapshot{}, fail("E_PUBLIC_FEED", "Only the verified Google public-feed endpoints are supported.")
	}
	req, e := http.NewRequest(http.MethodGet, url, nil)
	if e != nil {
		return publicSnapshot{}, fail("E_PUBLIC_FEED", "Public-feed request could not be prepared.")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "WalletDiagnostic-public-check/0.1")
	resp, e := client.Do(req)
	if e != nil {
		var dns *net.DNSError
		var cert *tls.CertificateVerificationError
		if errors.As(e, &dns) {
			return publicSnapshot{}, fail("E_PUBLIC_DNS", "Android could not resolve the Google public-feed hostname. Check the native DNS capability and connectivity; cached evidence was preserved.")
		}
		if errors.As(e, &cert) {
			return publicSnapshot{}, fail("E_PUBLIC_TLS", "Google public-feed TLS certificate verification failed. Check device time and the system trust store; verification was not bypassed.")
		}
		return publicSnapshot{}, fail("E_PUBLIC_FEED", "Google public-feed request failed or timed out. Existing cached evidence was preserved; no local material was uploaded.")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return publicSnapshot{}, fail("E_PUBLIC_FEED", "Google public-feed request returned a non-success response. No redirect, retry or alternate service was used.")
	}
	for _, part := range strings.Split(strings.Join(resp.Header.Values("Cache-Control"), ","), ",") {
		if strings.TrimSpace(strings.ToLower(part)) == "no-store" {
			return publicSnapshot{}, fail("E_PUBLIC_FEED", "Public response forbids caching. Existing evidence was preserved without storing the new response.")
		}
	}
	t, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || t != "application/json" {
		return publicSnapshot{}, fail("E_PUBLIC_FEED", "Google public-feed response was not the verified JSON format.")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if e != nil || len(b) == 0 || len(b) > max {
		return publicSnapshot{}, fail("E_PUBLIC_FEED", "Google public-feed response was empty, unreadable or exceeded the size bound.")
	}
	return publicSnapshot{b, hash(b), publicExpiry(resp.Header, now).Format(time.RFC3339)}, nil
}

func (a *App) loadPublicCache() (publicCache, *keybox.PublicFeeds, time.Time, error) {
	var c publicCache
	if e := readJSON(filepath.Join(a.Root, "public-attestation.json"), &c); e != nil {
		return c, nil, time.Time{}, e
	}
	checked, e := time.Parse(time.RFC3339, c.CheckedAt)
	if e != nil || c.Schema != 1 || checked.After(a.Now().Add(time.Minute)) {
		return c, nil, time.Time{}, fail("E_PUBLIC_FEED", "Public-feed cache metadata is invalid; refresh it explicitly.")
	}
	var until time.Time
	for _, s := range []publicSnapshot{c.Roots, c.Status} {
		expiry, e := time.Parse(time.RFC3339, s.ExpiresAt)
		if e != nil || !validHash.MatchString(s.SHA256) || hash(s.Body) != s.SHA256 || expiry.After(checked.Add(24*time.Hour)) {
			return c, nil, time.Time{}, fail("E_PUBLIC_FEED", "Public-feed cache failed metadata or checksum checks; refresh it explicitly.")
		}
		if until.IsZero() || expiry.Before(until) {
			until = expiry
		}
	}
	f, e := keybox.ParsePublicFeeds(c.Roots.Body, c.Status.Body)
	if e != nil {
		return c, nil, time.Time{}, fail("E_PUBLIC_FEED", "Public-feed cache format is invalid or unsupported; no public trust verdict was issued.")
	}
	return c, f, until, nil
}

var publicLimitations = []string{
	"The complete Google public feeds are fetched over verified HTTPS; no private key, local certificate, serial or keybox is uploaded.",
	"The feeds have no documented detached signature. Cached bytes and timestamps are locally checked, not a signed offline CRL.",
	"A recognized Google root key and absence from this status snapshot do not establish genuine hardware, fresh attestation, issuer approval or Wallet acceptance.",
	"Private-input validation uses the helper's conservative date/chain profile. Historical factory-attestation exceptions are not silently applied to imported signer keys.",
}

func (a *App) publicTrustView() map[string]any {
	out := map[string]any{"available": false, "state": "no-cache", "sources": "Google public attestation roots and status over verified HTTPS", "keys": []keybox.PublicKeyCheck{}, "limitations": publicLimitations, "next_step": "Run an explicit Google public-feed refresh, then recheck the current chain locally."}
	c, f, until, e := a.loadPublicCache()
	if e != nil {
		if !os.IsNotExist(e) {
			out["state"] = "invalid"
			out["next_step"] = "Public evidence is invalid or unsupported. Refresh explicitly; current files were not changed."
		}
		return out
	}
	out["checked_at"], out["expires_at"] = c.CheckedAt, until.Format(time.RFC3339)
	out["roots_sha256"], out["status_sha256"] = c.Roots.SHA256, c.Status.SHA256
	if !a.Now().Before(until) {
		out["state"] = "stale"
		out["next_step"] = "Refresh the expired public-feed snapshot before interpreting status."
		return out
	}
	out["state"] = "fresh"
	b, e := bounded(filepath.Join(a.Active, "keybox.xml"), keybox.MaxInput)
	if e != nil {
		out["next_step"] = "Current keybox is unavailable; no public chain assessment was possible."
		return out
	}
	out["keybox_sha256"] = hash(b)
	d, e := keybox.Parse(b, a.Now())
	if e != nil {
		out["next_step"] = "Current input failed conservative local validation. Review its diagnostic before a public-chain assessment."
		return out
	}
	checks, e := d.CheckPublic(f)
	if e != nil {
		out["state"] = "invalid"
		return out
	}
	out["available"] = true
	out["keys"] = checks
	out["next_step"] = "Check current Wallet setup/security guidance and Play certification; public-chain checks do not prove payment readiness."
	for _, check := range checks {
		if check.Revocation == "listed-revoked" || check.Revocation == "listed-suspended" {
			out["next_step"] = "A local chain certificate is listed by Google. Preserve it and obtain authorized non-listed material before considering a replacement."
			break
		}
		if !check.GoogleRootKey {
			out["next_step"] = "The chain anchor does not match Google's published root keys. Local consistency does not establish Google trust."
		}
	}
	return out
}

func (a *App) Trust(action string) (any, error) {
	return a.withLock(func() (any, error) {
		if action == "" || action == "status" {
			return a.publicTrustView(), nil
		}
		if action != "refresh" {
			return nil, fail("E_REQUEST", "Trust actions are status or refresh.")
		}
		if a.Fake {
			return a.publicTrustView(), fail("E_CAPABILITY", "Network refresh is disabled in the fake-engine test backend.")
		}
		client, e := publicHTTPClient()
		if e != nil {
			return a.publicTrustView(), e
		}
		return a.refreshPublic(client)
	})
}

// The caller holds the operation lock. The unexported helper permits bounded
// synthetic HTTPS tests without exposing a client/URL override to CLI callers.
func (a *App) refreshPublic(client *http.Client) (any, error) {
	checked := a.Now().UTC()
	roots, e := fetchPublic(client, publicRootsURL, keybox.MaxPublicRoots, checked)
	if e != nil {
		return a.publicTrustView(), e
	}
	status, e := fetchPublic(client, publicStatusURL, keybox.MaxPublicStatus, a.Now().UTC())
	if e != nil {
		return a.publicTrustView(), e
	}
	if _, e = keybox.ParsePublicFeeds(roots.Body, status.Body); e != nil {
		return a.publicTrustView(), fail("E_PUBLIC_FEED", "Public JSON did not pass the verified schema. Existing evidence was preserved.")
	}
	c := publicCache{1, a.Now().UTC().Format(time.RFC3339), roots, status}
	if e = writeJSON(filepath.Join(a.Root, "public-attestation.json"), c); e != nil {
		return a.publicTrustView(), e
	}
	return a.publicTrustView(), nil
}

func (a *App) rejectPublicListed(d *keybox.Document) error {
	_, f, until, e := a.loadPublicCache()
	if e != nil || !a.Now().Before(until) {
		return nil
	} // Unknown remains explicit in plan evidence.
	checks, e := d.CheckPublic(f)
	if e != nil {
		return fail("E_VALIDATION", "Public-chain assessment failed; inspect diagnostics before Apply.")
	}
	for _, check := range checks {
		if check.Revocation == "listed-revoked" || check.Revocation == "listed-suspended" {
			return fail("E_VALIDATION", "Selected or retained chain includes a certificate listed by Google's fresh public status feed. No configuration was changed.")
		}
	}
	return nil
}

// Every reviewed plan binds public evidence too. Refreshing, corrupting or
// expiring it invalidates a plan before writes and at each write boundary.
// Ordinary planning/applying never fetches data in the background.
func (a *App) planCapabilities() (map[string]string, error) {
	out, e := a.capabilities()
	if e != nil {
		return nil, e
	}
	stackBinding, e := a.stackEvidenceBinding()
	if e != nil {
		return nil, e
	}
	out["stack_evidence_binding"] = stackBinding
	b, readErr := bounded(filepath.Join(a.Root, "public-attestation.json"), 4<<20)
	out["public_feed_snapshot"] = "absent"
	if readErr == nil {
		out["public_feed_snapshot"] = hash(b)
	} else if !os.IsNotExist(readErr) {
		out["public_feed_snapshot"] = "unreadable"
	}
	out["public_feed_state"] = "unknown"
	if _, _, until, loadErr := a.loadPublicCache(); loadErr == nil {
		out["public_feed_state"] = "stale"
		if a.Now().Before(until) {
			out["public_feed_state"] = "fresh"
		}
	}
	return out, nil
}
