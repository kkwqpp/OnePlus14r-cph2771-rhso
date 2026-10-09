package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"walletdiagnostic/internal/keybox"
)

// Network tests use a local, authenticated TLS server only. DialContext maps
// the fixed public host to its loopback listener; neither DNS nor Google is
// contacted. Synthetic keyboxes come from core_test.go, never device files.
func mappedPublicTLSClient(t *testing.T, handler http.Handler) (*http.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := publicHTTPClient()
	if err != nil {
		t.Fatal("public client construction failed")
	}
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport.TLSClientConfig.RootCAs = pool
	transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "android.googleapis.com:443" {
			return nil, errors.New("synthetic-private-network-sentinel")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return client, server
}

func TestPublicExpiryConservativeResponseAge(t *testing.T) {
	now := coreTestNow
	base := func() http.Header { return http.Header{"Date": []string{now.Format(http.TimeFormat)}} }
	cases := []struct {
		name string
		set  func(http.Header)
		ttl  time.Duration
	}{
		{"no_lifetime", func(h http.Header) {}, 0},
		{"public_only", func(h http.Header) { h.Set("Cache-Control", "public") }, 0},
		{"fresh_max_age", func(h http.Header) { h.Set("Cache-Control", "public, max-age=3600") }, time.Hour},
		{"quoted_max_age", func(h http.Header) { h.Set("Cache-Control", `max-age="3600"`) }, time.Hour},
		{"intermediary_age", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "1200") }, 40 * time.Minute},
		{"apparent_age", func(h http.Header) {
			h.Set("Cache-Control", "max-age=3600")
			h.Set("Date", now.Add(-10*time.Minute).Format(http.TimeFormat))
		}, 50 * time.Minute},
		{"max_of_ages", func(h http.Header) {
			h.Set("Cache-Control", "max-age=3600")
			h.Set("Date", now.Add(-10*time.Minute).Format(http.TimeFormat))
			h.Set("Age", "1200")
		}, 40 * time.Minute},
		{"already_old", func(h http.Header) {
			h.Set("Cache-Control", "max-age=3600")
			h.Set("Date", now.Add(-2*time.Hour).Format(http.TimeFormat))
		}, 0},
		{"zero_lifetime", func(h http.Header) { h.Set("Cache-Control", "max-age=0") }, 0},
		{"age_exhausted", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "3600") }, 0},
		{"age_over_lifetime", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "7200") }, 0},
		{"cap_one_day", func(h http.Header) { h.Set("Cache-Control", "max-age=999999"); h.Set("Age", "60") }, 24*time.Hour - time.Minute},
		{"no_cache", func(h http.Header) { h.Set("Cache-Control", "max-age=3600,no-cache") }, 0},
		{"no_store", func(h http.Header) { h.Set("Cache-Control", "max-age=3600,no-store") }, 0},
		{"field_no_cache", func(h http.Header) { h.Set("Cache-Control", `max-age=3600,no-cache="Set-Cookie"`) }, 0},
		{"second_header_no_cache", func(h http.Header) { h.Add("Cache-Control", "max-age=3600"); h.Add("Cache-Control", "no-cache") }, 0},
		{"second_header_no_store", func(h http.Header) { h.Add("Cache-Control", "max-age=3600"); h.Add("Cache-Control", "no-store") }, 0},
		{"duplicate_max_age", func(h http.Header) { h.Add("Cache-Control", "max-age=3600"); h.Add("Cache-Control", "max-age=3600") }, 0},
		{"negative_max_age", func(h http.Header) { h.Set("Cache-Control", "max-age=-1") }, 0},
		{"signed_max_age", func(h http.Header) { h.Set("Cache-Control", "max-age=+3600") }, 0},
		{"bad_max_age", func(h http.Header) { h.Set("Cache-Control", "max-age=private-sentinel") }, 0},
		{"overflow_max_age", func(h http.Header) { h.Set("Cache-Control", "max-age=999999999999999999999999999") }, 0},
		{"unbalanced_quote", func(h http.Header) { h.Set("Cache-Control", `max-age="3600`) }, 0},
		{"negative_age", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "-1") }, 0},
		{"empty_age", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "") }, 0},
		{"signed_age", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "+1") }, 0},
		{"bad_age", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Set("Age", "private-sentinel") }, 0},
		{"duplicate_age", func(h http.Header) { h.Set("Cache-Control", "max-age=3600"); h.Add("Age", "0"); h.Add("Age", "0") }, 0},
		{"duplicate_date", func(h http.Header) {
			h.Set("Cache-Control", "max-age=3600")
			h.Add("Date", now.Format(http.TimeFormat))
		}, 0},
		{"missing_date", func(h http.Header) { h.Del("Date"); h.Set("Cache-Control", "max-age=3600") }, 0},
		{"invalid_date", func(h http.Header) { h.Set("Date", "private-sentinel"); h.Set("Cache-Control", "max-age=3600") }, 0},
		{"future_date_too_far", func(h http.Header) {
			h.Set("Date", now.Add(6*time.Minute).Format(http.TimeFormat))
			h.Set("Cache-Control", "max-age=3600")
		}, 0},
		{"expires_only", func(h http.Header) { h.Set("Expires", now.Add(time.Hour).Format(http.TimeFormat)) }, time.Hour},
		{"expires_with_age", func(h http.Header) { h.Set("Expires", now.Add(time.Hour).Format(http.TimeFormat)); h.Set("Age", "600") }, 50 * time.Minute},
		{"expires_older_date", func(h http.Header) {
			h.Set("Date", now.Add(-time.Minute).Format(http.TimeFormat))
			h.Set("Expires", now.Add(50*time.Minute).Format(http.TimeFormat))
			h.Set("Age", "600")
		}, 41 * time.Minute},
		{"expires_limits_max_age", func(h http.Header) {
			h.Set("Cache-Control", "max-age=3600")
			h.Set("Expires", now.Add(30*time.Minute).Format(http.TimeFormat))
			h.Set("Age", "600")
		}, 20 * time.Minute},
		{"expired_expires", func(h http.Header) { h.Set("Expires", now.Add(-time.Second).Format(http.TimeFormat)) }, 0},
		{"invalid_expires_without_lifetime", func(h http.Header) { h.Set("Expires", "private-sentinel") }, 0},
		{"duplicate_expires", func(h http.Header) {
			h.Add("Expires", now.Add(time.Hour).Format(http.TimeFormat))
			h.Add("Expires", now.Add(-time.Hour).Format(http.TimeFormat))
		}, 0},
		{"shared_only_lifetime", func(h http.Header) { h.Set("Cache-Control", "s-maxage=3600") }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := base()
			tc.set(h)
			until := publicExpiry(h, now)
			if tc.ttl == 0 {
				if until.After(now) {
					t.Fatal("unsupported or stale freshness produced a future deadline")
				}
			} else if !until.Equal(now.Add(tc.ttl)) {
				t.Fatalf("public cache lifetime got %v, want %v", until.Sub(now), tc.ttl)
			}
		})
	}
}

func TestFetchPublicFixedEndpointPrivateRequest(t *testing.T) {
	var calls atomic.Int32
	body := []byte(`{"entries":{}}`)
	client, _ := mappedPublicTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Host != "android.googleapis.com" || r.URL.RawQuery != "" || r.URL.Fragment != "" || (r.URL.Path != "/attestation/root" && r.URL.Path != "/attestation/status") {
			t.Error("public request changed fixed endpoint or method")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 || len(r.Cookies()) != 0 {
			t.Error("public request carried credentials, cookies or body")
		}
		data, _ := io.ReadAll(r.Body)
		if len(data) != 0 || r.Header.Get("Accept") != "application/json" {
			t.Error("public request did not contain only the public GET contract")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Date", coreTestNow.Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Set-Cookie", "private-cookie-sentinel=value")
		_, _ = w.Write(body)
	}))
	if client.Jar != nil {
		t.Fatal("public client unexpectedly retains cookies")
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.Proxy != nil || client.Timeout <= 0 || transport.ResponseHeaderTimeout <= 0 || transport.MaxResponseHeaderBytes <= 0 {
		t.Fatal("public client lost TLS verification, bounds or proxy isolation")
	}
	for _, endpoint := range []string{publicRootsURL, publicStatusURL} {
		snapshot, err := fetchPublic(client, endpoint, len(body), coreTestNow)
		if err != nil || !bytes.Equal(snapshot.Body, body) || snapshot.SHA256 != hash(body) || snapshot.ExpiresAt != coreTestNow.Add(time.Hour).Format(time.RFC3339) {
			t.Fatal("bounded public response was not preserved with correct freshness")
		}
	}
	for _, endpoint := range []string{"http://android.googleapis.com/attestation/root", publicStatusURL + "?serial=private-network-sentinel", "https://evil.invalid/attestation/root", publicRootsURL + "/", publicRootsURL + "#private-network-sentinel"} {
		snapshot, err := fetchPublic(client, endpoint, len(body), coreTestNow)
		assertPublicFetchError(t, snapshot, err)
	}
	if calls.Load() != 2 {
		t.Fatal("unsupported endpoint reached the network or request was retried")
	}
}

func TestFetchPublicFailuresAreBoundedAndRedacted(t *testing.T) {
	cases := []struct {
		name   string
		status int
		mime   string
		body   string
		max    int
	}{
		{"unauthorized", 401, "application/json", "private-network-sentinel", 32},
		{"server_error", 503, "application/json", "private-network-sentinel", 32},
		{"redirect", 302, "application/json", "private-network-sentinel", 32},
		{"html", 200, "text/html", "private-network-sentinel", 32},
		{"wrong_json_mime", 200, "application/problem+json", "private-network-sentinel", 32},
		{"missing_mime", 200, "", "private-network-sentinel", 32},
		{"malformed_mime", 200, "application/json;invalid", "private-network-sentinel", 32},
		{"empty_body", 200, "application/json", "", 32},
		{"oversized_body", 200, "application/json", strings.Repeat("private-network-sentinel", 10), 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			client, _ := mappedPublicTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.mime)
				w.Header().Set("Location", "https://evil.invalid/private-network-sentinel")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			snapshot, err := fetchPublic(client, publicStatusURL, tc.max, coreTestNow)
			assertPublicFetchError(t, snapshot, err)
			if calls.Load() != 1 {
				t.Fatal("failed public request redirected or retried")
			}
		})
	}
	t.Run("untrusted_tls", func(t *testing.T) {
		client, _ := mappedPublicTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS request reached HTTP handler") }))
		client.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
		snapshot, err := fetchPublic(client, publicRootsURL, 128, coreTestNow)
		assertPublicFetchError(t, snapshot, err, "E_PUBLIC_TLS")
	})
	t.Run("truncated_body", func(t *testing.T) {
		client, _ := mappedPublicTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte("private-network-sentinel"))
		}))
		snapshot, err := fetchPublic(client, publicStatusURL, 2048, coreTestNow)
		assertPublicFetchError(t, snapshot, err)
	})
	t.Run("read_failure", func(t *testing.T) {
		client := &http.Client{Transport: publicRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: publicFailedReader{}}, nil
		})}
		snapshot, err := fetchPublic(client, publicStatusURL, 128, coreTestNow)
		assertPublicFetchError(t, snapshot, err)
	})
	t.Run("sanitized_dns_failure", func(t *testing.T) {
		client := &http.Client{Transport: publicRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "private-network-sentinel", Name: "private-network-sentinel.invalid", IsNotFound: true}
		})}
		snapshot, err := fetchPublic(client, publicStatusURL, 128, coreTestNow)
		assertPublicFetchError(t, snapshot, err, "E_PUBLIC_DNS")
	})
	t.Run("request_timeout", func(t *testing.T) {
		client := &http.Client{Timeout: 20 * time.Millisecond, Transport: publicRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		snapshot, err := fetchPublic(client, publicStatusURL, 128, coreTestNow)
		assertPublicFetchError(t, snapshot, err)
	})
	t.Run("bounded_stream", func(t *testing.T) {
		reader := &publicCountingReader{}
		client := &http.Client{Transport: publicRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: reader}, nil
		})}
		snapshot, err := fetchPublic(client, publicStatusURL, 1024, coreTestNow)
		assertPublicFetchError(t, snapshot, err)
		if reader.total != 1025 || !reader.closed {
			t.Fatal("oversized public stream was not bounded or closed")
		}
	})
}

type publicRoundTripFunc func(*http.Request) (*http.Response, error)

func (f publicRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type publicFailedReader struct{}

func (publicFailedReader) Read([]byte) (int, error) { return 0, errors.New("private-network-sentinel") }
func (publicFailedReader) Close() error             { return nil }

type publicCountingReader struct {
	total  int
	closed bool
}

func (r *publicCountingReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 'x'
	}
	r.total += len(b)
	return len(b), nil
}
func (r *publicCountingReader) Close() error { r.closed = true; return nil }

func assertPublicFetchError(t *testing.T, snapshot publicSnapshot, err error, expected ...string) {
	t.Helper()
	code := "E_PUBLIC_FEED"
	if len(expected) != 0 {
		code = expected[0]
	}
	requireCode(t, err, code)
	if len(snapshot.Body) != 0 || snapshot.SHA256 != "" || snapshot.ExpiresAt != "" {
		t.Fatal("failed acquisition returned partial accepted evidence")
	}
	body, marshalErr := json.Marshal(Response(nil, err))
	if marshalErr != nil || bytes.Contains(body, []byte("private-network-sentinel")) || bytes.Contains(body, []byte("evil.invalid")) || bytes.Contains(body, []byte("BEGIN")) {
		t.Fatal("public acquisition error exposed upstream or private data")
	}
}

func syntheticPublicCache(t *testing.T, fixture []byte) publicCache {
	t.Helper()
	var parsed struct {
		Boxes []struct {
			Keys []struct {
				Chain struct {
					Certificates []string `xml:"Certificate"`
				} `xml:"CertificateChain"`
			} `xml:"Key"`
		} `xml:"Keybox"`
	}
	if err := xml.Unmarshal(fixture, &parsed); err != nil || len(parsed.Boxes) == 0 || len(parsed.Boxes[0].Keys) == 0 {
		t.Fatal("synthetic public-catalog extraction failed")
	}
	certs := parsed.Boxes[0].Keys[0].Chain.Certificates
	roots, err := json.Marshal([]string{certs[len(certs)-1]})
	if err != nil {
		t.Fatal("synthetic public catalog encoding failed")
	}
	status := []byte(`{"entries":{}}`)
	return publicCache{Schema: 1, CheckedAt: coreTestNow.Format(time.RFC3339), Roots: publicSnapshot{Body: roots, SHA256: hash(roots), ExpiresAt: coreTestNow.Add(2 * time.Hour).Format(time.RFC3339)}, Status: publicSnapshot{Body: status, SHA256: hash(status), ExpiresAt: coreTestNow.Add(time.Hour).Format(time.RFC3339)}}
}

func saveSyntheticPublicCache(t *testing.T, app *App, cache publicCache) []byte {
	t.Helper()
	if err := writeJSON(filepath.Join(app.Root, "public-attestation.json"), cache); err != nil {
		t.Fatal("synthetic cache write failed")
	}
	body, err := os.ReadFile(filepath.Join(app.Root, "public-attestation.json"))
	if err != nil {
		t.Fatal("synthetic cache read failed")
	}
	return body
}

func TestPublicCacheFreshnessAndViewsRemainRedacted(t *testing.T) {
	fixture := syntheticKeybox(t)
	s := newSandbox(t, fixture)
	if view := s.app.publicTrustView(); view["state"] != "no-cache" || view["available"] != false {
		t.Fatal("missing public evidence was presented as available")
	}
	cache := syntheticPublicCache(t, fixture)
	cacheBytes := saveSyntheticPublicCache(t, s.app, cache)
	loaded, feed, until, err := s.app.loadPublicCache()
	if err != nil || feed == nil || loaded.Schema != 1 || !until.Equal(coreTestNow.Add(time.Hour)) {
		t.Fatal("valid public cache did not use the earlier independent feed deadline")
	}
	view := s.app.publicTrustView()
	if view["state"] != "fresh" || view["available"] != true || view["expires_at"] != cache.Status.ExpiresAt {
		t.Fatal("fresh evidence was not available")
	}
	checks := view["keys"].([]keybox.PublicKeyCheck)
	if len(checks) != 2 || !checks[0].GoogleRootKey || !checks[1].GoogleRootKey || checks[0].Revocation != "not-listed-as-of-feed" {
		t.Fatal("synthetic public-chain assessment was incorrect")
	}
	assertPublicViewRedacted(t, view)
	result, err := s.app.Trust("status")
	if err != nil {
		t.Fatal("read-only trust status failed")
	}
	assertPublicViewRedacted(t, Response(result, nil))
	result, err = s.app.Trust("refresh")
	requireCode(t, err, "E_CAPABILITY")
	assertPublicViewRedacted(t, Response(result, err))
	after, err := os.ReadFile(filepath.Join(s.app.Root, "public-attestation.json"))
	if err != nil || !bytes.Equal(after, cacheBytes) {
		t.Fatal("fake-engine refresh modified public evidence")
	}
	requireSnapshot(t, s.app, s.old)
	s.app.Now = func() time.Time { return coreTestNow.Add(time.Hour) }
	view = s.app.publicTrustView()
	if view["state"] != "stale" || view["available"] != false || len(view["keys"].([]keybox.PublicKeyCheck)) != 0 {
		t.Fatal("expired public evidence was interpreted as a current verdict")
	}
	assertPublicViewRedacted(t, view)
	s.app.Now = func() time.Time { return coreTestNow.Add(-2 * time.Minute) }
	if view := s.app.publicTrustView(); view["state"] != "invalid" || view["available"] != false {
		t.Fatal("clock rollback accepted a future acquisition timestamp")
	}
}

func TestPublicCacheCorruptionAndSchemaFailClosed(t *testing.T) {
	fixture := syntheticKeybox(t)
	cache := syntheticPublicCache(t, fixture)
	cases := []struct {
		name   string
		mutate func(*publicCache)
	}{
		{"version", func(c *publicCache) { c.Schema = 2 }},
		{"checked_invalid", func(c *publicCache) { c.CheckedAt = "private-network-sentinel" }},
		{"checked_future", func(c *publicCache) { c.CheckedAt = coreTestNow.Add(2 * time.Minute).Format(time.RFC3339) }},
		{"bad_checksum", func(c *publicCache) { c.Status.SHA256 = strings.Repeat("f", 64) }},
		{"invalid_checksum_format", func(c *publicCache) { c.Roots.SHA256 = "private-network-sentinel" }},
		{"root_body_corrupt", func(c *publicCache) { c.Roots.Body = []byte("private-network-sentinel") }},
		{"status_body_corrupt", func(c *publicCache) { c.Status.Body = []byte("private-network-sentinel") }},
		{"root_schema", func(c *publicCache) { c.Roots.Body = []byte(`[]`); c.Roots.SHA256 = hash(c.Roots.Body) }},
		{"status_schema", func(c *publicCache) {
			c.Status.Body = []byte(`{"entries":{"a":{"status":"VALID"}}}`)
			c.Status.SHA256 = hash(c.Status.Body)
		}},
		{"expiry_invalid", func(c *publicCache) { c.Status.ExpiresAt = "private-network-sentinel" }},
		{"expiry_beyond_cap", func(c *publicCache) {
			c.Roots.ExpiresAt = coreTestNow.Add(24*time.Hour + time.Second).Format(time.RFC3339)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t, fixture)
			c := cache
			tc.mutate(&c)
			original := saveSyntheticPublicCache(t, s.app, c)
			_, feed, _, err := s.app.loadPublicCache()
			if err == nil || feed != nil {
				t.Fatal("corrupt public cache produced a parsed feed")
			}
			view := s.app.publicTrustView()
			if view["state"] != "invalid" || view["available"] != false || len(view["keys"].([]keybox.PublicKeyCheck)) != 0 {
				t.Fatal("invalid public evidence produced a trust result")
			}
			assertPublicViewRedacted(t, Response(view, err))
			after, err := os.ReadFile(filepath.Join(s.app.Root, "public-attestation.json"))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("read-only invalid-cache inspection changed evidence")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
}

func TestPublicRefreshAtomicEvidencePreservation(t *testing.T) {
	fixture := syntheticKeybox(t)
	base := syntheticPublicCache(t, fixture)
	newStatus := []byte(`{"entries":{"1":{"status":"SUSPENDED","comment":"private-network-sentinel"}}}`)
	for _, mode := range []string{"success", "roots-error", "status-error", "bad-schema", "bad-mime", "no-store"} {
		t.Run(mode, func(t *testing.T) {
			s := newSandbox(t, fixture)
			original := saveSyntheticPublicCache(t, s.app, base)
			var calls atomic.Int32
			client, _ := mappedPublicTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Date", coreTestNow.Format(http.TimeFormat))
				w.Header().Set("Cache-Control", "max-age=3600")
				if r.URL.Path == "/attestation/root" {
					w.Header().Set("Set-Cookie", "private-cookie-sentinel=value")
					if mode == "roots-error" {
						w.WriteHeader(503)
						_, _ = w.Write([]byte("private-network-sentinel"))
						return
					}
					_, _ = w.Write(base.Roots.Body)
					return
				}
				if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
					t.Error("refresh uploaded credentials, cookie or body")
				}
				w.Header().Set("Age", "1200")
				switch mode {
				case "status-error":
					w.WriteHeader(503)
					_, _ = w.Write([]byte("private-network-sentinel"))
					return
				case "bad-schema":
					_, _ = w.Write([]byte(`{"entries":{"a":{"status":"private-network-sentinel"}}}`))
					return
				case "bad-mime":
					w.Header().Set("Content-Type", "text/html")
				case "no-store":
					w.Header().Set("Cache-Control", "max-age=3600,no-store")
				}
				_, _ = w.Write(newStatus)
			}))
			result, err := s.app.withLock(func() (any, error) { return s.app.refreshPublic(client) })
			assertPublicViewRedacted(t, Response(result, err))
			after, readErr := os.ReadFile(filepath.Join(s.app.Root, "public-attestation.json"))
			if readErr != nil {
				t.Fatal("refresh evidence disappeared")
			}
			if mode == "success" {
				if err != nil || bytes.Equal(original, after) {
					t.Fatal("verified refresh did not replace cache")
				}
				loaded, _, until, err := s.app.loadPublicCache()
				if err != nil || !bytes.Equal(loaded.Status.Body, newStatus) || loaded.Status.SHA256 != hash(newStatus) || !until.Equal(coreTestNow.Add(40*time.Minute)) {
					t.Fatal("successful refresh lost source bytes or independent response age")
				}
				view := result.(map[string]any)
				if view["available"] != true || view["state"] != "fresh" {
					t.Fatal("success did not return fresh redacted assessment")
				}
				for _, check := range view["keys"].([]keybox.PublicKeyCheck) {
					if check.Revocation != "listed-suspended" {
						t.Fatal("refreshed suspension was hidden")
					}
				}
			} else {
				requireCode(t, err, "E_PUBLIC_FEED")
				if !bytes.Equal(original, after) {
					t.Fatal("failed or non-cacheable refresh overwrote existing evidence")
				}
				view := result.(map[string]any)
				if view["state"] != "fresh" || view["available"] != true || view["status_sha256"] != base.Status.SHA256 {
					t.Fatal("failed refresh discarded still-fresh prior evidence")
				}
			}
			wantCalls := int32(2)
			if mode == "roots-error" {
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Fatal("refresh retried, skipped a required feed or followed another endpoint")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
}

func TestPublicViewSeparatesSourceFreshnessFromInputAssessment(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, mode := range []string{"missing-active", "invalid-active", "unknown-anchor", "listed-revoked", "listed-suspended"} {
		t.Run(mode, func(t *testing.T) {
			s := newSandbox(t, fixture)
			cache := syntheticPublicCache(t, fixture)
			switch mode {
			case "missing-active":
				if err := os.Remove(filepath.Join(s.app.Active, "keybox.xml")); err != nil {
					t.Fatal("synthetic active removal failed")
				}
			case "invalid-active":
				testWrite(t, filepath.Join(s.app.Active, "keybox.xml"), []byte("private-network-sentinel"))
			case "unknown-anchor":
				cache.Roots = syntheticPublicCache(t, syntheticKeybox(t)).Roots
			case "listed-revoked", "listed-suspended":
				state := "REVOKED"
				if mode == "listed-suspended" {
					state = "SUSPENDED"
				}
				cache.Status.Body = []byte(`{"entries":{"1":{"status":"` + state + `","comment":"private-network-sentinel"}}}`)
				cache.Status.SHA256 = hash(cache.Status.Body)
			}
			saveSyntheticPublicCache(t, s.app, cache)
			view := s.app.publicTrustView()
			if view["state"] != "fresh" {
				t.Fatal("input problem obscured independent public-feed freshness")
			}
			if mode == "missing-active" || mode == "invalid-active" {
				if view["available"] != false || len(view["keys"].([]keybox.PublicKeyCheck)) != 0 {
					t.Fatal("unvalidated input received a public-chain result")
				}
			} else {
				checks := view["keys"].([]keybox.PublicKeyCheck)
				if view["available"] != true || len(checks) != 2 {
					t.Fatal("valid synthetic inputs were not assessed")
				}
				for _, check := range checks {
					if mode == "unknown-anchor" && (check.GoogleRootKey || check.Revocation != "unknown") {
						t.Fatal("unknown anchor confused with Google trust")
					}
					if mode != "unknown-anchor" && (check.Revocation != mode || check.ListedCertificateCount != 1) {
						t.Fatal("public listing was lost in redacted view")
					}
				}
			}
			assertPublicViewRedacted(t, view)
		})
	}
}

func assertPublicViewRedacted(t *testing.T, value any) {
	t.Helper()
	requireRedacted(t, value)
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("public view encoding failed")
	}
	for _, forbidden := range []string{"private-network-sentinel", "synthetic-sensitive-", "-----BEGIN", "\"serial\"", "\"subject\"", "\"hardware_valid\":true", "\"wallet_passed\":true"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatal("public view exposed input identity or manufactured acceptance proof")
		}
	}
}
