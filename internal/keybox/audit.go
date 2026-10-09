package keybox

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

// Audit exposes structural inventory even when mandatory cryptographic validation
// fails. It never exposes PEM bytes, certificate identities or input metadata.
func Audit(data []byte, now time.Time) any {
	out := map[string]any{"structural_valid": false, "cryptographic_consistent": false, "trust": "unknown", "revocation": "unknown", "engine_adoption": "pending", "wallet_acceptance": "unverified", "algorithms": []string{}, "keyboxes": []any{}}
	root, e := parseXML(data)
	if e != nil {
		out["validation_error"] = e.Error()
		return out
	}
	doc, e := Parse(data, now)
	if e == nil {
		return doc.Summary()
	}
	out["validation_error"] = e.Error()
	// Only schema labels from the strict bounded XML parser are traversed.
	algos := []string{}
	boxes := []any{}
	for bi, b := range root.children {
		if b.name != "Keybox" {
			continue
		}
		keys := []any{}
		for ki, k := range b.children {
			if k.name != "Key" {
				continue
			}
			algo := k.attrs["algorithm"]
			if algo != "rsa" && algo != "ecdsa" {
				algo = "unsupported"
			}
			algos = append(algos, algo)
			entry := map[string]any{"index": ki, "algorithm": algo, "certificate_count": 0, "private_key_format": "unavailable"}
			for _, n := range k.children {
				if n.name == "PrivateKey" {
					s := strings.TrimSpace(n.text.String())
					entry["pem_begin_count"] = strings.Count(s, "-----BEGIN ")
					entry["pem_end_count"] = strings.Count(s, "-----END ")
					entry["pem_lines"] = len(strings.Split(s, "\n"))
					entry["literal_backslash_n"] = strings.Contains(s, `\n`)
					indented := false
					for _, line := range strings.Split(s, "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), "-----") && strings.HasPrefix(line, " ") {
							indented = true
						}
					}
					entry["indented_boundary"] = indented
					for _, label := range []string{"EC PRIVATE KEY", "RSA PRIVATE KEY", "PRIVATE KEY"} {
						if strings.HasPrefix(s, "-----BEGIN "+label+"-----") {
							entry["private_key_format"] = label
						}
					}
				}
				if n.name == "CertificateChain" {
					count := 0
					certs := []any{}
					for _, c := range n.children {
						if c.name == "Certificate" {
							count++
							if p, e := completePEM(c.text.String(), false); e == nil && p.Type == "CERTIFICATE" {
								if cert, e := x509.ParseCertificate(p.Bytes); e == nil {
									validity := "valid-at-collection"
									if now.Before(cert.NotBefore) {
										validity = "not-yet-valid"
									}
									if now.After(cert.NotAfter) {
										validity = "expired"
									}
									digest := sha256.Sum256(cert.Raw)
									certs = append(certs, map[string]any{"index": count - 1, "validity": validity, "not_before": cert.NotBefore.UTC().Format(time.RFC3339), "not_after": cert.NotAfter.UTC().Format(time.RFC3339), "sha256": hex.EncodeToString(digest[:]), "placeholder_indicator": placeholder(cert.Subject.CommonName) || placeholder(cert.Issuer.CommonName)})
								}
							}
						}
					}
					entry["certificate_count"] = count
					entry["certificates"] = certs
				}
			}
			keys = append(keys, entry)
		}
		boxes = append(boxes, map[string]any{"index": bi - 1, "keys": keys})
	}
	out["algorithms"] = algos
	out["keyboxes"] = boxes
	out["structural_inventory_only"] = true
	return out
}
