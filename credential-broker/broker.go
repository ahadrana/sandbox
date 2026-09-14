// Package credentialbroker issues short-lived, scoped, HMAC-signed
// credential tokens (PLAN §12, FR-SEC-003). Tokens are verifiable offline,
// expiring, and revocable. Issuance, use, and revocation are audited by
// token ID — the token VALUE is never written to any audit record.
package credentialbroker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/network"
)

var (
	ErrBadSignature = errors.New("credential signature invalid")
	ErrExpired      = errors.New("credential expired")
	ErrRevoked      = errors.New("credential revoked")
	ErrMalformed    = errors.New("credential malformed")
)

// Claims is the signed token payload.
type Claims struct {
	TokenID      string    `json:"token_id"`
	TenantID     string    `json:"tenant_id"`
	TaskRef      string    `json:"task_ref"`
	Capabilities []string  `json:"capabilities"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Broker signs and verifies tokens with an HMAC key and tracks revocations.
type Broker struct {
	mu      sync.Mutex
	key     []byte
	nextID  int
	revoked map[string]bool
	audit   *network.AuditLog
}

// New creates a broker; auditPath "" means memory-only auditing.
func New(key []byte, auditPath string) (*Broker, error) {
	if len(key) == 0 {
		return nil, errors.New("broker key required")
	}
	audit, err := network.NewAuditLog(auditPath)
	if err != nil {
		return nil, err
	}
	return &Broker{key: key, revoked: map[string]bool{}, audit: audit}, nil
}

func (b *Broker) sign(payload []byte) string {
	mac := hmac.New(sha256.New, b.key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Issue mints a token scoped to tenant/task with capabilities and TTL.
func (b *Broker) Issue(tenantID, taskRef string, capabilities []string, ttl time.Duration, now time.Time) (string, Claims, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	claims := Claims{
		TokenID:      fmt.Sprintf("tok-%d", b.nextID),
		TenantID:     tenantID,
		TaskRef:      taskRef,
		Capabilities: append([]string{}, capabilities...),
		ExpiresAt:    now.Add(ttl),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + b.sign(payload)
	b.audit.Record("issue", claims.TokenID, fmt.Sprintf("tenant=%s task=%s caps=%v expires=%s", tenantID, taskRef, capabilities, claims.ExpiresAt), now)
	return token, claims, nil
}

// Verify checks signature, expiry, and revocation.
func (b *Broker) Verify(token string, now time.Time) (Claims, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	parts := 0
	var payloadB64, sig string
	for i, c := range token {
		if c == '.' {
			payloadB64, sig, parts = token[:i], token[i+1:], 1
			break
		}
	}
	if parts == 0 || payloadB64 == "" || sig == "" {
		return Claims{}, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if !hmac.Equal([]byte(sig), []byte(b.sign(payload))) {
		return Claims{}, ErrBadSignature
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrMalformed
	}
	if now.After(claims.ExpiresAt) {
		b.audit.Record("use", claims.TokenID, "denied: expired", now)
		return Claims{}, ErrExpired
	}
	if b.revoked[claims.TokenID] {
		b.audit.Record("use", claims.TokenID, "denied: revoked", now)
		return Claims{}, ErrRevoked
	}
	b.audit.Record("use", claims.TokenID, "verified", now)
	return claims, nil
}

// Revoke adds a token ID to the revocation list.
func (b *Broker) Revoke(tokenID string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked[tokenID] = true
	b.audit.Record("revoke", tokenID, "revoked", now)
}

// AuditEntries returns the broker audit trail (token IDs, never values).
func (b *Broker) AuditEntries() []network.AuditEntry {
	return b.audit.Entries()
}
