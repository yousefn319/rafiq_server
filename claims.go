package main

import (
	"encoding/json"
	"time"
)

type BaseClaims struct {
	ID        int       `db:"id" json:"jti"`
	Issuer    string    `db:"-" json:"iss"`
	IssuedAt  time.Time `db:"updated_at" json:"iat"`
	ExpiresAt time.Time `db:"expires_at" json:"exp"`
}

func (claim *BaseClaims) Verify() bool {
	return time.Now().Before(claim.ExpiresAt)
}

type SessionClaims struct {
	UserID int64 `json:"user_id"`
	BaseClaims
}

type MFAClaims struct {
	Secret      []byte          `db:"secret" json:"-"`
	Duration    time.Duration   `db:"duration" json:"-"`
	UserID      int64           `db:"user_id" json:"user_id"`
	RequestType string          `db:"request_type" json:"-"`
	Request     json.RawMessage `db:"request" json:"-"`
	BaseClaims
}
