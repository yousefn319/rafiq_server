package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Token[T any] struct {
	Header Header
	Claims T
}

var ErrUnsupportedSig = errors.New("unsupported signature scheme")
var ErrUnsupportedType = errors.New("unsupported jwt type")
var ErrSigMismatch = errors.New("signature doesn't match")
var ErrTokenMalformed = errors.New("token contains an invalid number of segments")
var ErrTokenExpired = errors.New("token expired")

var urlEncoding = base64.RawURLEncoding

func StrictUnmarshal[T any](data []byte, v *T) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func Parse[T any](tokenString string, secret []byte) (*Token[T], error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	headerBytes, err1 := urlEncoding.DecodeString(parts[0])
	payloadBytes, err2 := urlEncoding.DecodeString(parts[1])
	signature, err3 := urlEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.Join(err1, err2, err3)
	}

	var header Header
	var payload T
	err1 = StrictUnmarshal(headerBytes, &header)
	err2 = StrictUnmarshal(payloadBytes, &payload)
	if err1 != nil || err2 != nil {
		return nil, errors.Join(err1, err2)
	}

	if header.Algorithm != "HS256" {
		return nil, ErrUnsupportedSig
	}
	if header.Type != "JWT" {
		return nil, ErrUnsupportedType
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	mac.Write([]byte("."))
	mac.Write([]byte(parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, ErrSigMismatch
	}

	return &Token[T]{header, payload}, nil
}

func Create[T any](claims T, secret []byte) ([]byte, error) {
	header := Header{
		Algorithm: "HS256",
		Type:      "JWT",
	}
	headerBytes, err1 := json.Marshal(header)
	claimsBytes, err2 := json.Marshal(claims)
	if err1 != nil || err2 != nil {
		return nil, errors.Join(err1, err2)
	}

	header64 := make([]byte, urlEncoding.EncodedLen(len(headerBytes)))
	claims64 := make([]byte, urlEncoding.EncodedLen(len(claimsBytes)))
	urlEncoding.Encode(header64, headerBytes)
	urlEncoding.Encode(claims64, claimsBytes)

	mac := hmac.New(sha256.New, secret)
	mac.Write(header64)
	mac.Write([]byte("."))
	mac.Write(claims64)
	signatureBytes := mac.Sum(nil)

	signature64 := make([]byte, urlEncoding.EncodedLen(len(signatureBytes)))
	urlEncoding.Encode(signature64, signatureBytes)

	return slices.Concat(header64, []byte("."), claims64, []byte("."), signature64), nil
}
