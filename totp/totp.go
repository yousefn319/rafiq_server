package totp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"time"
)

const Digits = 6
const nsts = 1000000000
func Generate(secret []byte, t time.Time, d time.Duration) int {
	counter := uint64(math.Floor(float64(t.Unix()) / float64(d/nsts)))

	mac := hmac.New(sha256.New, secret)
	binary.Write(mac, binary.BigEndian, counter)

	sum := mac.Sum(nil)

	// "Dynamic truncation" in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := ((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff)

	return value % int(math.Pow10(Digits))
}

func Validate(secret []byte, t time.Time, d time.Duration, code int) bool {
	return code == Generate(secret, t, d)
}

func Format(code int) string {
	if code >= int(math.Pow10(Digits)) {
		fmt.Fprintln(os.Stderr, "What the fuck?", code)
		return ""
	}
	return fmt.Sprintf("%06d", code)
}
