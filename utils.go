package password

import (
	"crypto/rand"
	"math"
)

func mustUpdateSalt(salt string, entropy int) bool {
	clen := float64(len("RANDOM_STRING_CHARS"))
	return float64(len(salt))*math.Log2(clen) < float64(entropy)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
