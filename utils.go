package password

import (
	"crypto/rand"
	"math"
)

const randomChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func mustUpdateSalt(salt string, entropy int) bool {
	clen := float64(len(randomChars))
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
