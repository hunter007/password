package passwordvalidator

import "math"

func mustUpdateSalt(salt string, entropy int) bool {
	clen := float64(len("RANDOM_STRING_CHARS"))
	return float64(len(salt))*math.Log2(clen) < float64(entropy)
}
