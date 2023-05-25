package passwordvalidator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	algo string
}

func (hasher *bcryptHasher) Encode(password string) (string, error) {
	return hasher.encode(password, hasher.algo, bcrypt.DefaultCost)
}

func (hasher *bcryptHasher) encode(password, algo string, cost int) (string, error) {
	var data []byte
	if algo == bcryptSha256Algo {
		d := sha256.Sum256([]byte(password))
		data = d[:]
	} else {
		data = []byte(password)
	}

	hash, err := bcrypt.GenerateFromPassword(data, cost)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s%s", algo, sep, hex.EncodeToString(hash)), nil
}

func (hasher *bcryptHasher) Decode(decoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(decoded, sep, 2)
	if parts[0] != bcryptSha256Algo && parts[0] != bcryptAlgo {
		return nil, errUnknownAlgorithm
	}

	b, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, errUnknownAlgorithm
	}

	cost, err := bcrypt.Cost(b)
	if err != nil {
		return nil, errUnknownAlgorithm
	}

	return &PasswordInfo{
		Algorithm:  parts[0],
		Hash:       parts[1],
		Iterations: cost,
	}, nil
}

func (hasher *bcryptHasher) Verify(password, encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}

	encoded2, err := hasher.encode(password, pi.Algorithm, pi.Iterations)
	if err != nil {
		return false
	}
	fmt.Printf("===3: %s\n", encoded2)
	return encoded2 == encoded
}

func (hasher *bcryptHasher) MustUpdate(encoded string) bool {
	// TODO(zhaowentao)
	return false
}

func (hasher *bcryptHasher) Harden(password, encoded string) (string, error) {
	// TODO(zhaowentao)
	return encoded, nil
}

func newBcryptHasher(opt *HasherOption) (Hasher, error) {
	return &bcryptHasher{algo: opt.Algorithm}, nil
}
