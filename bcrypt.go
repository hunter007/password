package passwordvalidator

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	algo string
}

func (hasher *bcryptHasher) Encode(password string) (string, error) {
	var data []byte
	if hasher.algo == bcryptSha256Algo {
		d := sha256.Sum256([]byte(password))
		data = d[:]
	}

	hash, err := bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s%s", hasher.algo, sep, string(hash)), nil
}

func (hasher *bcryptHasher) Decode(decoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(decoded, sep, 2)
	if parts[0] != bcryptSha256Algo && parts[0] != bcryptAlgo {
		return nil, errUnknownAlgorithm
	}

	cost, err := bcrypt.Cost([]byte(parts[1]))
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

	err = bcrypt.CompareHashAndPassword([]byte(pi.Hash), []byte(password))
	return err == nil
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
