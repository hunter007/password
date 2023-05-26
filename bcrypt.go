package password

import (
	"crypto/sha256"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	algo string
	cost int
}

func (hasher *bcryptHasher) Encode(password string) (string, error) {
	return hasher.encode(password, hasher.algo, hasher.cost)
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
	ss := []string{
		algo,
		string(hash),
	}

	return strings.Join(ss, sep), nil
}

func (hasher *bcryptHasher) Decode(decoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(decoded, sep, 2)
	if parts[0] != bcryptSha256Algo && parts[0] != bcryptAlgo {
		return nil, errUnknownAlgorithm
	}

	cost, err := bcrypt.Cost([]byte(parts[1]))
	if err != nil {
		return nil, err
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

	var data []byte
	if pi.Algorithm == bcryptSha256Algo {
		d := sha256.Sum256([]byte(password))
		data = d[:]
	} else {
		data = []byte(password)
	}
	err = bcrypt.CompareHashAndPassword([]byte(pi.Hash), data)
	return err == nil
}

func (hasher *bcryptHasher) MustUpdate(encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}
	return pi.Iterations < hasher.cost
}

func (hasher *bcryptHasher) Harden(password, encoded string) (string, error) {
	// TODO(zhaowentao)
	return encoded, nil
}

func newBcryptHasher(opt *HasherOption) (Hasher, error) {
	cost := bcrypt.DefaultCost
	if opt.Iterations > cost {
		cost = opt.Iterations
	}

	return &bcryptHasher{
		algo: opt.Algorithm,
		cost: cost,
	}, nil
}
