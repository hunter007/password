package passwordvalidator

import (
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type pbkdf2Hasher struct {
	algo      string
	salt      string
	iterCount int
}

func (hasher *pbkdf2Hasher) getSizeAndNew() (int, func() hash.Hash) {
	var size int
	var newfunc func() hash.Hash

	switch hasher.algo {
	case pbkdf2Sha256Algo:
		size, newfunc = sha256.Size, sha256.New
		break
	case pbkdf2Sha1Algo:
		size, newfunc = sha1.Size, sha1.New
		break
	}
	return size, newfunc
}

func (hasher *pbkdf2Hasher) Encode(password string) (string, error) {
	return hasher.encode(
		hasher.algo,
		[]byte(password),
		[]byte(hasher.salt),
		hasher.iterCount,
	), nil
}

func (hasher *pbkdf2Hasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 4)
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	if parts[0] != pbkdf2Sha1Algo && parts[0] != pbkdf2Sha256Algo {
		return nil, errUnknownAlgorithm
	}

	return &PasswordInfo{
		Algorithm:  parts[0],
		Iterations: iter,
		Salt:       parts[2],
		Hash:       parts[3],
	}, nil
}

func (hasher *pbkdf2Hasher) Verify(password, encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}

	return encoded == hasher.encode(pi.Algorithm, []byte(password), []byte(pi.Salt), pi.Iterations)
}

func (hasher *pbkdf2Hasher) MustUpdate(encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}

	updateSalt := mustUpdateSalt(pi.Salt, saltEntropy)

	return pi.Iterations < hasher.iterCount || updateSalt
}

func (hasher *pbkdf2Hasher) Harden(password, encoded string) (string, error) {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return "", err
	}

	extraIterations := hasher.iterCount - pi.Iterations
	if extraIterations > 0 {
		return hasher.encode(
			pi.Algorithm,
			[]byte(password),
			[]byte(pi.Salt),
			extraIterations,
		), nil
	}

	return encoded, nil
}

func (hasher *pbkdf2Hasher) encode(algo string, password, salt []byte, iteration int) string {
	size, newFunc := hasher.getSizeAndNew()
	hash := pbkdf2.Key(
		password,
		salt,
		iteration,
		size,
		newFunc,
	)
	ss := []string{
		algo,
		strconv.Itoa(iteration),
		string(salt),
		base64.StdEncoding.EncodeToString(hash),
	}
	return strings.Join(ss, sep)
}

func newPBKDDF2Hasher(opt *HasherOption) (Hasher, error) {
	return &pbkdf2Hasher{
		algo:      opt.Algorithm,
		salt:      opt.Salt,
		iterCount: opt.Iterations,
	}, nil
}
