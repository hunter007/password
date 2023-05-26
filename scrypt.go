package password

import (
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	blockSize   = 1 << 3
	maxMemory   = 0
	parallelism = 1
	workFactor  = 1 << 14
	keyLen      = 64
)

type scryptHasher struct {
	salt string
}

func (hasher *scryptHasher) Encode(password string) (string, error) {
	return hasher.encode(password, hasher.salt)
}

func (hasher *scryptHasher) encode(password, salt string) (string, error) {
	dk, err := scrypt.Key(
		[]byte(password),
		[]byte(salt),
		workFactor,
		blockSize,
		parallelism,
		keyLen)
	if err != nil {
		return "", err
	}

	hash := base64.StdEncoding.EncodeToString(dk)
	parts := []string{
		scryptAlgo,
		strconv.Itoa(workFactor),
		hasher.salt,
		strconv.Itoa(blockSize),
		strconv.Itoa(parallelism),
		hash,
	}
	return strings.Join(parts, sep), nil
}

func (hasher *scryptHasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 6)
	if parts[0] != scryptAlgo {
		return nil, errUnknownAlgorithm
	}

	return &PasswordInfo{
		Algorithm: scryptAlgo,
		Hash:      parts[5],
		Salt:      parts[2],
	}, nil
}

func (hasher *scryptHasher) Verify(password, encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}

	encoded2, err := hasher.encode(password, pi.Salt)
	if err != nil {
		return false
	}

	return encoded2 == encoded
}

func (hasher *scryptHasher) MustUpdate(encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}
	return mustUpdateSalt(pi.Salt, saltEntropy) || len(pi.Salt) < len(hasher.salt)
}

func (hasher *scryptHasher) Harden(password, encoded string) (string, error) {
	return encoded, nil
}

func newScryptHasher(opt *HasherOption) (Hasher, error) {
	return &scryptHasher{salt: opt.Salt}, nil
}
