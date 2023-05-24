package passwordvalidator

import (
	"crypto/sha1" // #nosec
	"fmt"
	"strings"
)

type sha1Hasher struct {
	salt string
}

func (hasher *sha1Hasher) Encode(password string) (string, error) {
	return hasher.encode(password, hasher.salt)
}

func (hasher *sha1Hasher) encode(password, salt string) (string, error) {
	sum := sha1.Sum([]byte(fmt.Sprintf("%s%s", salt, password))) // #nosec
	return strings.Join([]string{sha1Algo, salt, string(sum[:])}, sep), nil
}

func (hasher *sha1Hasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 2)
	if parts[0] != sha1Algo {
		return nil, errUnknownAlgorithm
	}

	return &PasswordInfo{
		Algorithm: sha1Algo,
		Salt:      parts[1],
		Hash:      parts[2],
	}, nil
}

func (hasher *sha1Hasher) Verify(password, encoded string) bool {
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

func (hasher *sha1Hasher) MustUpdate(encoded string) bool {
	return false
}

func (hasher *sha1Hasher) Harden(password, encoded string) (string, error) {
	return encoded, nil
}

func newSha1Hasher(opt *HasherOption) (Hasher, error) {
	if len(opt.Salt) == 0 {
		return nil, errBlankSalt
	}

	return &sha1Hasher{salt: opt.Salt}, nil
}
