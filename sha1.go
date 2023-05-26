package password

import (
	"crypto/sha1" // #nosec
	"encoding/hex"
	"strings"
)

type sha1Hasher struct {
	salt string
}

func (hasher *sha1Hasher) Encode(password string) (string, error) {
	return hasher.encode(password, hasher.salt), nil
}

func (hasher *sha1Hasher) encode(password, salt string) string {
	h := sha1.New() // #nosec
	h.Write([]byte(salt))
	h.Write([]byte(password))
	parts := []string{sha1Algo, salt, hex.EncodeToString(h.Sum(nil))}
	return strings.Join(parts, sep)
}

func (hasher *sha1Hasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 3)
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

	encoded2 := hasher.encode(password, pi.Salt)
	return encoded2 == encoded
}

func (hasher *sha1Hasher) MustUpdate(encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}
	return mustUpdateSalt(pi.Salt, saltEntropy) || len(pi.Salt) < len(hasher.salt)
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
