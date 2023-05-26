package password

import (
	"crypto/md5" // #nosec
	"encoding/hex"
	"strings"
)

type md5Hasher struct {
	salt string
}

func (hasher *md5Hasher) Algorithm() string {
	if len(hasher.salt) > 0 {
		return md5Algo
	} else {
		return unsaltedMd5Algo
	}
}

func (hasher *md5Hasher) Encode(password string) (string, error) {
	return hasher.encode(password, hasher.salt), nil
}

func (hasher *md5Hasher) encode(password, salt string) string {
	h := md5.New() // #nosec

	// to support `unsalted_md5`
	if len(salt) > 0 {
		h.Write([]byte(salt))
	}
	h.Write([]byte(password))
	parts := []string{hasher.Algorithm(), salt, hex.EncodeToString(h.Sum(nil))}
	return strings.Join(parts, sep)
}

func (hasher *md5Hasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 3)
	if parts[0] != md5Algo && parts[0] != unsaltedMd5Algo {
		return nil, errUnknownAlgorithm
	}

	return &PasswordInfo{
		Algorithm: parts[0],
		Salt:      parts[1],
		Hash:      parts[2],
	}, nil
}

func (hasher *md5Hasher) Verify(password, encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}

	return hasher.encode(password, pi.Salt) == encoded
}

func (hasher *md5Hasher) MustUpdate(encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}
	return mustUpdateSalt(pi.Salt, saltEntropy)
}

func (hasher *md5Hasher) Harden(password, encoded string) (string, error) {
	return encoded, nil
}

func newMD5Hasher(opt *HasherOption) (Hasher, error) {
	return &md5Hasher{salt: opt.Salt}, nil
}
