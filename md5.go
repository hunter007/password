package passwordvalidator

import (
	"crypto/md5"
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
	return hasher.encode(password, hasher.salt)
}

func (hasher *md5Hasher) encode(password, salt string) (string, error) {
	h := md5.New()
	// to support `unsalted_md5`
	if len(salt) > 0 {
		h.Write([]byte(salt))
	}
	h.Write([]byte(password))
	parts := []string{hasher.Algorithm(), salt, string(h.Sum(nil))}
	return strings.Join(parts, sep), nil
}

func (hasher *md5Hasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 2)
	if parts[0] != md5Algo && parts[0] != unsaltedMd5Algo {
		return nil, errUnknownAlgorithm
	}

	return &PasswordInfo{
		Algorithm: parts[0],
		Hash:      parts[1],
		Salt:      parts[2],
	}, nil
}

func (hasher *md5Hasher) Verify(password, encoded string) bool {
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
