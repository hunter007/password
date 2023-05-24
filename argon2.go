package passwordvalidator

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  int
	keyLength   uint32
}

var defaultParams = &params{
	memory:      64 * 1024,
	iterations:  1,
	parallelism: 4,
	saltLength:  16,
	keyLength:   32,
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

type argon2Hasher struct {
	opt *HasherOption
}

var errArgon2Encode = errors.New("")

func (hasher *argon2Hasher) Encode(password string) (string, error) {
	salt, err := generateRandomBytes(defaultParams.saltLength)
	if err != nil {
		return "", errArgon2Encode
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		defaultParams.iterations,
		defaultParams.memory,
		defaultParams.parallelism,
		defaultParams.keyLength)

	return argon2Algo + string(hash), nil
}

func (hasher *argon2Hasher) Decode(encoded string) (*PasswordInfo, error) {
	// TODO(zhaowentao):
	return &PasswordInfo{
		Algorithm: argon2Algo,
	}, nil
}

func (hasher *argon2Hasher) Verify(password, encoded string) bool {
	// TODO(zhaowentao): 处理 Verify
	return false
}

func (hasher *argon2Hasher) MustUpdate(encoded string) bool {
	// TODO(zhaowentao): 处理 Verify
	return false
}

func (hasher *argon2Hasher) Harden(password, encoded string) (string, error) {
	// TODO(zhaowentao): 处理 Verify
	return encoded, nil
}

func newArgon2Hasher(opt *HasherOption) (Hasher, error) {
	return &argon2Hasher{opt: opt}, nil
}
