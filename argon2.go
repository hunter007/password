package passwordvalidator

import (
	"encoding/hex"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params Argon2id parameters
type Argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  int
	keyLength   uint32
}

var defaultArgon2Params = &Argon2Params{
	memory:      64 * 1024,
	iterations:  1,
	parallelism: 4,
	saltLength:  16,
	keyLength:   32,
}

type argon2Hasher struct {
	params *Argon2Params
}

func (hasher *argon2Hasher) Encode(password string) (string, error) {
	salt, err := generateRandomBytes(hasher.params.saltLength)
	if err != nil {
		return "", err
	}
	return hasher.encode(password, salt, hasher.params)
}

func (hasher *argon2Hasher) encode(password string, salt []byte, params *Argon2Params) (string, error) {
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength)

	p := []string{
		argon2Algo,
		hex.EncodeToString(salt),
		strconv.Itoa(int(params.iterations)),
		strconv.Itoa(int(params.memory)),
		strconv.Itoa(int(params.parallelism)),
		strconv.Itoa(int(params.keyLength)),
		hex.EncodeToString(hash),
	}
	return strings.Join(p, sep), nil
}

func (hasher *argon2Hasher) Decode(encoded string) (*PasswordInfo, error) {
	parts := strings.SplitN(encoded, sep, 7)
	if parts[0] != argon2Algo {
		return nil, errUnknownAlgorithm
	}

	iter, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, err
	}

	memory, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, err
	}

	parallelism, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil, err
	}

	keyLength, err := strconv.Atoi(parts[5])
	if err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return &PasswordInfo{
		Algorithm:  parts[0],
		Hash:       parts[6],
		Salt:       parts[1],
		Iterations: iter,
		Others: &Argon2Params{
			memory:      uint32(memory),
			iterations:  uint32(iter),
			parallelism: uint8(parallelism),
			saltLength:  len(salt),
			keyLength:   uint32(keyLength),
		},
	}, nil
}

func (hasher *argon2Hasher) Verify(password, encoded string) bool {
	pi, err := hasher.Decode(encoded)
	if err != nil {
		return false
	}
	params := pi.Others.(*Argon2Params)
	salt, _ := hex.DecodeString(pi.Salt)
	encoded2, err := hasher.encode(password, salt, params)
	if err != nil {
		return false
	}
	return encoded2 == encoded
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
	var params *Argon2Params
	if opt.Params == nil {
		params = defaultArgon2Params
	} else {
		p, ok := opt.Params.(*Argon2Params)
		if !ok {
			params = defaultArgon2Params
		} else {
			params = p
		}
	}
	return &argon2Hasher{params: params}, nil
}
