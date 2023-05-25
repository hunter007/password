package passwordvalidator

import (
	"strings"
)

const saltEntropy = 128

const (
	md5Algo          = "md5"
	unsaltedMd5Algo  = "unsalted_md5"
	pbkdf2Sha256Algo = "pbkdf2_sha256"
	pbkdf2Sha1Algo   = "pbkdf2_sha1"
	argon2Algo       = "argon2id"
	bcryptAlgo       = "bcrypt"
	bcryptSha256Algo = "bcrypt_sha256"
	scryptAlgo       = "scrypt"
	sha1Algo         = "sha1"
)

var supportAlgorithms = map[string]struct{}{
	md5Algo:          {},
	unsaltedMd5Algo:  {},
	pbkdf2Sha256Algo: {},
	pbkdf2Sha1Algo:   {},
	argon2Algo:       {},
	bcryptAlgo:       {},
	bcryptSha256Algo: {},
	scryptAlgo:       {},
	sha1Algo:         {},
}

// HasherOption Hasher option
type HasherOption struct {
	// Algorithm: Support md5, unsalted_md5, pbkdf2_sha256, pbkdf2_sha1,
	// argon2id, bcrypt, bcrypt_sha256, scrypt, sha1
	Algorithm string `json:"algorithm"`

	Secret string `json:"secret"`

	// Salt: cannot contain '$'
	Salt string `json:"salt"`
	// Iterations: should be gratter than 0
	Iterations int         `json:"iterations"`
	Params     interface{} `json:"params"`
}

func (ho *HasherOption) validate() error {
	if _, ok := supportAlgorithms[ho.Algorithm]; !ok {
		return errUnknownAlgorithm
	}

	if strings.Contains(ho.Salt, sep) {
		return errIllegalSalt
	}

	if ho.Iterations <= 0 {
		return errIllegalIterations
	}

	return nil
}

func (ho *HasherOption) NewHasher() (Hasher, error) {
	switch ho.Algorithm {
	case unsaltedMd5Algo, md5Algo:
		return newMD5Hasher(ho)
	case pbkdf2Sha1Algo, pbkdf2Sha256Algo:
		return newPBKDDF2Hasher(ho)
	case argon2Algo:
		return newArgon2Hasher(ho)
	case bcryptSha256Algo, bcryptAlgo:
		return newBcryptHasher(ho)
	case scryptAlgo:
		return newScryptHasher(ho)
	case sha1Algo:
		return newSha1Hasher(ho)
	}
	return nil, errUnknownAlgorithm
}
