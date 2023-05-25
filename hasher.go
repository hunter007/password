package passwordvalidator

import "errors"

type Hasher interface {
	Encode(password string) (string, error)
	Decode(decoded string) (*PasswordInfo, error)
	Verify(password, encoded string) bool
	MustUpdate(encoded string) bool
	Harden(password, encoded string) (string, error)
}

var errNilHasherOption = errors.New("nil HasherOption")

func NewHasher(opt *HasherOption) (Hasher, error) {
	if opt == nil {
		return nil, errNilHasherOption
	}
	err := opt.validate()
	if err != nil {
		return nil, err
	}
	return opt.NewHasher()
}

const sep string = "$"

type PasswordInfo struct {
	Algorithm  string
	Hash       string
	Iterations int
	Salt       string
	Others     interface{}
}
