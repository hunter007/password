package passwordvalidator

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"unicode"
)

// Validator option
type ValidatorOption struct {
	// MinLength should be more than 0, and less than `MaxLength``
	MinLength uint8 `json:"min_length"`

	// MaxLength should be less than 32, and more than `MinLength`
	MaxLength uint8 `json:"max_length"`

	// CommonPasswordUrl
	CommonPasswordUrl string `json:"common_password_url"`
	CommonPasswords   []string `json:"common_passwords"`

	RequireDigit       bool `json:"require_digit"`
	RequireLowercase   bool `json:"require_lowercase"`
	RequireUppercase   bool `json:"require_uppercase"`
	RequirePunctuation bool `json:"require_punctuation"`
}

func (opt *ValidatorOption) loadCommonPasswords() error {
	opt.CommonPasswordUrl = strings.TrimSpace(opt.CommonPasswordUrl)
	if len(opt.CommonPasswordUrl) == 0 {
		return nil
	}

	resp, err := http.Get(opt.CommonPasswordUrl)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if opt.CommonPasswords == nil {
		opt.CommonPasswords = make([]string, 0, 0)
	}
	s := strings.Split(string(bs), "\n")
	opt.CommonPasswords = append(opt.CommonPasswords, s...)

	return nil
}

func (opt *ValidatorOption) validate() error {
	if opt.MinLength <= 0 {
		return errMin
	}

	if opt.MaxLength >= 32 {
		return errMax
	}

	if opt.MinLength > opt.MaxLength {
		return errMinMax
	}

	return opt.loadCommonPasswords()
}

// Validator for validating password
type Validator interface {
	// validates a password
	Validate(password string) error
}

type validator struct {
	opt *ValidatorOption
}

func (v *validator) Validate(password string) error {
	l := len(password)
	err := v.validateLength(l)
	if err != nil {
		return err
	}

	var hasDigit, hasUpperLetter, hasLowerLetter, hasPunct bool
	for _, r := range password {
		if unicode.IsDigit(r) && !hasDigit {
			hasDigit = true
		}
		if unicode.IsUpper(r) && !hasUpperLetter {
			hasUpperLetter = true
		}
		if unicode.IsLower(r) && !hasLowerLetter {
			hasLowerLetter = true
		}
		if unicode.IsPunct(r) && !hasPunct {
			hasPunct = true
		}
	}

	if v.opt.RequireDigit && !hasDigit {
		return v.error()
	}

	if v.opt.RequireLowercase && !hasLowerLetter {
		return v.error()
	}

	if v.opt.RequireUppercase && !hasUpperLetter {
		return v.error()
	}

	if v.opt.RequirePunctuation && !hasPunct {
		return v.error()
	}

	if !v.validateCommonPasswords(password){
		return errCommon
	}

	return nil
}

func (v *validator) validateCommonPasswords(password string) bool {
	p := strings.ToLower(password)
	for _, s := v.opt.CommonPasswords {
		if s == p {
			return false
		}
	}
	return true
}

func (v *validator) validateLength(length int) error {
	if length < int(v.opt.MinLength) {
		return errMinLength(int(v.opt.MinLength))
	}

	if length > int(v.opt.MaxLength) {
		return errMaxLength(int(v.opt.MaxLength))
	}

	return nil
}

func (v *validator) error() error {
	builder := strings.Builder{}
	builder.WriteString("The password should contain ")

	if v.opt.RequireDigit {
		builder.WriteString("digits, ")
	}

	if v.opt.RequireLowercase && v.opt.RequireUppercase {
		builder.WriteString("upper or lower letters, ")
	} else if v.opt.RequireLowercase {
		builder.WriteString("upper letters, ")
	} else if v.opt.RequireUppercase {
		builder.WriteString("lower letters, ")
	}

	if v.opt.RequirePunctuation {
		builder.WriteString("punctuations, ")
	}

	return errors.New(builder.String())
}

// New return a Validator
func New(opt *ValidatorOption) (Validator, error) {
	err := opt.validate()
	if err != nil {
		return nil, err
	}

	return &validator{
		opt: opt,
	}, nil
}