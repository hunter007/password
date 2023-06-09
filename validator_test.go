package password

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func mockServer() *httptest.Server {
	healthHandler := func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("1234567\n111111111"))
	}

	return httptest.NewServer(http.HandlerFunc(healthHandler))
}

func TestValidatorOptionWithCommonPasswordURL(t *testing.T) {
	server := mockServer()
	defer server.Close()

	voption := &ValidatorOption{
		MinLength:         6,
		MaxLength:         20,
		CommonPasswordURL: server.URL,
	}
	err := voption.validate()
	if err != nil {
		t.Errorf("should be nil, now %s", err)
	}

	if len(voption.CommonPasswords) != 2 {
		t.Errorf("get CommonPasswordURL error")
	}
}

func TestValidatorOptionWithMap(t *testing.T) {
	var voption ValidatorOption

	config := map[string]interface{}{
		"min_length":          6,
		"max_length":          20,
		"common_passwords":    []string{"123456", "1qasw23ed"},
		"require_digit":       true,
		"require_letter":      true,
		"require_punctuation": true,
	}
	b, _ := json.Marshal(config)
	err := json.Unmarshal(b, &voption)
	if err != nil {
		t.Errorf("config ValidatorOption with map error: %s", err)
	}
}

func TestValidatorOption(t *testing.T) {
	data := []struct {
		Name string
		opt  *ValidatorOption
	}{
		{
			Name: "blank option",
			opt:  &ValidatorOption{},
		},
		{
			Name: "MinLength should be more than 0",
			opt: &ValidatorOption{
				MinLength: 0,
			},
		},
		{
			Name: "MaxLength should be less than 32",
			opt: &ValidatorOption{
				MaxLength: 32,
			},
		},
		{
			Name: "MinLength should not be more than MaxLength",
			opt: &ValidatorOption{
				MinLength: 10,
				MaxLength: 8,
			},
		},
	}

	for _, item := range data {
		t.Run(item.Name, func(t *testing.T) {
			_, err := NewValidator(item.opt)
			if err == nil {
				t.Error("error should occur, not nil.")
			}
		})
	}
}

func TestValidatorError(t *testing.T) {
	data := []struct {
		name     string
		option   *ValidatorOption
		password string
	}{
		{
			name: "Password is too short",
			option: &ValidatorOption{
				MinLength: 6,
				MaxLength: 10,
			},
			password: "123",
		},
		{
			name: "Password is too long",
			option: &ValidatorOption{
				MinLength: 6,
				MaxLength: 15,
			},
			password: "adasdweuygefgwefwuiefowfw",
		},
		{
			name: "This is a common password",
			option: &ValidatorOption{
				MinLength:       4,
				MaxLength:       15,
				CommonPasswords: []string{"123456", "1qasw23ed"},
			},
			password: "1qasw23ed",
		},
		{
			name: "Password should contains digit",
			option: &ValidatorOption{
				MinLength:    4,
				MaxLength:    10,
				RequireDigit: true,
			},
			password: "adaf%^$d",
		},
		{
			name: "Password should contains lower letters",
			option: &ValidatorOption{
				MinLength:        4,
				MaxLength:        10,
				RequireLowercase: true,
			},
			password: "32@3GUGU",
		},
		{
			name: "Password should contains upper letters",
			option: &ValidatorOption{
				MinLength:        5,
				MaxLength:        10,
				RequireUppercase: true,
			},
			password: "%^sd122",
		},
		{
			name: "Password should contains lower and upper letters",
			option: &ValidatorOption{
				MinLength:        4,
				MaxLength:        15,
				RequireLowercase: true,
				RequireUppercase: true,
			},
			password: "%^&2323",
		},
		{
			name: "Password should contains punctuations",
			option: &ValidatorOption{
				MinLength:          4,
				MaxLength:          10,
				RequirePunctuation: true,
			},
			password: "234sdfs",
		},
		{
			name: "Password should contains digit, letter and punctuations",
			option: &ValidatorOption{
				MinLength:          4,
				MaxLength:          15,
				RequireDigit:       true,
				RequirePunctuation: true,
				RequireLetter:      true,
			},
			password: "342deddw",
		},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			v, err := NewValidator(d.option)
			if err != nil {
				t.Errorf("bad option: %s", err)
			}

			err = v.Validate(d.password)
			if err == nil {
				t.Error("Error should occur")
			}
			t.Log(err.Error())

			if len(d.password) < int(d.option.MinLength) {
				c := strconv.Itoa(int(d.option.MinLength))
				if !strings.Contains(err.Error(), c) {
					t.Errorf("The value of MinLength should in error string.")
				}
			} else if len(d.password) > int(d.option.MaxLength) {
				c := strconv.Itoa(int(d.option.MaxLength))
				if !strings.Contains(err.Error(), c) {
					t.Errorf("The value of MaxLength should in error string.")
				}
			} else if d.option.CommonPasswords != nil {
				if err != errCommon {
					t.Errorf("errCommon should be returned.")
				}
			} else if d.option.RequireDigit {
				if !strings.Contains(err.Error(), "digit") {
					t.Errorf("Error string should contains 'digit'")
				}
			} else if d.option.RequireLowercase {
				if !strings.Contains(err.Error(), "lower") {
					t.Errorf("Error string should contains 'lower'")
				}
			} else if d.option.RequireUppercase {
				if !strings.Contains(err.Error(), "upper") {
					t.Errorf("Error string should contains 'upper'")
				}
			} else if d.option.RequireLowercase && d.option.RequireUppercase {
				if !strings.Contains(err.Error(), "upper") || !strings.Contains(err.Error(), "lower") {
					t.Errorf("Error string should contains 'upper' and 'lower'")
				}
			} else if d.option.RequirePunctuation {
				if !strings.Contains(err.Error(), "punctuations") {
					t.Errorf("Error string should contains 'punctuations'")
				}
			} else if d.option.RequirePunctuation && d.option.RequireDigit && d.option.RequireLetter && !d.option.RequireLowercase && !d.option.RequireUppercase {
				s := err.Error()
				if !strings.Contains(s, "digit") || !strings.Contains(s, "upper or lower letters") || !strings.Contains(s, "punctuations") {
					t.Errorf("Err string should contains 'digit', 'punctuations' and 'upper or lower letters'")
				}
			}
		})
	}
}
