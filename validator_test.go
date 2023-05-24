package passwordvalidator

import "testing"

type validateData struct {
	option   *ValidatorOption
	password string
}

func TestValidator(t *testing.T) {
	data := []validateData{
		{
			option:   &ValidatorOption{},
			password: "adasd",
		},
		{
			option: &ValidatorOption{
				MinLength: 10,
			},
			password: "adasd",
		},
		{
			option: &ValidatorOption{
				MaxLength: 15,
			},
			password: "adasd",
		},
		{
			option: &ValidatorOption{
				MaxLength: 15,
			},
			password: "adasd",
		},
	}

	for _, d := range data {
		t.Run("No limited", func(t *testing.T) {
			v, _ := New(d.option)
			err := v.Validate(d.password)
			if err != nil {
				t.Error("Should be nil.")
			}
		})

		t.Run("Require min length", func(t *testing.T) {
			v, _ := New(d.option)
			err := v.Validate(d.password)
			if len(d.password) < int(d.option.MinLength) {
				if err == nil {
					t.Errorf("不满足")
				}
			}
		})
	}
}
