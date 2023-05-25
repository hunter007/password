package passwordvalidator

import "testing"

func TestDefaultArgon2(t *testing.T) {
	opt := &HasherOption{
		Iterations: 1,
		Algorithm:  argon2Algo,
	}
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("err should be nil: %s", err)
	}
	password1, password2 := "123qweasd", "1qasw231w"
	encoded1, err := hasher.Encode(password1)
	if err != nil {
		t.Errorf("Encode(encoded1) should be ok: %s", err)
	}

	encoded2, err := hasher.Encode(password2)
	if err != nil {
		t.Errorf("Encode(encoded2) should be ok: %s", err)
	}

	pi, err := hasher.Decode(encoded1)
	if err != nil {
		t.Errorf("Decode(encoded1) should be ok: %s", err)
	}
	p1, _ := pi.Others.(*Argon2Params)
	p2, _ := opt.Params.(*Argon2Params)
	if p2 != nil && *p1 != *p2 {
		t.Errorf("Params should be same")
	}

	if !hasher.Verify(password1, encoded1) {
		t.Errorf("Verify() should be true")
	}

	if hasher.Verify(password1, encoded2) {
		t.Errorf("Verify() should be false")
	}
}

func TestArgon2(t *testing.T) {
	opt := &HasherOption{
		Iterations: 1,
		Algorithm:  argon2Algo,
		Params: &Argon2Params{
			memory:      32 * 1024,
			iterations:  10,
			parallelism: 2,
			saltLength:  8,
			keyLength:   32,
		},
	}
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("err should be nil: %s", err)
	}
	password1, password2 := "123qweasd", "1qasw231w"
	encoded1, err := hasher.Encode(password1)
	if err != nil {
		t.Errorf("Encode(encoded1) should be ok: %s", err)
	}

	encoded2, err := hasher.Encode(password2)
	if err != nil {
		t.Errorf("Encode(encoded2) should be ok: %s", err)
	}

	pi, err := hasher.Decode(encoded1)
	if err != nil {
		t.Errorf("Decode(encoded1) should be ok: %s", err)
	}
	p1, _ := pi.Others.(*Argon2Params)
	p2, _ := opt.Params.(*Argon2Params)
	if *p1 != *p2 {
		t.Errorf("Params should be same")
	}

	if !hasher.Verify(password1, encoded1) {
		t.Errorf("Verify() should be true")
	}

	if hasher.Verify(password1, encoded2) {
		t.Errorf("Verify() should be false")
	}
}
