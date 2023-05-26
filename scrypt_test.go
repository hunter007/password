package password

import "testing"

func TestScrypt(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  scryptAlgo,
		Salt:       "saltsaltsalt",
		Iterations: 1,
	}

	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("failed to new scrypt hasher: %s", err)
	}

	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with scrypt: %s", err)
	}

	wrongEncoded := "aa" + encoded
	if _, err = hasher.Decode(wrongEncoded); err == nil {
		t.Error("Decode(wrongEncoded) should be err")
	}

	if err != errUnknownAlgorithm {
		t.Errorf("Decode(wrongEncoded) err should be %s: %s", errUnknownAlgorithm, err)
	}

	t.Logf("encoded password: %s", encoded)

	if hasher.Verify(password, wrongEncoded) {
		t.Error("Verify(wrongEncoded) should be false")
	}

	if !hasher.Verify(password, encoded) {
		t.Error("scrypt verify error")
	}
}

func TestMustUpdateForScrypt(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  scryptAlgo,
		Salt:       "saltsaltsalt",
		Iterations: 1,
	}
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("failed to new scrypt hasher: %s", err)
	}

	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with scrypt: %s", err)
	}

	if hasher.MustUpdate(encoded) {
		t.Error("should not update")
	}

	wrongEncoded := "aa" + encoded
	if hasher.MustUpdate(wrongEncoded) {
		t.Error("should not update because of wrong encoded")
	}

	opt2 := &HasherOption{
		Algorithm:  scryptAlgo,
		Salt:       "saltsaltsalt2",
		Iterations: 1,
	}
	hasher, _ = NewHasher(opt2)
	if !hasher.MustUpdate(encoded) {
		t.Error("should update because of longer salt")
	}

	opt3 := &HasherOption{
		Algorithm:  scryptAlgo,
		Salt:       "saltsaltsal",
		Iterations: 1,
	}
	hasher, _ = NewHasher(opt3)
	if hasher.MustUpdate(encoded) {
		t.Error("should not update because of shorter salt")
	}
}
