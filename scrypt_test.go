package passwordvalidator

import "testing"

func TestScrypt(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  scryptAlgo,
		Salt:       "salt",
		Iterations: 1,
	}
	password := "1qasw23ed"

	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("failed to new scrypt hasher: %s", err)
	}

	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with scrypt: %s", err)
	}

	t.Logf("encoded password: %s", encoded)
	if !hasher.Verify(password, encoded) {
		t.Error("scrypt verify error")
	}
}
