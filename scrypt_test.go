package password

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
