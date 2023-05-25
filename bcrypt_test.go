package password

import "testing"

func TesBcrypt(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  bcryptAlgo,
		Salt:       "salt",
		Iterations: 1,
	}
	password := "1qasw23"
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("failed to new %s hasher: %s", opt.Algorithm, err)
	}

	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with %s: %s", opt.Algorithm, err)
	}
	t.Logf("encoded password: %s", encoded)
	if !hasher.Verify(password, encoded) {
		t.Errorf("wrong algorithm: %s", opt.Algorithm)
	}
}
