package password

import "testing"

func TestPbkdf2Sha1Hasher(t *testing.T) {
	opt := HasherOption{
		Algorithm:  pbkdf2Sha1Algo,
		Salt:       "salt",
		Iterations: 10000,
	}
	password := "1qasw23ed"

	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("failed to new %s hasher: %s", pbkdf2Sha1Algo, err)
	}
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with %s: %s", pbkdf2Sha1Algo, err)
	}

	t.Logf("encoded password: %s", encoded)
	if !hasher.Verify(password, encoded) {
		t.Errorf("Algo %s error", pbkdf2Sha1Algo)
	}
}

func TestPbkdf2Sha256Hasher(t *testing.T) {
	opt := HasherOption{
		Algorithm:  pbkdf2Sha256Algo,
		Salt:       "salt",
		Iterations: 10000,
	}
	password := "1qasw23ed"

	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("failed to new %s hasher: %s", pbkdf2Sha256Algo, err)
	}
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with %s: %s", pbkdf2Sha256Algo, err)
	}

	wrongEncoded := "aa" + encoded
	if _, err = hasher.Decode(wrongEncoded); err == nil {
		t.Error("Decode(wrongEncoded) should error")
	}

	if hasher.Verify(password, wrongEncoded) {
		t.Error("Verify(password, wrongEncoded) error")
	}
	if !hasher.Verify(password, encoded) {
		t.Errorf("Algo %s error", pbkdf2Sha256Algo)
	}
}
