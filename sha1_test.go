package password

import "testing"

func TestSha1(t *testing.T) {
	salt := "sha1"
	opt := HasherOption{
		Algorithm:  sha1Algo,
		Salt:       salt,
		Iterations: 1,
	}

	password := "1qasw23ed"
	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("failed to new sha1 hasher: %s", err)
	}
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with sha1: %s", err)
	}

	wrongEncoded := "ww" + encoded
	_, err = hasher.Decode(wrongEncoded)
	if err == nil {
		t.Error("Decode(wrongEncoded) should be error")
	}

	pi, err := hasher.Decode(encoded)
	if err != nil {
		t.Errorf("Decode(encoded) should be nil: %s", err)
	}
	if pi == nil || pi.Algorithm != sha1Algo || pi.Salt != opt.Salt {
		t.Errorf("Decode(encoded) error: pi=%v", pi)
	}

	if hasher.Verify(password, wrongEncoded) {
		t.Error("verify(wrongEncoded) should fail")
	}

	if !hasher.Verify(password, encoded) {
		t.Error("failed to verify password with sha1")
	}
}
