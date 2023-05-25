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

	if !hasher.Verify(password, encoded) {
		t.Error("failed to verify password with sha1")
	}
}
