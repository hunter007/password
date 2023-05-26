package password

import "testing"

func TestSha1WithNoSalt(t *testing.T) {
	opt := HasherOption{
		Algorithm:  sha1Algo,
		Salt:       "",
		Iterations: 1,
	}
	hasher, err := NewHasher(&opt)
	if err == nil {
		t.Errorf("NewHasher should be eror")
	}
	if hasher != nil {
		t.Errorf("NewHasher: hasher should be nil")
	}
	if err != errBlankSalt {
		t.Errorf("err should be %s", errBlankSalt)
	}
}

func TestSha1(t *testing.T) {
	salt := "sha1sha1sha1"
	opt := HasherOption{
		Algorithm:  sha1Algo,
		Salt:       salt,
		Iterations: 1,
	}

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

func TestMustUpdateForSha1(t *testing.T) {
	opt := HasherOption{
		Algorithm:  sha1Algo,
		Salt:       "sha1sha1sha1",
		Iterations: 1,
	}

	hasher, _ := NewHasher(&opt)
	encoded, _ := hasher.Encode(password)

	if hasher.MustUpdate(encoded) {
		t.Error("should not updated")
	}

	wrongEncoded := "aa" + encoded
	if hasher.MustUpdate(wrongEncoded) {
		t.Error("should not updated because of wrong encoded")
	}

	opt2 := HasherOption{
		Algorithm:  sha1Algo,
		Salt:       "sha1sha1sha12",
		Iterations: 1,
	}
	hasher, _ = NewHasher(&opt2)
	if !hasher.MustUpdate(encoded) {
		t.Error("should updated because of longer salt")
	}

	opt3 := HasherOption{
		Algorithm:  sha1Algo,
		Salt:       "sha1sha1sha",
		Iterations: 1,
	}
	hasher, _ = NewHasher(&opt3)
	if hasher.MustUpdate(encoded) {
		t.Error("should not updated because of shorter salt")
	}
}
