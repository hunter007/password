package passwordvalidator

import "testing"

func TestMd5(t *testing.T) {
	salt := "salt"
	opt := HasherOption{
		Algorithm:  md5Algo,
		Salt:       salt,
		Iterations: 1,
	}
	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("error should be nil, now %s", err)
	}

	password := "1qasw23ed"
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to Encode(password): %s", err)
	}
	t.Logf("encoded password: %s", encoded)

	equal := hasher.Verify(password, encoded)
	if !equal {
		t.Errorf("MD5 error")
	}
}

func TestUnsaltedMd5(t *testing.T) {
	salt := ""
	opt := HasherOption{
		Algorithm:  unsaltedMd5Algo,
		Salt:       salt,
		Iterations: 1,
	}
	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("error should be nil, now %s", err)
	}

	password := "1qasw23ed"
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to Encode(password): %s", err)
	}
	t.Logf("encoded password: %s", encoded)

	equal := hasher.Verify(password, encoded)
	if !equal {
		t.Errorf("MD5 error")
	}
}
