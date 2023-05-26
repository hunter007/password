package password

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

	password := "1qasw2ed"
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to Encode(password): %s", err)
	}
	t.Logf("encoded password: %s", encoded)

	wrongEncoded := "aa" + encoded
	_, err = hasher.Decode(wrongEncoded)
	if err == nil {
		t.Error("Decode(wrongEncoded) should fail")
	}

	if hasher.Verify(password, wrongEncoded) {
		t.Error("Verify(wrongEncoded) should fail")
	}

	if !hasher.Verify(password, encoded) {
		t.Error("Verify(wrongEncoded) should be nil")
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

func TestMustUpdateForMd5(t *testing.T) {
	opt := HasherOption{
		Algorithm:  unsaltedMd5Algo,
		Salt:       "",
		Iterations: 1,
	}
	hasher, _ := NewHasher(&opt)
	encoded, _ := hasher.Encode(password)

	if hasher.MustUpdate(encoded) {
		t.Error("should not update")
	}

	opt1 := HasherOption{
		Algorithm:  md5Algo,
		Salt:       "saltsaltsaltsalt",
		Iterations: 1,
	}
	hasher, _ = NewHasher(&opt1)
	encoded, _ = hasher.Encode(password)
	if hasher.MustUpdate(encoded) {
		t.Error("should not update")
	}
	wrongEncoded := "aa" + encoded
	if hasher.MustUpdate(wrongEncoded) {
		t.Error("should not update because of wrong encoded")
	}

	opt2 := HasherOption{
		Algorithm:  md5Algo,
		Salt:       "saltsaltsaltsa",
		Iterations: 1,
	}
	hasher, _ = NewHasher(&opt2)
	if hasher.MustUpdate(encoded) {
		t.Error("should not update because of short salt")
	}
}
