package password

import (
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
)

const password = "1qasw23ed"

func TestPbkdf2Sha1Hasher(t *testing.T) {
	opt := HasherOption{
		Algorithm:  pbkdf2Sha1Algo,
		Salt:       "salt",
		Iterations: 10000,
	}

	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("failed to new %s hasher: %s", pbkdf2Sha1Algo, err)
	}

	pHasher := hasher.(*pbkdf2Hasher)
	size, newFunc := pHasher.getSizeAndNew()
	if opt.Algorithm == pbkdf2Sha1Algo {
		if size != sha1.Size {
			t.Error("wrong size")
		}

		if reflect.ValueOf(newFunc).Pointer() != reflect.ValueOf(sha1.New).Pointer() {
			t.Error("wrong newFunc")
		}
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

	hasher, err := NewHasher(&opt)
	if err != nil {
		t.Errorf("failed to new %s hasher: %s", pbkdf2Sha256Algo, err)
	}

	pHasher := hasher.(*pbkdf2Hasher)
	size, newFunc := pHasher.getSizeAndNew()
	if opt.Algorithm == pbkdf2Sha256Algo {
		if size != sha256.Size {
			t.Error("wrong size")
		}

		if reflect.ValueOf(newFunc).Pointer() != reflect.ValueOf(sha256.New).Pointer() {
			t.Error("wrong newFunc")
		}
	}

	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with %s: %s", pbkdf2Sha256Algo, err)
	}

	wrongEncoded := "aa" + encoded
	if _, err = hasher.Decode(wrongEncoded); err == nil {
		t.Error("Decode(wrongEncoded) should error")
	}

	pp := strings.SplitN(encoded, sep, 4)
	pp[1] = "aa"
	wrongEncoded2 := strings.Join(pp, sep)
	if _, err = hasher.Decode(wrongEncoded2); err == nil {
		t.Error("Decode(wrongEncoded2) should error")
	}

	if hasher.Verify(password, wrongEncoded) {
		t.Error("Verify(password, wrongEncoded) error")
	}
	if !hasher.Verify(password, encoded) {
		t.Errorf("Algo %s error", pbkdf2Sha256Algo)
	}
}

func TestMustUpdateForPbkdf2Sha256(t *testing.T) {
	opt := HasherOption{
		Algorithm:  pbkdf2Sha256Algo,
		Salt:       "saltsaltsalt",
		Iterations: 10000,
	}

	hasher, _ := NewHasher(&opt)
	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with %s: %s", pbkdf2Sha256Algo, err)
	}

	if hasher.MustUpdate(encoded) {
		t.Error("should not update")
	}

	opt2 := HasherOption{
		Algorithm:  pbkdf2Sha256Algo,
		Salt:       "saltsaltsalt",
		Iterations: 10001,
	}
	hasher2, _ := NewHasher(&opt2)
	if !hasher2.MustUpdate(encoded) {
		t.Error("should update because of Iterations")
	}

	opt3 := HasherOption{
		Algorithm:  pbkdf2Sha256Algo,
		Salt:       "saltsaltsaltsaltsalt11",
		Iterations: 10000,
	}
	hasher3, _ := NewHasher(&opt3)
	if !hasher3.MustUpdate(encoded) {
		t.Error("should update because of Salt")
	}

	opt4 := HasherOption{
		Algorithm:  pbkdf2Sha256Algo,
		Salt:       "saltsaltsalt",
		Iterations: 9000,
	}
	hasher4, _ := NewHasher(&opt4)
	if hasher4.MustUpdate(encoded) {
		t.Error("should not update because of less Iterations")
	}
}
