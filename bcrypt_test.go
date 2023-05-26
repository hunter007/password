/*
bcrypt example:

$  2a  $ 11 $ zKTTgVR.DRjGv1QkiT5l . AkXjrkxpX5CR/IrTRc1tk.el9Mqvd2
Prefix Cost   Salt                   Hashed Text
*/
package password

import "testing"

func TestBcryptSha256(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  bcryptSha256Algo,
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

func TestBcrypt(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  bcryptAlgo,
		Salt:       "salt",
		Iterations: 1,
	}
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("failed to new %s hasher: %s", opt.Algorithm, err)
	}

	encoded, err := hasher.Encode(password)
	if err != nil {
		t.Errorf("failed to encode password with %s: %s", opt.Algorithm, err)
	}
	t.Logf("encoded password: %s", encoded)

	wrongEncoded := "AA" + encoded
	_, err = hasher.Decode(wrongEncoded)
	if err == nil {
		t.Error("Decode(wrongEncoded) should be err")
	}
	pi, err := hasher.Decode(encoded)
	if err != nil {
		t.Errorf("Decode(encoded) should be nil: %s", err)
	}
	if pi == nil {
		t.Error("Decode(encoded) pi should not be nil")
	}
	if pi != nil && pi.Algorithm != opt.Algorithm {
		t.Errorf("wrong pi %s != %s", pi.Algorithm, opt.Algorithm)
	}

	if hasher.Verify(password, wrongEncoded) {
		t.Error("should decode error")
	}

	if !hasher.Verify(password, encoded) {
		t.Errorf("wrong algorithm: %s", opt.Algorithm)
	}
}

func TestMustUpdateForBcrypt(t *testing.T) {
	opt := &HasherOption{
		Algorithm:  bcryptAlgo,
		Salt:       "salt",
		Iterations: 12,
	}
	hasher, _ := NewHasher(opt)
	encoded, _ := hasher.Encode(password)
	if hasher.MustUpdate(encoded) {
		t.Error("should not update")
	}

	opt2 := &HasherOption{
		Algorithm:  bcryptAlgo,
		Salt:       "saltsaltsaltsalt",
		Iterations: 12,
	}
	hasher, _ = NewHasher(opt2)
	if hasher.MustUpdate(encoded) {
		t.Error("should not update because of no use salt")
	}

	opt3 := &HasherOption{
		Algorithm:  bcryptAlgo,
		Salt:       "saltsaltsaltsa",
		Iterations: 14,
	}
	hasher, _ = NewHasher(opt3)
	if !hasher.MustUpdate(encoded) {
		t.Error("should update because of bigger cost")
	}

	opt4 := &HasherOption{
		Algorithm:  bcryptAlgo,
		Salt:       "saltsaltsaltsa",
		Iterations: 11,
	}
	hasher, _ = NewHasher(opt4)
	if hasher.MustUpdate(encoded) {
		t.Error("should not update because of smaller cost")
	}
}
