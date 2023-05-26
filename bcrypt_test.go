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
