package password

import (
	"strings"
	"testing"
)

func TestDefaultArgon2(t *testing.T) {
	opt := &HasherOption{
		Iterations: 1,
		Algorithm:  argon2Algo,
	}
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("err should be nil: %s", err)
	}
	password1, password2 := "123qweasd", "1qasw231w"
	encoded1, err := hasher.Encode(password1)
	if err != nil {
		t.Errorf("Encode(encoded1) should be ok: %s", err)
	}
	t.Logf("encoded1:  %s\n", encoded1)

	wrongEncoded := "aa" + encoded1
	_, err = hasher.Decode(wrongEncoded)
	if err != errUnknownAlgorithm {
		t.Errorf("Decode(wrongEncoded) should be errUnknownAlgorithm: %s", err)
	}

	parts := strings.SplitN(encoded1, sep, 7)
	iter := parts[2]

	parts[2] = "er"
	wrongIter := strings.Join(parts, sep)
	_, err = hasher.Decode(wrongIter)
	if err == nil {
		t.Error("Decode(wrongIter) should be error")
	}
	parts[2] = iter

	memory := parts[3]
	parts[3] = "er"
	wrongMemory := strings.Join(parts, sep)
	_, err = hasher.Decode(wrongMemory)
	if err == nil {
		t.Error("Decode(wrongMemory) should be error")
	}
	parts[3] = memory

	parallelism := parts[4]
	parts[4] = "er"
	wrongParallelism := strings.Join(parts, sep)
	_, err = hasher.Decode(wrongParallelism)
	if err == nil {
		t.Error("Decode(wrongMemory) should be error")
	}
	parts[4] = parallelism

	keyLength := parts[5]
	parts[5] = "er"
	wrongKeyLength := strings.Join(parts, sep)
	_, err = hasher.Decode(wrongKeyLength)
	if err == nil {
		t.Error("Decode(keyLength) should be error")
	}
	// Verify error
	if hasher.Verify(password1, wrongKeyLength) {
		t.Error("Verify(password1, wrongKeyLength) should be error")
	}
	parts[5] = keyLength

	encoded2, err := hasher.Encode(password2)
	if err != nil {
		t.Errorf("Encode(encoded2) should be ok: %s", err)
	}

	pi, err := hasher.Decode(encoded1)
	if err != nil {
		t.Errorf("Decode(encoded1) should be ok: %s", err)
	}
	p1, _ := pi.Others.(*Argon2Params)
	p2, _ := opt.Params.(*Argon2Params)
	if p2 != nil && *p1 != *p2 {
		t.Errorf("Params should be same")
	}

	if !hasher.Verify(password1, encoded1) {
		t.Errorf("Verify() should be true")
	}

	if hasher.Verify(password1, encoded2) {
		t.Errorf("Verify() should be false")
	}
}

func TestArgon2(t *testing.T) {
	opt := &HasherOption{
		Iterations: 1,
		Algorithm:  argon2Algo,
		Params: &Argon2Params{
			memory:      32 * 1024,
			iterations:  10,
			parallelism: 2,
			saltLength:  8,
			keyLength:   32,
		},
	}
	hasher, err := NewHasher(opt)
	if err != nil {
		t.Errorf("err should be nil: %s", err)
	}
	password1, password2 := "123qweasd", "1qasw231w"
	encoded1, err := hasher.Encode(password1)
	if err != nil {
		t.Errorf("Encode(encoded1) should be ok: %s", err)
	}

	encoded2, err := hasher.Encode(password2)
	if err != nil {
		t.Errorf("Encode(encoded2) should be ok: %s", err)
	}

	pi, err := hasher.Decode(encoded1)
	if err != nil {
		t.Errorf("Decode(encoded1) should be ok: %s", err)
	}
	p1, _ := pi.Others.(*Argon2Params)
	p2, _ := opt.Params.(*Argon2Params)
	if *p1 != *p2 {
		t.Errorf("Params should be same")
	}

	if !hasher.Verify(password1, encoded1) {
		t.Errorf("Verify() should be true")
	}

	if hasher.Verify(password1, encoded2) {
		t.Errorf("Verify() should be false")
	}
}

func TestMustUpdateForArgon2(t *testing.T) {
	opt := &HasherOption{
		Iterations: 1,
		Algorithm:  argon2Algo,
		Params: &Argon2Params{
			memory:      32 * 1024,
			iterations:  10,
			parallelism: 2,
			saltLength:  8,
			keyLength:   32,
		},
	}
	hasher, _ := NewHasher(opt)
	encoded, _ := hasher.Encode(password)

	if hasher.MustUpdate(encoded) {
		t.Error("should not updated")
	}

	opt2 := &HasherOption{
		Iterations: 1,
		Algorithm:  argon2Algo,
		Params: &Argon2Params{
			memory:      32 * 1024,
			iterations:  10,
			parallelism: 2,
			saltLength:  9,
			keyLength:   32,
		},
	}
	hasher, _ = NewHasher(opt2)
	if !hasher.MustUpdate(encoded) {
		t.Error("should updated because of different param")
	}
}
