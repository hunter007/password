package password

import "testing"

func TestNewHasher(t *testing.T) {
	var opt *HasherOption

	_, err := NewHasher(opt)
	if err == nil {
		t.Errorf("NewHasher(nil) should be error")
	} else if err != errNilHasherOption {
		t.Errorf("NewHasher(nil) should be errNilHasherOption: %s", err)
	}
}
