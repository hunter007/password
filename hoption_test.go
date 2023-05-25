package passwordvalidator

import "testing"

func TestHasherOption(t *testing.T) {
	ho := &HasherOption{
		Algorithm: "non-algo",
	}

	if err := ho.validate(); err == nil {
		t.Errorf("ho.validate() should be error")
	}
	ho.Algorithm = md5Algo

	ho.Salt = "ad$dfd"
	err := ho.validate()
	if err == nil {
		t.Errorf("Salt: ho.validate() should be error")
	} else if err != errIllegalSalt {
		t.Errorf("Salt: error should be errIllegalSalt: %s", err)
	}

	ho.Salt = "adfedfd"
	err = ho.validate()
	if err == nil {
		t.Errorf("Iterations: ho.validate() should be error")
	} else if err != errIllegalIterations {
		t.Errorf("Iterations: error should be errIllegalIterations: %s", err)
	}
}
