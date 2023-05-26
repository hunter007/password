package password

import "testing"

func TestMustUpdateSalt(t *testing.T) {
	data := []struct {
		name         string
		salt         string
		shouldUpdate bool
	}{
		{
			name:         "salt is too short",
			salt:         "salt",
			shouldUpdate: true,
		},
		{
			name:         "correct salt",
			salt:         "saltsaltsaltsaltsaltsa",
			shouldUpdate: false,
		},
		{
			name:         "correct salt, max length is 11",
			salt:         "saltsaltsaltsaltsalts",
			shouldUpdate: false,
		},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			ret := mustUpdateSalt(d.salt, saltEntropy)
			if d.shouldUpdate {
				if d.shouldUpdate != ret {
					t.Error("bad salt")
				}
			} else {
				if d.shouldUpdate != ret {
					t.Error("bad salt should be updated")
				}
			}
		})
	}
}
