package password

import (
	"errors"
	"fmt"
)

// Unknown algorithm.
var errUnknownAlgorithm = errors.New("unknown algorithm")

// Salt cannot contain '$'.
var errIllegalSalt = errors.New("salt cannot contain '$'")

// Iterations should be gratter than 0.
var errIllegalIterations = errors.New("iterations should be gratter than 0")

// Salt must be provided and cannot contain $.
var errBlankSalt = errors.New("salt must be provided and cannot contain $")

// MinLength should less than MaxLength
var errMinMax = errors.New("min_length should less than max_length")

// MinLength should more than 0
var errMin = errors.New("min_length should more than 0")

// MinLength should more than 0
var errMax = errors.New(fmt.Sprintf("max_length should less than %d", maxLengthPassword))

// This password is too common
var errCommon = errors.New("this password is too common")

// At least `length` characters.
func errMinLength(length int) error {
	return fmt.Errorf("this password is too short. It must contain at least %d characters", length)
}

// At most `length` characters.
func errMaxLength(length int) error {
	return fmt.Errorf("this password is too long. It must contain at most %d characters", length)
}
