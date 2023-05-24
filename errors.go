package passwordvalidator

import (
	"errors"
	"fmt"
)

//=============================================================================
// hasher errors
//=============================================================================

// Unknown algorithm.
var errUnknownAlgorithm = errors.New("Unknown algorithm.")

// Salt cannot contain '$'.
var errIllegalSalt = errors.New("Salt cannot contain '$'.")

// Iterations should be gratter than 0.
var errIllegalIterations = errors.New("Iterations should be gratter than 0.")

// Salt must be provided and cannot contain $.
var errBlankSalt = errors.New("salt must be provided and cannot contain $.")

//=============================================================================
// validator errors
//=============================================================================

// MinLength should less than MaxLength
var errMinMax = errors.New("min_length should less than max_length")

// MinLength should more than 0
var errMin = errors.New("min_length should more than 0")

// MinLength should more than 0
var errMax = errors.New("min_length should more than 0")

// This password is too common
var errCommon = errors.New("This password is too common.")

// At least `length` characters.
func errMinLength(length int) error {
	return fmt.Errorf("This password is too short. It must contain at least %d characters.", length)
}

// At most `length` characters.
func errMaxLength(length int) error {
	return fmt.Errorf("This password is too long. It must contain at most %d characters.", length)
}
