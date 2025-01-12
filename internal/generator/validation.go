// Goal: Enforce 256bit key size, base64 encoding by default, ensure ID + Timestamp.

package keyGenerator

import (
	"encoding/base64"
	"fmt"
)

type ValidationError struct {
	Field   string
	Message string
}

type KeyValidationMech struct {
	MinKeyS              int
	MaxKeyS              int
	KeyFormatRequirement string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func NewKeyValidation() *KeyValidationMech {
	return &KeyValidationMech{
		MinKeyS:              32,
		MaxKeyS:              64,
		KeyFormatRequirement: "base64",
	}
}

func (v *KeyValidationMech) ValidateKey(keyPair *KeyPair) error {
	if len(keyPair.Key) < v.MinKeyS {
		return &ValidationError{
			Field:   "key_size",
			Message: fmt.Sprintf("key size %d is below minimum required size %d", len(keyPair.Key), v.MinKeyS),
		}
	}

	if len(keyPair.Key) > v.MaxKeyS {
		return &ValidationError{
			Field:   "key_size",
			Message: fmt.Sprintf("key size %d exceeds maximum allowed size %d", len(keyPair.Key), v.MaxKeyS),
		}
	}

	_, err := base64.StdEncoding.DecodeString(keyPair.EncodedKey)
	if err != nil {
		return &ValidationError{
			Field:   "encoding",
			Message: "invalid base64 encoding",
		}
	}

	if keyPair.ID == "" {
		return &ValidationError{
			Field:   "key_id",
			Message: "key ID cannot be empty",
		}
	}

	if keyPair.CreatedTime.IsZero() {
		return &ValidationError{
			Field:   "created_at",
			Message: "creation timestamp is not set",
		}
	}

	return nil
}

func (k *KeyPair) Validate() error {
	validator := NewKeyValidation()
	return validator.ValidateKey(k)
}
