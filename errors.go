package pooldap

import "github.com/pkg/errors"

var (
	ErrNotFound          = errors.New("object not found")
	ErrNotUnique         = errors.New("too many entries returned")
	ErrDnNotFound        = errors.New("user 'dn' not found in attributes")
	ErrAttributeNotFound = errors.New("attribute not found")
)
