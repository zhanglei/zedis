package server

import (
	"errors"

	"github.com/tidwall/redcon"
)

var (
	// ErrInvalidContext represents an invalid context error
	ErrInvalidContext = errors.New("Context in connection was not a zedis context")
)

// context represents a zedis connection context
type context struct {
	JWT string
}

// getContext receives an redcon connection and
// casts it's context value to a zedis context
// If casting/assertion fails, returns an error
func getContext(conn redcon.Conn) (context, error) {
	ctx, ok := conn.Context().(context)
	if !ok {
		return context{}, ErrInvalidContext
	}

	return ctx, nil
}
