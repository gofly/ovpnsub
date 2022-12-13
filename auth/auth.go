package auth

import (
	"context"
)

type AuthService interface {
	Authorize(ctx context.Context, username, password string) (string, error)
	VerifyToken(ctx context.Context, token string) (string, error)
}
