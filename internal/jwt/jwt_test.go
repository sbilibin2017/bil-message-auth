package jwt

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJWT_GenerateAndParse(t *testing.T) {
	j, err := New(WithSecretKey("my-secret"), WithExpiration(time.Minute))
	assert.NoError(t, err)

	userID := uuid.New()
	deviceID := uuid.New()

	t.Run("valid token", func(t *testing.T) {
		token, err := j.Generate(userID, deviceID)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		uuidUser, uuidDevice, err := j.Parse(context.Background(), token)
		assert.NoError(t, err)
		assert.Equal(t, userID, uuidUser)
		assert.Equal(t, deviceID, uuidDevice)
	})

	t.Run("expired token", func(t *testing.T) {
		// Generate a normal token first
		token, err := j.Generate(userID, deviceID)
		assert.NoError(t, err)

		// Manually parse and modify the claims to set expiration in the past
		_, _, err = j.Parse(context.Background(), token)
		assert.NoError(t, err)

		// Instead, create a new claims object with past expiration
		c := claims{
			UserUUID:   userID,
			DeviceUUID: deviceID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
			},
		}
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
		signedToken, err := expiredToken.SignedString(j.secretKey)
		assert.NoError(t, err)

		uuidUser, uuidDevice, err := j.Parse(context.Background(), signedToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is expired")
		assert.Equal(t, uuid.Nil, uuidUser)
		assert.Equal(t, uuid.Nil, uuidDevice)

	})
}

func TestJWT_GetFromHeader(t *testing.T) {
	j, _ := New()

	tests := []struct {
		name      string
		header    http.Header
		wantToken string
		wantErr   string
	}{
		{
			name:      "valid header",
			header:    http.Header{"Authorization": {"Bearer my-token"}},
			wantToken: "my-token",
		},
		{
			name:    "missing header",
			header:  http.Header{},
			wantErr: "missing authorization header",
		},
		{
			name:    "invalid prefix",
			header:  http.Header{"Authorization": {"Token my-token"}},
			wantErr: "invalid authorization header format",
		},
		{
			name:    "empty token",
			header:  http.Header{"Authorization": {"Bearer "}},
			wantErr: "empty token in authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := j.GetFromHeader(tt.header)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}

func TestJWT_NewWithOptions(t *testing.T) {
	tests := []struct {
		name    string
		secret  []string
		exp     []time.Duration
		wantErr bool
		wantExp time.Duration
		wantKey []byte
	}{
		{
			name:    "default values",
			secret:  []string{""},
			exp:     []time.Duration{0},
			wantErr: false,
			wantExp: time.Hour,
			wantKey: []byte("secret-key"),
		},
		{
			name:    "custom secret and expiration",
			secret:  []string{"abc123"},
			exp:     []time.Duration{2 * time.Hour},
			wantErr: false,
			wantExp: 2 * time.Hour,
			wantKey: []byte("abc123"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := New(WithSecretKey(tt.secret...), WithExpiration(tt.exp...))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantExp, j.exp)
				assert.Equal(t, tt.wantKey, j.secretKey)
			}
		})
	}
}
