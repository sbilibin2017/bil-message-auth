package jwt

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWT представляет работу с JWT-токенами.
type JWT struct {
	secretKey []byte
	exp       time.Duration
}

// Opt — функциональная опция для настройки JWT.
type Opt func(*JWT) error

// New создаёт новый JWT, применяя указанные опции.
func New(opts ...Opt) (*JWT, error) {
	j := &JWT{
		secretKey: []byte("secret-key"),
		exp:       time.Hour,
	}
	for _, opt := range opts {
		if err := opt(j); err != nil {
			return nil, err
		}
	}
	return j, nil
}

// WithSecretKey задаёт секретный ключ. Используется первое непустое значение.
func WithSecretKey(secret ...string) Opt {
	return func(j *JWT) error {
		for _, s := range secret {
			if s != "" {
				j.secretKey = []byte(s)
				return nil
			}
		}
		return nil
	}
}

// WithExpiration задаёт время жизни токена. Используется первое положительное значение.
func WithExpiration(exp ...time.Duration) Opt {
	return func(j *JWT) error {
		for _, e := range exp {
			if e > 0 {
				j.exp = e
				return nil
			}
		}
		return nil
	}
}

// claims — структура для хранения полезной нагрузки токена.
type claims struct {
	UserUUID   uuid.UUID `json:"user_uuid"`
	DeviceUUID uuid.UUID `json:"device_uuid"`
	jwt.RegisteredClaims
}

// Generate создаёт JWT-токен.
func (j *JWT) Generate(userUUID uuid.UUID, deviceUUID uuid.UUID) (string, error) {
	c := claims{
		UserUUID:   userUUID,
		DeviceUUID: deviceUUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.exp)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString(j.secretKey)
}

// Parse парсит токен и проверяет его срок действия.
func (j *JWT) Parse(ctx context.Context, tokenString string) (userUUID uuid.UUID, deviceUUID uuid.UUID, err error) {
	c := &claims{}

	token, err := jwt.ParseWithClaims(tokenString, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.secretKey, nil
	})
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	claims, ok := token.Claims.(*claims)
	if !ok {
		return uuid.Nil, uuid.Nil, errors.New("invalid token claims")
	}

	if claims.ExpiresAt != nil && !claims.ExpiresAt.Time.IsZero() && claims.ExpiresAt.Time.Before(time.Now()) {
		return uuid.Nil, uuid.Nil, errors.New("token expired")
	}

	return claims.UserUUID, claims.DeviceUUID, nil
}

// GetFromHeader извлекает токен из заголовка Authorization.
func (j *JWT) GetFromHeader(header http.Header) (string, error) {
	const prefix = "Bearer "
	authHeader := header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, prefix) {
		return "", errors.New("invalid authorization header format")
	}

	token := strings.TrimSpace(authHeader[len(prefix):])
	if token == "" {
		return "", errors.New("empty token in authorization header")
	}

	return token, nil
}
