package models

import (
	"time"

	"github.com/google/uuid"
)

// UserDB представляет запись пользователя из таблицы users
type UserDB struct {
	UserUUID     uuid.UUID `json:"user_uuid" db:"user_uuid"`         // Уникальный идентификатор пользователя
	Username     string    `json:"username" db:"username"`           // Имя пользователя
	PasswordHash string    `json:"password_hash" db:"password_hash"` // Хэш пароля пользователя
	CreatedAt    time.Time `json:"created_at" db:"created_at"`       // Время создания записи пользователя
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`       // Время последнего обновления записи пользователя
}
