package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceDB представляет запись устройства пользователя из таблицы devices
type DeviceDB struct {
	DeviceUUID uuid.UUID `json:"device_uuid" db:"device_uuid"` // уникальный идентификатор устройства
	UserUUID   uuid.UUID `json:"user_uuid" db:"user_uuid"`     // идентификатор пользователя, которому принадлежит устройство
	PublicKey  string    `json:"public_key" db:"public_key"`   // публичный ключ устройства, уникальный для каждого устройства
	CreatedAt  time.Time `json:"created_at" db:"created_at"`   // время создания записи устройства
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`   // время последнего обновления записи устройства
}
