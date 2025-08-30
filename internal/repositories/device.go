package repositories

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/sbilibin2017/bil-message-auth/internal/models"
)

type DeviceWriteRepository struct {
	db *sqlx.DB
}

// NewDeviceWriteRepository создаёт новый репозиторий устройств для записи
func NewDeviceWriteRepository(db *sqlx.DB) *DeviceWriteRepository {
	return &DeviceWriteRepository{db: db}
}

// Save вставляет новое устройство или обновляет user_uuid, public_key, updated_at, если device_uuid уже существует
func (repo *DeviceWriteRepository) Save(
	ctx context.Context,
	deviceUUID uuid.UUID,
	userUUID uuid.UUID,
	publicKey string,
) error {
	now := time.Now().UTC()

	query := `
		INSERT INTO devices (device_uuid, user_uuid, public_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (device_uuid) DO UPDATE
		SET user_uuid   = EXCLUDED.user_uuid,
		    public_key  = EXCLUDED.public_key,
		    updated_at  = $5
	`

	_, err := repo.db.ExecContext(ctx, query, deviceUUID, userUUID, publicKey, now, now)
	if err != nil {
		return err
	}

	return nil
}

type DeviceReadRepository struct {
	db *sqlx.DB
}

// NewDeviceReadRepository создаёт новый репозиторий устройств для чтения
func NewDeviceReadRepository(db *sqlx.DB) *DeviceReadRepository {
	return &DeviceReadRepository{db: db}
}

// GetByPublicKey возвращает устройство по public_key
func (repo *DeviceReadRepository) GetByPublicKey(ctx context.Context, publicKey string) (*models.DeviceDB, error) {
	var device models.DeviceDB
	query := `
		SELECT device_uuid, user_uuid, public_key, created_at, updated_at
		FROM devices
		WHERE public_key = $1
	`
	err := repo.db.GetContext(ctx, &device, query, publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

// ListDevicesByUserUUID возвращает все устройства для указанного userUUID
func (repo *DeviceReadRepository) ListDevicesByUserUUID(ctx context.Context, userUUID uuid.UUID) ([]*models.DeviceDB, error) {
	var devices []*models.DeviceDB
	query := `
		SELECT device_uuid, user_uuid, public_key, created_at, updated_at
		FROM devices
		WHERE user_uuid = $1
		ORDER BY created_at
	`
	err := repo.db.SelectContext(ctx, &devices, query, userUUID)
	if err != nil {
		return nil, err
	}
	return devices, nil
}

// GetByUserDeviceUUIDs возвращает устройство по userUUID и deviceUUID
func (repo *DeviceReadRepository) GetByUserDeviceUUIDs(ctx context.Context, userUUID uuid.UUID, deviceUUID uuid.UUID) (*models.DeviceDB, error) {
	var device models.DeviceDB
	query := `
		SELECT device_uuid, user_uuid, public_key, created_at, updated_at
		FROM devices
		WHERE user_uuid = $1 AND device_uuid = $2
	`
	err := repo.db.GetContext(ctx, &device, query, userUUID, deviceUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}
