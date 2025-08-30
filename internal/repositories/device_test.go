package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	_ "modernc.org/sqlite"
)

func setupDeviceDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Connect("sqlite", ":memory:")
	assert.NoError(t, err)

	schema := `
	CREATE TABLE devices (
		device_uuid TEXT PRIMARY KEY,
		user_uuid TEXT NOT NULL,
		public_key TEXT UNIQUE NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(schema)
	assert.NoError(t, err)
	return db
}

func TestDeviceWriteAndReadRepository(t *testing.T) {
	db := setupDeviceDB(t)
	defer db.Close()

	writeRepo := NewDeviceWriteRepository(db)
	readRepo := NewDeviceReadRepository(db)

	ctx := context.Background()
	deviceUUID := uuid.New()
	userUUID := uuid.New()
	publicKey := "pubkey1"

	// Сохраняем устройство
	err := writeRepo.Save(ctx, deviceUUID, userUUID, publicKey)
	assert.NoError(t, err)

	// Проверяем чтение
	device, err := readRepo.GetByPublicKey(ctx, publicKey)
	assert.NoError(t, err)
	assert.NotNil(t, device)
	assert.Equal(t, deviceUUID, device.DeviceUUID)
	assert.Equal(t, userUUID, device.UserUUID)
	assert.Equal(t, publicKey, device.PublicKey)

	// Обновляем устройство
	newUserUUID := uuid.New()
	newPublicKey := "pubkey2"
	err = writeRepo.Save(ctx, deviceUUID, newUserUUID, newPublicKey)
	assert.NoError(t, err)

	deviceUpdated, err := readRepo.GetByPublicKey(ctx, newPublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, deviceUpdated)
	assert.Equal(t, deviceUUID, deviceUpdated.DeviceUUID)
	assert.Equal(t, newUserUUID, deviceUpdated.UserUUID)
	assert.Equal(t, newPublicKey, deviceUpdated.PublicKey)

	// Проверяем, что старый publicKey больше не существует
	deviceOld, err := readRepo.GetByPublicKey(ctx, publicKey)
	assert.NoError(t, err)
	assert.Nil(t, deviceOld)
}

func TestSaveConflictExistingUUID_Device(t *testing.T) {
	db := setupDeviceDB(t)
	defer db.Close()

	writeRepo := NewDeviceWriteRepository(db)

	ctx := context.Background()
	deviceUUID := uuid.New()
	userUUID := uuid.New()
	pub1 := "pubkeyA"
	pub2 := "pubkeyB"

	// Создаём устройство
	err := writeRepo.Save(ctx, deviceUUID, userUUID, pub1)
	assert.NoError(t, err)

	// Обновляем то же устройство
	newUserUUID := uuid.New()
	err = writeRepo.Save(ctx, deviceUUID, newUserUUID, pub2)
	assert.NoError(t, err)

	device, err := NewDeviceReadRepository(db).GetByPublicKey(ctx, pub2)
	assert.NoError(t, err)
	assert.NotNil(t, device)
	assert.Equal(t, deviceUUID, device.DeviceUUID)
	assert.Equal(t, newUserUUID, device.UserUUID)
	assert.Equal(t, pub2, device.PublicKey)
}

func TestListDevicesByUserUUID(t *testing.T) {
	db := setupDeviceDB(t)
	defer db.Close()

	writeRepo := NewDeviceWriteRepository(db)
	readRepo := NewDeviceReadRepository(db)

	ctx := context.Background()
	userUUID := uuid.New()

	// Добавляем несколько устройств для одного пользователя
	devices := []struct {
		deviceUUID uuid.UUID
		publicKey  string
	}{
		{uuid.New(), "key1"},
		{uuid.New(), "key2"},
		{uuid.New(), "key3"},
	}

	for _, d := range devices {
		err := writeRepo.Save(ctx, d.deviceUUID, userUUID, d.publicKey)
		assert.NoError(t, err)
	}

	// Добавляем устройство для другого пользователя, чтобы убедиться, что фильтрация работает
	err := writeRepo.Save(ctx, uuid.New(), uuid.New(), "otherkey")
	assert.NoError(t, err)

	// Получаем список устройств по userUUID
	list, err := readRepo.ListDevicesByUserUUID(ctx, userUUID)
	assert.NoError(t, err)
	assert.Len(t, list, len(devices))

	// Проверяем, что все устройства вернулись корректно и отсортированы по created_at
	for i, d := range devices {
		assert.Equal(t, d.deviceUUID, list[i].DeviceUUID)
		assert.Equal(t, userUUID, list[i].UserUUID)
		assert.Equal(t, d.publicKey, list[i].PublicKey)
	}
}

func TestGetByUserDeviceUUIDs(t *testing.T) {
	db := setupDeviceDB(t)
	defer db.Close()

	writeRepo := NewDeviceWriteRepository(db)
	readRepo := NewDeviceReadRepository(db)

	ctx := context.Background()
	userUUID := uuid.New()
	deviceUUID := uuid.New()
	publicKey := "pubkeyXYZ"

	// Сохраняем устройство
	err := writeRepo.Save(ctx, deviceUUID, userUUID, publicKey)
	assert.NoError(t, err)

	// Получаем устройство по userUUID и deviceUUID
	device, err := readRepo.GetByUserDeviceUUIDs(ctx, userUUID, deviceUUID)
	assert.NoError(t, err)
	assert.NotNil(t, device)
	assert.Equal(t, deviceUUID, device.DeviceUUID)
	assert.Equal(t, userUUID, device.UserUUID)
	assert.Equal(t, publicKey, device.PublicKey)

	// Проверяем случай, когда deviceUUID не существует
	deviceNotFound, err := readRepo.GetByUserDeviceUUIDs(ctx, userUUID, uuid.New())
	assert.NoError(t, err)
	assert.Nil(t, deviceNotFound)

	// Проверяем случай, когда userUUID не существует
	deviceNotFound2, err := readRepo.GetByUserDeviceUUIDs(ctx, uuid.New(), deviceUUID)
	assert.NoError(t, err)
	assert.Nil(t, deviceNotFound2)
}
