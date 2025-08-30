package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/stretchr/testify/assert"
	_ "modernc.org/sqlite"
)

func setupDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Connect("sqlite", ":memory:")
	assert.NoError(t, err)

	schema := `
	CREATE TABLE users (
		user_uuid TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(schema)
	assert.NoError(t, err)
	return db
}

func TestUserWriteAndReadRepository(t *testing.T) {
	db := setupDB(t)
	defer db.Close()

	writeRepo := NewUserWriteRepository(db)
	readRepo := NewUserReadRepository(db)

	ctx := context.Background()
	userUUID := uuid.New()
	username := "alice"
	passwordHash := "secret"

	// Сохраняем пользователя
	err := writeRepo.Save(ctx, userUUID, username, passwordHash)
	assert.NoError(t, err)

	// Проверяем чтение
	user, err := readRepo.GetByUsername(ctx, username)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, userUUID, user.UserUUID)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, passwordHash, user.PasswordHash)

	// Обновляем пользователя
	newUsername := "alice_updated"
	newHash := "new_secret"
	err = writeRepo.Save(ctx, userUUID, newUsername, newHash)
	assert.NoError(t, err)

	userUpdated, err := readRepo.GetByUsername(ctx, newUsername)
	assert.NoError(t, err)
	assert.NotNil(t, userUpdated)
	assert.Equal(t, userUUID, userUpdated.UserUUID)
	assert.Equal(t, newUsername, userUpdated.Username)
	assert.Equal(t, newHash, userUpdated.PasswordHash)

	// Проверяем, что old username больше не существует
	userOld, err := readRepo.GetByUsername(ctx, username)
	assert.NoError(t, err)
	assert.Nil(t, userOld)
}

func TestSaveConflictExistingUUID(t *testing.T) {
	db := setupDB(t)
	defer db.Close()

	writeRepo := NewUserWriteRepository(db)

	ctx := context.Background()
	userUUID := uuid.New()
	username := "bob"
	hash1 := "hash1"
	hash2 := "hash2"

	// Создаём пользователя
	err := writeRepo.Save(ctx, userUUID, username, hash1)
	assert.NoError(t, err)

	// Обновляем того же пользователя
	err = writeRepo.Save(ctx, userUUID, "bob_updated", hash2)
	assert.NoError(t, err)

	user, err := NewUserReadRepository(db).GetByUsername(ctx, "bob_updated")
	assert.NoError(t, err)
	assert.Equal(t, userUUID, user.UserUUID)
	assert.Equal(t, hash2, user.PasswordHash)
}

func TestGetByUUID(t *testing.T) {
	db := setupDB(t)
	defer db.Close()

	writeRepo := NewUserWriteRepository(db)
	readRepo := NewUserReadRepository(db)

	ctx := context.Background()
	userUUID := uuid.New()
	username := "charlie"
	passwordHash := "supersecret"

	// Сохраняем пользователя
	err := writeRepo.Save(ctx, userUUID, username, passwordHash)
	assert.NoError(t, err)

	// Читаем пользователя по UUID
	user, err := readRepo.GetByUUID(ctx, userUUID)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, userUUID, user.UserUUID)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, passwordHash, user.PasswordHash)

	// Проверяем несуществующий UUID
	nonExistentUUID := uuid.New()
	userNil, err := readRepo.GetByUUID(ctx, nonExistentUUID)
	assert.NoError(t, err)
	assert.Nil(t, userNil)
}
