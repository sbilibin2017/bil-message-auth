package repositories

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/sbilibin2017/bil-message-auth/internal/models"
)

type UserWriteRepository struct {
	db *sqlx.DB
}

// NewUserWriteRepository создаёт новый репозиторий пользователей
func NewUserWriteRepository(db *sqlx.DB) *UserWriteRepository {
	return &UserWriteRepository{db: db}
}

// Save вставляет нового пользователя или обновляет username, password_hash, updated_at, если user_uuid уже существует
func (repo *UserWriteRepository) Save(
	ctx context.Context,
	userUUID uuid.UUID,
	username string,
	passwordHash string,
) error {
	now := time.Now().UTC()

	query := `
		INSERT INTO users (user_uuid, username, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_uuid) DO UPDATE
		SET username = EXCLUDED.username,
		    password_hash = EXCLUDED.password_hash,
		    updated_at = $5
	`

	_, err := repo.db.ExecContext(ctx, query, userUUID, username, passwordHash, now, now)
	if err != nil {
		return err
	}

	return nil
}

type UserReadRepository struct {
	db *sqlx.DB
}

// NewUserReadRepository создаёт новый репозиторий для чтения пользователей
func NewUserReadRepository(db *sqlx.DB) *UserReadRepository {
	return &UserReadRepository{db: db}
}

// GetByUsername возвращает пользователя по username
func (repo *UserReadRepository) GetByUsername(ctx context.Context, username string) (*models.UserDB, error) {
	var user models.UserDB
	query := `
		SELECT user_uuid, username, password_hash, created_at, updated_at
		FROM users
		WHERE username = $1
	`
	err := repo.db.GetContext(ctx, &user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetByUUID возвращает пользователя по его UUID
func (repo *UserReadRepository) GetByUUID(ctx context.Context, userUUID uuid.UUID) (*models.UserDB, error) {
	var user models.UserDB
	query := `
		SELECT user_uuid, username, password_hash, created_at, updated_at
		FROM users
		WHERE user_uuid = $1
	`
	err := repo.db.GetContext(ctx, &user, query, userUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}
