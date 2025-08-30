package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/sbilibin2017/bil-message-auth/internal/models"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrInvalidCredentials  = errors.New("invalid username or password")
	ErrDeviceNotRegistered = errors.New("device is not registered")
)

// UserWriter представляет интерфейс для записи пользователей в хранилище.
type UserWriter interface {
	Save(ctx context.Context, userUUID uuid.UUID, username string, passwordHash string) error
}

// UserReader представляет интерфейс для чтения пользователей из хранилища.
type UserReader interface {
	GetByUsername(ctx context.Context, username string) (*models.UserDB, error)
	GetByUUID(ctx context.Context, userUUID uuid.UUID) (*models.UserDB, error)
}

// DeviceWriter представляет интерфейс для записи устройств в хранилище.
type DeviceWriter interface {
	Save(ctx context.Context, deviceUUID uuid.UUID, userUUID uuid.UUID, publicKey string) error
}

// DeviceReader представляет интерфейс для чтения устройств из хранилища.
type DeviceReader interface {
	GetByPublicKey(ctx context.Context, publicKey string) (*models.DeviceDB, error)
	ListDevicesByUserUUID(ctx context.Context, userUUID uuid.UUID) ([]*models.DeviceDB, error)
	GetByUserDeviceUUIDs(ctx context.Context, userUUID uuid.UUID, deviceUUID uuid.UUID) (*models.DeviceDB, error)
}

// AuthService предоставляет методы для аутентификации и управления пользователями и устройствами.
type AuthService struct {
	uw UserWriter
	ur UserReader
	dw DeviceWriter
	dr DeviceReader
}

// AuthServiceOption представляет функциональный параметр для конфигурации AuthService.
type AuthServiceOption func(*AuthService)

// NewAuthService создаёт новый AuthService с указанными опциями.
func NewAuthService(opts ...AuthServiceOption) *AuthService {
	svc := &AuthService{}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// WithUserWriter задаёт UserWriter для AuthService.
func WithUserWriter(uw UserWriter) AuthServiceOption {
	return func(s *AuthService) {
		s.uw = uw
	}
}

// WithUserReader задаёт UserReader для AuthService.
func WithUserReader(ur UserReader) AuthServiceOption {
	return func(s *AuthService) {
		s.ur = ur
	}
}

// WithDeviceWriter задаёт DeviceWriter для AuthService.
func WithDeviceWriter(dw DeviceWriter) AuthServiceOption {
	return func(s *AuthService) {
		s.dw = dw
	}
}

// WithDeviceReader задаёт DeviceReader для AuthService.
func WithDeviceReader(dr DeviceReader) AuthServiceOption {
	return func(s *AuthService) {
		s.dr = dr
	}
}

// RegisterUser регистрирует нового пользователя с указанным username и password.
// Возвращает ErrUserAlreadyExists, если пользователь с таким именем уже существует.
func (svc *AuthService) RegisterUser(
	ctx context.Context,
	username string,
	password string,
) error {
	// Проверяем, существует ли уже пользователь с таким username
	existingUser, err := svc.ur.GetByUsername(ctx, username)
	if err != nil {
		return err
	}
	if existingUser != nil {
		return ErrUserAlreadyExists
	}

	// Хэшируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Сохраняем пользователя через репозиторий
	if err := svc.uw.Save(ctx, uuid.New(), username, string(hash)); err != nil {
		return err
	}

	return nil
}

// RegisterDevice регистрирует новое устройство для пользователя.
// Проверяет правильность username и password, а также уникальность publicKey устройства.
func (svc *AuthService) RegisterDevice(
	ctx context.Context,
	username string,
	password string,
	publicKey string,
) error {
	// 1. Проверяем, что пользователь существует
	user, err := svc.ur.GetByUsername(ctx, username)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrInvalidCredentials
	}

	// 2. Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	// 3. Проверяем, зарегистрировано ли уже устройство с таким ключом
	existingDevice, err := svc.dr.GetByPublicKey(ctx, publicKey)
	if err != nil {
		return err
	}
	if existingDevice != nil {
		return nil
	}

	// 4. Генерируем новый deviceUUID
	deviceUUID := uuid.New()

	if err := svc.dw.Save(ctx, deviceUUID, user.UserUUID, publicKey); err != nil {
		return err
	}

	return nil
}

// Login проверяет username, password и publicKey устройства.
// Возвращает userUUID и deviceUUID при успешной аутентификации.
// Если устройство не зарегистрировано — возвращает ErrDeviceNotRegistered.
func (svc *AuthService) Login(
	ctx context.Context,
	username string,
	password string,
	publicKey string,
) (userUUID uuid.UUID, deviceUUID uuid.UUID, err error) {
	// 1. Проверяем, что пользователь существует
	user, err := svc.ur.GetByUsername(ctx, username)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if user == nil {
		return uuid.Nil, uuid.Nil, ErrInvalidCredentials
	}

	// 2. Проверяем правильность пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return uuid.Nil, uuid.Nil, ErrInvalidCredentials
	}

	// 3. Проверяем, зарегистрировано ли устройство с таким ключом
	device, err := svc.dr.GetByPublicKey(ctx, publicKey)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if device == nil {
		return uuid.Nil, uuid.Nil, ErrDeviceNotRegistered
	}

	return user.UserUUID, device.DeviceUUID, nil
}

// ListUserDevices возвращает список всех устройств пользователя по его UUID.
// Если пользователь не найден — возвращает ErrInvalidCredentials.
func (svc *AuthService) ListUserDevices(
	ctx context.Context,
	userUUID uuid.UUID,
) ([]*models.DeviceDB, error) {
	// 1. Проверяем, что пользователь существует
	user, err := svc.ur.GetByUUID(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}

	devices, err := svc.dr.ListDevicesByUserUUID(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	return devices, nil
}

// GetUserDevice возвращает устройство пользователя по userUUID и deviceUUID.
// Если устройство не найдено — возвращает nil без ошибки.
func (svc *AuthService) GetUserDevice(
	ctx context.Context,
	userUUID uuid.UUID,
	deviceUUID uuid.UUID,
) (*models.DeviceDB, error) {
	return svc.dr.GetByUserDeviceUUIDs(ctx, userUUID, deviceUUID)
}
