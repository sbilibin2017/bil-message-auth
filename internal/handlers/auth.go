package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sbilibin2017/bil-message-auth/internal/models"
	"github.com/sbilibin2017/bil-message-auth/internal/services"
)

// UserRegisterer — интерфейс для регистрации пользователя
type UserRegisterer interface {
	RegisterUser(ctx context.Context, username string, password string) error
}

// DeviceRegisterer — интерфейс для регистрации устройства
type DeviceRegisterer interface {
	RegisterDevice(ctx context.Context, username string, password string, publicKey string) error
}

// UserLoginer — интерфейс для регистрации пользователя
type UserLoginer interface {
	Login(ctx context.Context, username string, password string, publicKey string) (userUUID uuid.UUID, deviceUUID uuid.UUID, err error)
}

// DeviceLister — интерфейс для получения устройств пользователя
type DeviceLister interface {
	ListUserDevices(ctx context.Context, userUUID uuid.UUID) ([]*models.DeviceDB, error)
}

type UserDeviceGetter interface {
	GetUserDevice(ctx context.Context, userUUID uuid.UUID, deviceUUID uuid.UUID) (*models.DeviceDB, error)
}

// Tokener — интерфейс для генерации jwt
type Tokener interface {
	Generate(userUUID uuid.UUID, deviceUUID uuid.UUID) (string, error)
	GetFromHeader(header http.Header) (string, error)
	Parse(ctx context.Context, tokenString string) (userUUID uuid.UUID, deviceUUID uuid.UUID, err error)
}

// RegisterRequest представляет JSON тело запроса на регистрацию.
// swagger:model RegisterUserRequest
type RegisterUserRequest struct {
	// Username пользователя
	// required: true
	// example: johndoe
	Username string `json:"username"`

	// Пароль пользователя
	// required: true
	// example: mySecret123
	Password string `json:"password"`
}

// RegisterDeviceRequest представляет JSON тело запроса на регистрацию устройства.
// swagger:model RegisterDeviceRequest
type RegisterDeviceRequest struct {
	// Username пользователя
	// required: true
	// example: johndoe
	Username string `json:"username"`

	// Пароль пользователя
	// required: true
	// example: mySecret123
	Password string `json:"password"`

	// Публичный ключ устройства (raw string)
	// required: true
	// example: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE...
	PublicKey string `json:"public_key"`
}

// DeviceResponse представляет JSON ответ для одного устройства
// swagger:model DeviceResponse
type DeviceResponse struct {
	// Уникальный идентификатор устройства
	// example: 550e8400-e29b-41d4-a716-446655440000
	DeviceUUID uuid.UUID `json:"device_uuid"`

	// UUID пользователя, которому принадлежит устройство
	// example: 550e8400-e29b-41d4-a716-446655440001
	UserUUID uuid.UUID `json:"user_uuid"`

	// Публичный ключ устройства
	// example: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE...
	PublicKey string `json:"public_key"`

	// Дата и время создания устройства в формате RFC3339
	// example: 2025-08-30T12:34:56Z
	CreatedAt string `json:"created_at"`

	// Дата и время последнего обновления устройства в формате RFC3339
	// example: 2025-08-30T12:34:56Z
	UpdatedAt string `json:"updated_at"`
}

// LoginRequest представляет JSON тело запроса на логин.
// swagger:model LoginRequest
type LoginRequest struct {
	// Username пользователя
	// required: true
	// example: johndoe
	Username string `json:"username"`

	// Пароль пользователя
	// required: true
	// example: mySecret123
	Password string `json:"password"`

	// Публичный ключ устройства
	// required: true
	// example: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE...
	PublicKey string `json:"public_key"`
}

// UserDeviceResponse представляет JSON ответ для устройства пользователя
// swagger:model UserDeviceResponse
type UserDeviceResponse struct {
	// Уникальный идентификатор устройства
	// example: 550e8400-e29b-41d4-a716-446655440000
	DeviceUUID uuid.UUID `json:"device_uuid"`

	// UUID пользователя, которому принадлежит устройство
	// example: 550e8400-e29b-41d4-a716-446655440001
	UserUUID uuid.UUID `json:"user_uuid"`

	// Публичный ключ устройства
	// example: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE...
	PublicKey string `json:"public_key"`

	// Дата и время создания устройства в формате RFC3339
	// example: 2025-08-30T12:34:56Z
	CreatedAt string `json:"created_at"`

	// Дата и время последнего обновления устройства в формате RFC3339
	// example: 2025-08-30T12:34:56Z
	UpdatedAt string `json:"updated_at"`
}

// NewRegisterUserHandler создаёт HTTP-обработчик регистрации пользователя
// @Summary Регистрация нового пользователя
// @Description Создаёт нового пользователя с заданными username и password
// @Tags Auth
// @Accept json
// @Produce plain
// @Param request body RegisterUserRequest true "Данные пользователя"
// @Success 200 "Пользователь успешно зарегистрирован"
// @Failure 400 "Некорректные данные запроса"
// @Failure 409 "Пользователь с таким именем уже существует"
// @Failure 500 "Внутренняя ошибка сервера"
// @Router /auth/register/user [post]
func NewRegisterUserHandler(svc UserRegisterer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if err := svc.RegisterUser(r.Context(), req.Username, req.Password); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}
}

// NewRegisterDeviceHandler создаёт HTTP-обработчик регистрации устройства
// @Summary Регистрация нового устройства для существующего пользователя
// @Description Добавляет новое устройство (публичный ключ) для существующего пользователя
// @Tags Auth
// @Accept json
// @Produce plain
// @Param request body RegisterDeviceRequest true "Данные устройства"
// @Success 200 "Устройство успешно зарегистрировано"
// @Failure 400 "Некорректные данные запроса или неверные учетные данные"
// @Failure 409 "Устройство уже зарегистрировано"
// @Failure 500 "Внутренняя ошибка сервера"
// @Router /auth/register/device [post]
func NewRegisterDeviceHandler(svc DeviceRegisterer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterDeviceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		err := svc.RegisterDevice(r.Context(), req.Username, req.Password, req.PublicKey)
		if err != nil {
			switch err {
			case services.ErrInvalidCredentials:
				w.WriteHeader(http.StatusBadRequest)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// NewLoginHandler создаёт HTTP-обработчик логина пользователя
// @Summary Логин пользователя
// @Description Проверяет учетные данные пользователя и возвращает токен
// @Tags Auth
// @Accept json
// @Produce plain
// @Param request body LoginRequest true "Данные для логина"
// @Success 200 "Успешный логин, токен возвращается в теле"
// @Failure 400 "Некорректные данные запроса или неверные учетные данные"
// @Failure 500 "Внутренняя ошибка сервера"
// @Router /auth/login [post]
func NewLoginHandler(svc UserLoginer, tr Tokener) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		userUUID, deviceUUID, err := svc.Login(r.Context(), req.Username, req.Password, req.PublicKey)
		if err != nil {
			switch err {
			case services.ErrInvalidCredentials, services.ErrDeviceNotRegistered:
				w.WriteHeader(http.StatusBadRequest)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		tokenString, err := tr.Generate(userUUID, deviceUUID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(tokenString))
	}
}

// NewUserHandler создаёт HTTP-обработчик для получения информации о пользователе
// @Summary Получить информацию о пользователе
// @Description Возвращает данные пользователя по токену
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен"
// @Success 200 {object} UserDeviceResponse
// @Failure 400 "Некорректный токен"
// @Failure 404 "Пользователь не найден"
// @Failure 500 "Внутренняя ошибка сервера"
// @Router /auth/user [get]
func NewUserHandler(svc UserDeviceGetter, tr Tokener) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка Authorization
		tokenString, err := tr.GetFromHeader(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Парсим токен, получаем UUID пользователя
		userUUID, deviceUUID, err := tr.Parse(r.Context(), tokenString)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Получаем устройство пользователя из сервиса
		userDevice, err := svc.GetUserDevice(r.Context(), userUUID, deviceUUID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if userDevice == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Формируем ответ с UserDeviceResponse
		resp := UserDeviceResponse{
			DeviceUUID: userDevice.DeviceUUID,
			UserUUID:   userDevice.UserUUID,
			PublicKey:  userDevice.PublicKey,
			CreatedAt:  userDevice.CreatedAt.Format(time.RFC3339),
			UpdatedAt:  userDevice.UpdatedAt.Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// NewUserDeviceListHandler создаёт HTTP-обработчик для получения списка устройств пользователя
// @Summary Получить список устройств пользователя
// @Description Возвращает список всех устройств, зарегистрированных для пользователя
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен"
// @Success 200 {array} DeviceResponse
// @Failure 400 "Некорректный токен"
// @Failure 404 "Пользователь не найден"
// @Failure 500 "Внутренняя ошибка сервера"
// @Router /auth/user/devices [get]
func NewUserDeviceListHandler(svc DeviceLister, tr Tokener) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка Authorization
		tokenString, err := tr.GetFromHeader(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Декодируем токен
		userUUID, _, err := tr.Parse(r.Context(), tokenString)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Получаем устройства пользователя
		devices, err := svc.ListUserDevices(r.Context(), userUUID)
		if err != nil {
			if err == services.ErrInvalidCredentials {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		// Формируем ответ
		resp := make([]DeviceResponse, len(devices))
		for i, d := range devices {
			resp[i] = DeviceResponse{
				DeviceUUID: d.DeviceUUID,
				UserUUID:   d.UserUUID,
				PublicKey:  d.PublicKey,
				CreatedAt:  d.CreatedAt.Format(time.RFC3339),
				UpdatedAt:  d.UpdatedAt.Format(time.RFC3339),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
