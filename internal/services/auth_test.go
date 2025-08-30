package services

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sbilibin2017/bil-message-auth/internal/models"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_RegisterUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	username := "alice"
	password := "secret"

	mockUR := NewMockUserReader(ctrl)
	mockUW := NewMockUserWriter(ctrl)

	tests := []struct {
		name      string
		setupMock func()
		wantErr   error
	}{
		{
			name: "new user",
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, nil)
				mockUW.EXPECT().Save(gomock.Any(), gomock.Any(), username, gomock.Any()).Return(nil)
			},
			wantErr: nil,
		},
		{
			name: "user exists",
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(&models.UserDB{Username: username, UserUUID: uuid.New()}, nil)
			},
			wantErr: ErrUserAlreadyExists,
		},
		{
			name: "repo error",
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, errors.New("db error"))
			},
			wantErr: errors.New("db error"),
		},
		{
			name: "save user error",
			setupMock: func() {
				// Пользователь не существует
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, nil)
				// Репозиторий возвращает ошибку при сохранении
				mockUW.EXPECT().Save(gomock.Any(), gomock.Any(), username, gomock.Any()).
					Return(errors.New("save error"))
			},
			wantErr: errors.New("save error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			svc := NewAuthService(WithUserReader(mockUR), WithUserWriter(mockUW))
			err := svc.RegisterUser(ctx, username, password)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	username := "alice"
	password := "secret"
	userUUID := uuid.New()
	deviceUUID := uuid.New()
	publicKey := "pubkey"

	mockUR := NewMockUserReader(ctrl)
	mockDR := NewMockDeviceReader(ctrl)

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	tests := []struct {
		name           string
		loginPassword  string
		wantErr        error
		wantUserUUID   uuid.UUID
		wantDeviceUUID uuid.UUID
		setupMock      func()
	}{
		{
			name:           "success",
			loginPassword:  password,
			wantErr:        nil,
			wantUserUUID:   userUUID,
			wantDeviceUUID: deviceUUID,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, Username: username, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).
					Return(&models.DeviceDB{DeviceUUID: deviceUUID, PublicKey: publicKey}, nil)
			},
		},
		{
			name:          "invalid user",
			loginPassword: password,
			wantErr:       ErrInvalidCredentials,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, nil)
			},
		},
		{
			name:          "invalid password",
			loginPassword: "wrong",
			wantErr:       ErrInvalidCredentials,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
			},
		},
		{
			name:          "device not registered",
			loginPassword: password,
			wantErr:       ErrDeviceNotRegistered,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).Return(nil, nil)
			},
		},
		{
			name:          "user repo error",
			loginPassword: password,
			wantErr:       errors.New("user db error"),
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, errors.New("user db error"))
			},
		},
		{
			name:          "device repo error",
			loginPassword: password,
			wantErr:       errors.New("device db error"),
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).Return(nil, errors.New("device db error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			svc := NewAuthService(WithUserReader(mockUR), WithDeviceReader(mockDR))
			uuidU, uuidD, err := svc.Login(ctx, username, tt.loginPassword, publicKey)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
				assert.Equal(t, uuid.Nil, uuidU)
				assert.Equal(t, uuid.Nil, uuidD)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantUserUUID, uuidU)
				assert.Equal(t, tt.wantDeviceUUID, uuidD)
			}
		})
	}
}

func TestAuthService_ListUserDevices(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	userUUID := uuid.New()

	mockUR := NewMockUserReader(ctrl)
	mockDR := NewMockDeviceReader(ctrl)

	deviceList := []*models.DeviceDB{
		{DeviceUUID: uuid.New(), PublicKey: "key1"},
		{DeviceUUID: uuid.New(), PublicKey: "key2"},
	}

	tests := []struct {
		name      string
		wantErr   error
		wantList  []*models.DeviceDB
		setupMock func()
	}{
		{
			name:     "success",
			wantErr:  nil,
			wantList: deviceList,
			setupMock: func() {
				mockUR.EXPECT().GetByUUID(ctx, userUUID).
					Return(&models.UserDB{UserUUID: userUUID, Username: "alice"}, nil)
				mockDR.EXPECT().ListDevicesByUserUUID(ctx, userUUID).Return(deviceList, nil)
			},
		},
		{
			name:    "user not found",
			wantErr: ErrInvalidCredentials,
			setupMock: func() {
				mockUR.EXPECT().GetByUUID(ctx, userUUID).Return(nil, nil)
			},
		},
		{
			name:    "repo error",
			wantErr: errors.New("db error"),
			setupMock: func() {
				mockUR.EXPECT().GetByUUID(ctx, userUUID).
					Return(&models.UserDB{UserUUID: userUUID, Username: "alice"}, nil)
				mockDR.EXPECT().ListDevicesByUserUUID(ctx, userUUID).Return(nil, errors.New("db error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			svc := NewAuthService(WithUserReader(mockUR), WithDeviceReader(mockDR))
			list, err := svc.ListUserDevices(ctx, userUUID)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
				assert.Nil(t, list)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantList, list)
			}
		})
	}
}

func TestAuthService_RegisterDevice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	username := "alice"
	password := "secret"
	publicKey := "pubkey"
	userUUID := uuid.New()

	mockUR := NewMockUserReader(ctrl)
	mockDW := NewMockDeviceWriter(ctrl)
	mockDR := NewMockDeviceReader(ctrl)

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	tests := []struct {
		name          string
		inputPassword string
		wantErr       error
		setupMock     func()
	}{
		{
			name:          "success",
			inputPassword: password,
			wantErr:       nil,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).Return(nil, nil)
				mockDW.EXPECT().Save(ctx, gomock.Any(), userUUID, publicKey).Return(nil)
			},
		},
		{
			name:          "user not found",
			inputPassword: password,
			wantErr:       ErrInvalidCredentials,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, nil)
			},
		},
		{
			name:          "wrong password",
			inputPassword: "wrong",
			wantErr:       ErrInvalidCredentials,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
			},
		},
		{
			name:          "device already exists",
			inputPassword: password,
			wantErr:       nil,
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).
					Return(&models.DeviceDB{DeviceUUID: uuid.New(), PublicKey: publicKey}, nil)
			},
		},
		{
			name:          "user repo error",
			inputPassword: password,
			wantErr:       errors.New("user db error"),
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).Return(nil, errors.New("user db error"))
			},
		},
		{
			name:          "device repo error",
			inputPassword: password,
			wantErr:       errors.New("device db error"),
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).Return(nil, errors.New("device db error"))
			},
		},
		{
			name:          "save device error",
			inputPassword: password,
			wantErr:       errors.New("save device error"),
			setupMock: func() {
				mockUR.EXPECT().GetByUsername(ctx, username).
					Return(&models.UserDB{UserUUID: userUUID, PasswordHash: string(hash)}, nil)
				mockDR.EXPECT().GetByPublicKey(ctx, publicKey).Return(nil, nil)
				mockDW.EXPECT().Save(ctx, gomock.Any(), userUUID, publicKey).Return(errors.New("save device error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			svc := NewAuthService(
				WithUserReader(mockUR),
				WithDeviceReader(mockDR),
				WithDeviceWriter(mockDW),
			)

			err := svc.RegisterDevice(ctx, username, tt.inputPassword, publicKey)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_GetDevice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	userUUID := uuid.New()
	deviceUUID := uuid.New()
	device := &models.DeviceDB{
		DeviceUUID: deviceUUID,
		UserUUID:   userUUID,
		PublicKey:  "pubkeyXYZ",
	}

	mockDR := NewMockDeviceReader(ctrl)

	tests := []struct {
		name       string
		setupMock  func()
		wantDevice *models.DeviceDB
		wantErr    error
	}{
		{
			name: "device exists",
			setupMock: func() {
				mockDR.EXPECT().
					GetByUserDeviceUUIDs(ctx, userUUID, deviceUUID).
					Return(device, nil)
			},
			wantDevice: device,
			wantErr:    nil,
		},
		{
			name: "device not found",
			setupMock: func() {
				mockDR.EXPECT().
					GetByUserDeviceUUIDs(ctx, userUUID, deviceUUID).
					Return(nil, nil)
			},
			wantDevice: nil,
			wantErr:    nil,
		},
		{
			name: "repo error",
			setupMock: func() {
				mockDR.EXPECT().
					GetByUserDeviceUUIDs(ctx, userUUID, deviceUUID).
					Return(nil, errors.New("db error"))
			},
			wantDevice: nil,
			wantErr:    errors.New("db error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			svc := NewAuthService(WithDeviceReader(mockDR))
			gotDevice, err := svc.GetUserDevice(ctx, userUUID, deviceUUID)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
				assert.Nil(t, gotDevice)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantDevice, gotDevice)
			}
		})
	}
}
