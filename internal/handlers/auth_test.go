package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sbilibin2017/bil-message-auth/internal/models"
	"github.com/sbilibin2017/bil-message-auth/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestNewRegisterUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSvc := NewMockUserRegisterer(ctrl)

	tests := []struct {
		name           string
		payload        interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "success",
			payload: RegisterUserRequest{
				Username: "john",
				Password: "pass",
			},
			mockSetup: func() {
				mockSvc.EXPECT().RegisterUser(gomock.Any(), "john", "pass").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid json",
			payload:        "invalid",
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			payload: RegisterUserRequest{
				Username: "john",
				Password: "pass",
			},
			mockSetup: func() {
				mockSvc.EXPECT().RegisterUser(gomock.Any(), "john", "pass").Return(errors.New("internal error"))
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			handler := NewRegisterUserHandler(mockSvc)
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(tt.payload)

			req := httptest.NewRequest(http.MethodPost, "/auth/register/user", &body)
			w := httptest.NewRecorder()
			handler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Result().StatusCode)
		})
	}
}

func TestNewRegisterDeviceHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSvc := NewMockDeviceRegisterer(ctrl)

	tests := []struct {
		name           string
		payload        interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "success",
			payload: RegisterDeviceRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().RegisterDevice(gomock.Any(), "john", "pass", "pubkey").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid json",
			payload:        "invalid",
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid credentials",
			payload: RegisterDeviceRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().RegisterDevice(gomock.Any(), "john", "pass", "pubkey").Return(services.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "internal server error",
			payload: RegisterDeviceRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().RegisterDevice(gomock.Any(), "john", "pass", "pubkey").Return(errors.New("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			handler := NewRegisterDeviceHandler(mockSvc)
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(tt.payload)

			req := httptest.NewRequest(http.MethodPost, "/auth/register/device", &body)
			w := httptest.NewRecorder()
			handler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Result().StatusCode)
		})
	}
}

func TestNewLoginHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSvc := NewMockUserLoginer(ctrl)
	mockTok := NewMockTokener(ctrl)

	userID := uuid.New()
	deviceID := uuid.New()
	token := "token123"

	tests := []struct {
		name           string
		payload        interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "success",
			payload: LoginRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().Login(gomock.Any(), "john", "pass", "pubkey").Return(userID, deviceID, nil)
				mockTok.EXPECT().Generate(userID, deviceID).Return(token, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid json",
			payload:        "invalid",
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid credentials",
			payload: LoginRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().Login(gomock.Any(), "john", "pass", "pubkey").Return(uuid.Nil, uuid.Nil, services.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "device not registered",
			payload: LoginRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().Login(gomock.Any(), "john", "pass", "pubkey").Return(uuid.Nil, uuid.Nil, services.ErrDeviceNotRegistered)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "internal server error",
			payload: LoginRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().Login(gomock.Any(), "john", "pass", "pubkey").Return(uuid.Nil, uuid.Nil, errors.New("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "token generate error",
			payload: LoginRequest{
				Username:  "john",
				Password:  "pass",
				PublicKey: "pubkey",
			},
			mockSetup: func() {
				mockSvc.EXPECT().Login(gomock.Any(), "john", "pass", "pubkey").Return(userID, deviceID, nil)
				mockTok.EXPECT().Generate(userID, deviceID).Return("", errors.New("token error"))
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			handler := NewLoginHandler(mockSvc, mockTok)
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(tt.payload)

			req := httptest.NewRequest(http.MethodPost, "/auth/login", &body)
			w := httptest.NewRecorder()
			handler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Result().StatusCode)
		})
	}
}

func TestNewUserDeviceListHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSvc := NewMockDeviceLister(ctrl)
	mockTok := NewMockTokener(ctrl)

	userID := uuid.New()
	devices := []*models.DeviceDB{
		{
			DeviceUUID: uuid.New(),
			UserUUID:   userID,
			PublicKey:  "pubkey",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}

	tests := []struct {
		name           string
		tokenHeader    string
		mockSetup      func()
		expectedStatus int
	}{
		{
			name:        "success",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(userID, uuid.New(), nil)
				mockSvc.EXPECT().ListUserDevices(gomock.Any(), userID).Return(devices, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "invalid token header",
			tokenHeader: "",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("", errors.New("missing header"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "invalid token parse",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(uuid.Nil, uuid.Nil, errors.New("parse error"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "ErrInvalidCredentials returns 401",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(userID, uuid.New(), nil)
				mockSvc.EXPECT().ListUserDevices(gomock.Any(), userID).Return(nil, services.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:        "other service error returns 500",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(userID, uuid.New(), nil)
				mockSvc.EXPECT().ListUserDevices(gomock.Any(), userID).Return(nil, errors.New("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			handler := NewUserDeviceListHandler(mockSvc, mockTok)
			req := httptest.NewRequest(http.MethodGet, "/auth/user/devices", nil)
			if tt.tokenHeader != "" {
				req.Header.Set("Authorization", tt.tokenHeader)
			}
			w := httptest.NewRecorder()
			handler(w, req)
			assert.Equal(t, tt.expectedStatus, w.Result().StatusCode)
		})
	}
}

func TestNewUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSvc := NewMockUserDeviceGetter(ctrl)
	mockTok := NewMockTokener(ctrl)

	userID := uuid.New()
	deviceID := uuid.New()
	now := time.Now()

	device := &models.DeviceDB{
		DeviceUUID: deviceID,
		UserUUID:   userID,
		PublicKey:  "pubkey",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	tests := []struct {
		name           string
		tokenHeader    string
		mockSetup      func()
		expectedStatus int
		expectedBody   *UserDeviceResponse
	}{
		{
			name:        "success",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(userID, deviceID, nil)
				mockSvc.EXPECT().GetUserDevice(gomock.Any(), userID, deviceID).Return(device, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: &UserDeviceResponse{
				DeviceUUID: device.DeviceUUID,
				UserUUID:   device.UserUUID,
				PublicKey:  device.PublicKey,
				CreatedAt:  device.CreatedAt.Format(time.RFC3339),
				UpdatedAt:  device.UpdatedAt.Format(time.RFC3339),
			},
		},
		{
			name:        "missing token header",
			tokenHeader: "",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("", errors.New("missing header"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "invalid token parse",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(uuid.Nil, uuid.Nil, errors.New("parse error"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "user not found",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(userID, deviceID, nil)
				mockSvc.EXPECT().GetUserDevice(gomock.Any(), userID, deviceID).Return(nil, nil)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "service error",
			tokenHeader: "Bearer token123",
			mockSetup: func() {
				mockTok.EXPECT().GetFromHeader(gomock.Any()).Return("token123", nil)
				mockTok.EXPECT().Parse(gomock.Any(), "token123").Return(userID, deviceID, nil)
				mockSvc.EXPECT().GetUserDevice(gomock.Any(), userID, deviceID).Return(nil, errors.New("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			handler := NewUserHandler(mockSvc, mockTok)
			req := httptest.NewRequest(http.MethodGet, "/auth/user", nil)
			if tt.tokenHeader != "" {
				req.Header.Set("Authorization", tt.tokenHeader)
			}
			w := httptest.NewRecorder()
			handler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Result().StatusCode)

			if tt.expectedBody != nil {
				var resp UserDeviceResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.Equal(t, *tt.expectedBody, resp)
			}
		})
	}
}
