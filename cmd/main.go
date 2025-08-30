// main.go
// @title       auth API
// @version     1.0
// @description API для аутентификации
// @host        localhost:8080
// @BasePath    /api/v1
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/sbilibin2017/bil-message-auth/internal/handlers"
	"github.com/sbilibin2017/bil-message-auth/internal/jwt"
	"github.com/sbilibin2017/bil-message-auth/internal/repositories"
	"github.com/sbilibin2017/bil-message-auth/internal/services"
	_ "modernc.org/sqlite"
)

// main запускает сервер и выводит информацию о сборке.
func main() {
	printBuildInfo()
	parseFlags()
	err := run(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

// Информация о сборке. Может быть заполнена через ldflags при сборке.
var (
	buildVersion = "N/A" // Версия сборки
	buildDate    = "N/A" // Дата сборки
	buildCommit  = "N/A" // Хеш коммита
)

// Параметры сервера и базы данных, которые могут быть установлены через флаги командной строки.
var (
	addr           string        // Адрес HTTP сервера
	version        string        // Префикс версии API
	databaseDSN    string        // DSN подключения к базе данных
	databaseDriver string        // Драйвер базы данных (pgx, sqlite и т.д.)
	jwtSecretKey   string        // Секретный ключ для JWT
	jwtExp         time.Duration // Срок действия JWT
)

// printBuildInfo выводит информацию о сборке в лог.
func printBuildInfo() {
	log.Printf("Build Version: %s", buildVersion)
	log.Printf("Build Commit:  %s", buildCommit)
	log.Printf("Build Date:    %s", buildDate)
}

// parseFlags парсит флаги командной строки и заполняет глобальные переменные.
func parseFlags() {
	flag.StringVar(&addr, "a", ":8080", "Адрес HTTP сервера")
	flag.StringVar(&version, "v", "/api/v1", "Префикс версии API")
	flag.StringVar(&databaseDriver, "driver", "pgx", "Драйвер базы данных (pgx для PostgreSQL, sqlite и т.д.)")
	flag.StringVar(&databaseDSN, "d", "postgres://user:password@localhost:5432/db?sslmode=disable", "DSN подключения к базе данных")
	flag.StringVar(&jwtSecretKey, "jwt-secret", "supersecretkey", "Секретный ключ для JWT")
	flag.DurationVar(&jwtExp, "jwt-exp", 24*time.Hour, "Срок действия JWT")

	flag.Parse()
}

// run запускает HTTP-сервер и управляет его жизненным циклом.
// Возвращает ошибку, если не удалось подключиться к БД или сервер завершился с ошибкой.
func run(ctx context.Context) error {
	// Подключение к базе данных
	db, err := sqlx.Connect(databaseDriver, databaseDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	// Репозитории
	userWriter := repositories.NewUserWriteRepository(db)
	userReader := repositories.NewUserReadRepository(db)
	deviceWriter := repositories.NewDeviceWriteRepository(db)
	deviceReader := repositories.NewDeviceReadRepository(db)

	// JWT-сервис
	jwtSrv, err := jwt.New(jwt.WithSecretKey(jwtSecretKey), jwt.WithExpiration(jwtExp))
	if err != nil {
		return err
	}

	// Сервисы аутентификации
	authService := services.NewAuthService(
		services.WithUserWriter(userWriter),
		services.WithUserReader(userReader),
		services.WithDeviceWriter(deviceWriter),
		services.WithDeviceReader(deviceReader),
	)

	// HTTP-обработчики
	registerUserHandler := handlers.NewRegisterUserHandler(authService)
	registerDeviceHandler := handlers.NewRegisterDeviceHandler(authService)
	loginHandler := handlers.NewLoginHandler(authService, jwtSrv)
	userGetHandler := handlers.NewUserDeviceListHandler(authService, jwtSrv)
	userDeviceListHandler := handlers.NewUserDeviceListHandler(authService, jwtSrv)

	// Маршрутизация
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route(version, func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register/user", registerUserHandler)
			r.Post("/register/device", registerDeviceHandler)
			r.Post("/login", loginHandler)
			r.Get("/user", userGetHandler)
			r.Get("/user/devices", userDeviceListHandler)
		})
	})

	// HTTP-сервер
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(ctxShutdown)
	case err := <-errChan:
		return err
	}
}
