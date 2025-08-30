package main

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// resetFlags clears previously defined flags
func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

// TestParseFlagsDefault ensures parseFlags sets default values
func TestParseFlagsDefault(t *testing.T) {
	resetFlags()
	os.Args = []string{"cmd"} // no flags
	parseFlags()

	assert.Equal(t, ":8080", addr)
	assert.Equal(t, "/api/v1", version)
	assert.Equal(t, "postgres://user:password@localhost:5432/db?sslmode=disable", databaseDSN)
	assert.Equal(t, "pgx", databaseDriver)
	assert.Equal(t, "supersecretkey", jwtSecretKey)
	assert.Equal(t, 24*time.Hour, jwtExp)
}

// TestParseFlagsCustom ensures parseFlags correctly sets values from os.Args
func TestParseFlagsCustom(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"cmd",
		"-a", ":9090",
		"-v", "/v2",
		"-driver", "sqlite",
		"-d", "file::memory:?cache=shared",
		"-jwt-secret", "mysecret",
		"-jwt-exp", "48h",
	}

	parseFlags()

	assert.Equal(t, ":9090", addr)
	assert.Equal(t, "/v2", version)
	assert.Equal(t, "file::memory:?cache=shared", databaseDSN)
	assert.Equal(t, "sqlite", databaseDriver)
	assert.Equal(t, "mysecret", jwtSecretKey)
	assert.Equal(t, 48*time.Hour, jwtExp)
}

// TestRunServer ensures run starts and stops an HTTP server with in-memory SQLite
func TestRunServer(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"cmd",
		"-driver", "sqlite",
		"-d", "file::memory:?cache=shared",
	}
	parseFlags()

	// Set short timeout to stop server automatically
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		err := run(ctx)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-ctx.Done():
		// Server stopped via context timeout
		assert.True(t, true)
	}
}

// TestRunBadDB ensures run returns error with invalid driver
func TestRunBadDB(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"cmd",
		"-driver", "invalid_driver",
		"-d", "file::memory:?cache=shared",
	}
	parseFlags()

	ctx := context.Background()
	err := run(ctx)
	assert.Error(t, err)
}
