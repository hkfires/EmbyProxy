package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Defaults struct {
	CacheTTL           int64
	ListCacheTTL       int64
	MaxRetryBodyBytes  int64
	ImageCacheTTL      int
	PingCacheTTL       int
	StaticCacheTTL     int
	ProgressThrottleMS int64
}

type Config struct {
	CWD              string
	DBPath           string
	ServerName       string
	Port             int
	AdminToken       string
	Admin2FADisabled bool
	Defaults         Defaults
}

type ProxyEnv struct {
	CORSAllowOrigin    string
	CapyStripEmby      string
	EmosCompat         bool
	EmosMatchHosts     string
	EmosProxyID        string
	EmosProxyName      string
	ExternalAllowHosts string
	ExternalAllowAny   bool
}

func Load() (Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Config{}, err
	}
	_ = loadDotEnv(filepath.Join(cwd, ".env"))
	cfg := Config{
		CWD:              cwd,
		ServerName:       strings.TrimSpace(os.Getenv("SERVER_NAME")),
		DBPath:           envString("DB_PATH", filepath.Join(cwd, "data", "proxy.db")),
		Port:             envInt("PORT", 8787),
		AdminToken:       os.Getenv("ADMIN_TOKEN"),
		Admin2FADisabled: envBool("ADMIN_2FA_DISABLED", false),
		Defaults: Defaults{
			CacheTTL:           10000,
			ListCacheTTL:       180000,
			MaxRetryBodyBytes:  32 * 1024 * 1024,
			ImageCacheTTL:      30 * 24 * 60 * 60,
			PingCacheTTL:       60,
			StaticCacheTTL:     604800,
			ProgressThrottleMS: 1200,
		},
	}
	return cfg, nil
}

func (c Config) Addr() string {
	return "0.0.0.0:" + strconv.Itoa(c.Port)
}

func (c Config) ProxyEnv() ProxyEnv {
	return ProxyEnv{}
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		value = stripInlineComment(value)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			quote := value[0]
			if (quote == '\'' || quote == '"') && value[len(value)-1] == quote {
				value = value[1 : len(value)-1]
			}
		}
		if _, ok := os.LookupEnv(key); !ok {
			_ = os.Setenv(key, value)
		}
	}
	return s.Err()
}

func stripInlineComment(value string) string {
	inSingle := false
	inDouble := false
	for i, r := range value {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && i > 0 && value[i-1] == ' ' {
				return strings.TrimSpace(value[:i])
			}
		}
	}
	return value
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" || s == "0" || s == "false" || s == "off" || s == "no" {
		return false
	}
	return s == "1" || s == "true" || s == "yes" || s == "on"
}
