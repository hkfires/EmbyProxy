package config

import "testing"

func TestLoadServerName(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, tt := range []struct {
		name, value, want string
	}{
		{name: "explicit name", value: " hk1 ", want: "hk1"},
		{name: "unset", value: "", want: ""},
		{name: "blank", value: "  ", want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SERVER_NAME", tt.value)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ServerName != tt.want {
				t.Fatalf("ServerName = %q, want %q", cfg.ServerName, tt.want)
			}
		})
	}
}

func TestEnvBoolParsesAdmin2FADisabledValues(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  bool
	}{
		{value: "true", want: true},
		{value: "1", want: true},
		{value: "on", want: true},
		{value: "false", want: false},
		{value: "0", want: false},
		{value: "", want: false},
	} {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("ADMIN_2FA_DISABLED", tt.value)
			if got := envBool("ADMIN_2FA_DISABLED", false); got != tt.want {
				t.Fatalf("envBool() = %v, want %v", got, tt.want)
			}
		})
	}
}
