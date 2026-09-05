package identity

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testYambyDeviceID          = "00000000-0000-4000-8000-000000000001"
	testHillsWindowsID         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHillsAndroidID         = "bbbbbbbbbbbbbbbb"
	testSourceMediaBrowserAuth = `MediaBrowser Token="source-token", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
	testSourceEmbyTokenAuth    = `Emby Token="source-token", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
	testSourceEmbyAuth         = `Emby UserId="source-user", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
)

func TestRewriteMediaBrowserAuthorization(t *testing.T) {
	yamby := Snapshot{
		Profile:       DefaultProfile,
		ClientName:    "Yamby",
		ClientVersion: "2.0.4.6",
		DeviceName:    "Android",
		DeviceID:      testYambyDeviceID,
	}
	hillsWindows := Snapshot{
		Profile:       "hills_windows",
		ClientName:    "Hills Windows",
		ClientVersion: "1.3.1",
		DeviceName:    "DESKTOP-TEST",
		DeviceID:      testHillsWindowsID,
	}
	hillsAndroid := Snapshot{
		Profile:       "hills_android",
		ClientName:    "Hills",
		ClientVersion: "1.7.2",
		DeviceName:    "diting",
		DeviceID:      testHillsAndroidID,
	}
	tests := []struct {
		name string
		raw  string
		snap Snapshot
		want string
	}{
		{
			name: "yamby rewrites emby auth without user id field",
			raw:  `Emby UserId=user-from-auth,Client="Source Client",Device="Source Device",DeviceId="source-device-id",Version="0.0.0-test"`,
			snap: yamby,
			want: `Emby Client=Yamby,Device=Android,DeviceId=` + testYambyDeviceID + `,Version=2.0.4.6`,
		},
		{
			name: "yamby rewrites media browser auth without token field",
			raw:  testSourceMediaBrowserAuth,
			snap: yamby,
			want: `Emby Client=Yamby,Device=Android,DeviceId=` + testYambyDeviceID + `,Version=2.0.4.6`,
		},
		{
			name: "keeps non emby bearer authorization",
			raw:  `Bearer Token="source-token"`,
			snap: yamby,
			want: `Bearer Token="source-token"`,
		},
		{
			name: "keeps emby prefix lookalike",
			raw:  `EmbyX Client=Original, Device=SOURCE-PC`,
			snap: yamby,
			want: `EmbyX Client=Original, Device=SOURCE-PC`,
		},
		{
			name: "hills windows keeps quoted fields",
			raw:  `Emby Client=Original, Device=SOURCE-PC, DeviceId=original, Version=1.0`,
			snap: hillsWindows,
			want: `Emby Client="Hills Windows", Device="DESKTOP-TEST", DeviceId="` + testHillsWindowsID + `", Version="1.3.1"`,
		},
		{
			name: "hills android rewrites media browser auth without token field",
			raw:  testSourceMediaBrowserAuth,
			snap: hillsAndroid,
			want: `Emby Client="Hills", Device="diting", DeviceId="` + testHillsAndroidID + `", Version="1.7.2"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RewriteMediaBrowserAuthorization(tt.raw, tt.snap); got != tt.want {
				t.Fatalf("RewriteMediaBrowserAuthorization() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyToHeadersMovesAuthorizationToken(t *testing.T) {
	tests := []struct {
		name                 string
		headers              http.Header
		wantToken            string
		wantRewrittenAuthKey string
		wantAuthorization    string
		wantAbsent           []string
	}{
		{
			name:                 "moves MediaBrowser token when token header is missing",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Emby-Authorization": {testSourceMediaBrowserAuth},
			},
			wantToken: "source-token",
		},
		{
			name:                 "moves Emby token when token header is missing",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Emby-Authorization": {testSourceEmbyTokenAuth},
			},
			wantToken: "source-token",
		},
		{
			name:                 "moves X-Authorization token when token header is missing",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Authorization": {testSourceEmbyTokenAuth},
			},
			wantToken:  "source-token",
			wantAbsent: []string{"X-Authorization"},
		},
		{
			name:                 "normalizes Authorization token when token header is missing",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"Authorization": {testSourceEmbyTokenAuth},
			},
			wantToken:  "source-token",
			wantAbsent: []string{"Authorization"},
		},
		{
			name:                 "preserves existing token header",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Emby-Authorization": {testSourceMediaBrowserAuth},
				"X-Emby-Token":         {"existing-token"},
			},
			wantToken: "existing-token",
		},
		{
			name: "ignores token field without media browser scheme",
			headers: http.Header{
				"Authorization": {`Token="source-token"`},
			},
			wantToken:         "",
			wantAuthorization: `Token="source-token"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(nil)
			snap := manager.Snapshot(DefaultProfile)
			wantDeviceID := DeriveDeviceID("", DefaultProfile, "source-device-id", GetProfile(DefaultProfile))
			wantAuth := "Emby Client=" + snap.ClientName + ",Device=" + snap.DeviceName + ",DeviceId=" + wantDeviceID + ",Version=" + snap.ClientVersion

			manager.ApplyToHeaders(tt.headers, DefaultProfile)

			if got := tt.headers.Get("X-Emby-Token"); got != tt.wantToken {
				t.Fatalf("X-Emby-Token = %q, want %q", got, tt.wantToken)
			}
			if tt.wantRewrittenAuthKey != "" {
				value := tt.headers.Get(tt.wantRewrittenAuthKey)
				if value != wantAuth {
					t.Fatalf("%s = %q, want %q", tt.wantRewrittenAuthKey, value, wantAuth)
				}
				if strings.Contains(strings.ToLower(value), "token=") {
					t.Fatalf("%s still contains token: %q", tt.wantRewrittenAuthKey, value)
				}
			}
			if got := tt.headers.Get("Authorization"); tt.wantAuthorization != "" && got != tt.wantAuthorization {
				t.Fatalf("Authorization = %q, want %q", got, tt.wantAuthorization)
			}
			for _, key := range tt.wantAbsent {
				if got := tt.headers.Get(key); got != "" {
					t.Fatalf("%s = %q, want dropped", key, got)
				}
			}
		})
	}
}

func TestApplyToHeadersRewritesEmbyAuthorization(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	headers.Set("Authorization", testSourceEmbyAuth)
	headers.Set("X-Emby-Authorization", testSourceEmbyAuth)
	headers.Set("X-MediaBrowser-Authorization", testSourceEmbyAuth)
	headers.Set("X-Authorization", testSourceEmbyAuth)
	headers.Set("X-Application", "Original/1.0")
	headers.Set("X-Emby-Token", "kept-token")
	headers.Set("X-MediaBrowser-Token", "media-token")
	headers.Set("X-Emby-Client", "Original")
	headers.Set("X-Emby-Client-Version", "1.0")
	headers.Set("X-Emby-Device-Id", "original-device")
	headers.Set("X-Emby-Device-Name", "Original Device")
	headers.Set("X-MediaBrowser-Client", "Original")
	headers.Set("X-MediaBrowser-Client-Version", "1.0")
	headers.Set("X-MediaBrowser-Device-Id", "original-device")
	headers.Set("X-MediaBrowser-Device-Name", "Original Device")

	manager.ApplyToHeaders(headers, "yamby")

	wantDeviceID := DeriveDeviceID("", "yamby", "original-device", GetProfile("yamby"))
	if got := headers.Get("X-Emby-Client"); got != "Yamby" {
		t.Fatalf("X-Emby-Client = %q, want Yamby", got)
	}
	if got := headers.Get("X-Emby-Client-Version"); got != "2.0.4.6" {
		t.Fatalf("X-Emby-Client-Version = %q, want 2.0.4.6", got)
	}
	if got := headers.Get("X-Emby-Device-Name"); got != "Android" {
		t.Fatalf("X-Emby-Device-Name = %q, want Android", got)
	}
	if got := headers.Get("X-Emby-Device-Id"); got != wantDeviceID {
		t.Fatalf("X-Emby-Device-Id = %q, want derived %q", got, wantDeviceID)
	}
	value := headers.Get("X-Emby-Authorization")
	if !strings.Contains(value, `Client=Yamby`) || !strings.Contains(value, `Device=Android`) || !strings.Contains(value, `DeviceId=`+wantDeviceID) {
		t.Fatalf("X-Emby-Authorization was not rewritten to yamby identity: %s", value)
	}
	for _, key := range []string{
		"Authorization", "X-Authorization", "X-Application", "X-MediaBrowser-Authorization", "X-MediaBrowser-Token",
		"X-MediaBrowser-Client", "X-MediaBrowser-Client-Version", "X-MediaBrowser-Device-Id", "X-MediaBrowser-Device-Name",
	} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want dropped for yamby impersonation", key, got)
		}
	}
	if got := headers.Get("X-Emby-Token"); got != "kept-token" {
		t.Fatalf("X-Emby-Token = %q, want retained", got)
	}
}

func TestApplyToHeadersPromotesMediaBrowserToken(t *testing.T) {
	manager := NewManager(nil)
	tests := []struct {
		name    string
		profile string
	}{
		{name: "yamby", profile: "yamby"},
		{name: "hills", profile: "hills_android"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("X-MediaBrowser-Token", "media-token")
			headers.Set("X-MediaBrowser-Client", "Original")

			manager.ApplyToHeaders(headers, tt.profile)

			if got := headers.Get("X-Emby-Token"); got != "media-token" {
				t.Fatalf("X-Emby-Token = %q, want media-token", got)
			}
			if got := headers.Get("X-MediaBrowser-Token"); got != "" {
				t.Fatalf("X-MediaBrowser-Token = %q, want dropped after promotion", got)
			}
		})
	}
}

func TestApplyToHeadersNormalizesUnderscoreHeaderAliases(t *testing.T) {
	manager := NewManager(nil)
	yambySnap := manager.Snapshot("yamby")
	yambySnap.DeviceID = DeriveDeviceID("", "yamby", "source-device-id", Profiles["yamby"])
	hillsSnap := manager.Snapshot("hills_windows")
	hillsSnap.DeviceID = DeriveDeviceID("", "hills_windows", "source-device-id", Profiles["hills_windows"])

	tests := []struct {
		name    string
		profile string
		want    string
	}{
		{
			name:    "yamby",
			profile: "yamby",
			want:    buildYambyAuthorization(testSourceEmbyTokenAuth, yambySnap),
		},
		{
			name:    "hills",
			profile: "hills_windows",
			want:    buildHillsAuthorization(hillsSnap),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("X_MediaBrowser_Token", "media-token")
			headers.Set("X_Emby_Authorization", testSourceEmbyTokenAuth)
			headers.Set("X_Emby_Client", "Original")

			manager.ApplyToHeaders(headers, tt.profile)

			if got := headers.Get("X-Emby-Authorization"); got != tt.want {
				t.Fatalf("X-Emby-Authorization = %q, want %q", got, tt.want)
			}
			if got := headers.Get("X-Emby-Token"); got != "media-token" {
				t.Fatalf("X-Emby-Token = %q, want media-token", got)
			}
			for _, key := range []string{"X_MediaBrowser_Token", "X_Emby_Authorization", "X_Emby_Client"} {
				if got := headers.Get(key); got != "" {
					t.Fatalf("%s = %q, want dropped after normalization", key, got)
				}
			}
		})
	}
}

func TestApplyToHeadersAddsMissingProfileHeaders(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}

	manager.ApplyToHeaders(headers, "yamby")

	snap := manager.Snapshot("yamby")
	if got := headers.Get("X-Emby-Client"); got != "Yamby" {
		t.Fatalf("X-Emby-Client = %q, want Yamby", got)
	}
	if got := headers.Get("X-Emby-Client-Version"); got != "2.0.4.6" {
		t.Fatalf("X-Emby-Client-Version = %q, want 2.0.4.6", got)
	}
	if got := headers.Get("X-Emby-Device-Name"); got != "Android" {
		t.Fatalf("X-Emby-Device-Name = %q, want Android", got)
	}
	if got := headers.Get("X-Emby-Device-Id"); got != snap.DeviceID {
		t.Fatalf("X-Emby-Device-Id = %q, want fallback device ID %q", got, snap.DeviceID)
	}
	if got := headers.Get("X-Emby-Authorization"); !strings.Contains(got, "Client=Yamby") {
		t.Fatalf("X-Emby-Authorization = %q, want Yamby authorization", got)
	}
	for _, key := range []string{"Authorization", "X-Application", "X-MediaBrowser-Authorization"} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want empty", key, got)
		}
	}
}

func TestApplyToHeadersNormalizesHillsIdentityHeaders(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	headers.Set("Authorization", testSourceEmbyTokenAuth)
	headers.Set("X-Emby-Client", "Original")
	headers.Set("X-Emby-Client-Version", "0.0.0-test")
	headers.Set("X-Emby-Device-Id", "original-device")
	headers.Set("X-Emby-Device-Name", "Original Device")
	headers.Set("X-Emby-Language", "en-us")
	headers.Set("X-MediaBrowser-Client", "Original")
	headers.Set("X-MediaBrowser-Device-Id", "original-media-device")
	headers.Set("X-Application", "Original/0.0.0-test")

	manager.ApplyToHeaders(headers, "hills_windows")

	wantDeviceID := DeriveDeviceID("", "hills_windows", "original-device", Profiles["hills_windows"])
	snap := manager.Snapshot("hills_windows")
	snap.DeviceID = wantDeviceID

	if got := headers.Get("X-Emby-Client"); got != "Hills Windows" {
		t.Fatalf("X-Emby-Client = %q, want Hills Windows", got)
	}
	if got := headers.Get("X-Emby-Client-Version"); got != "1.3.1" {
		t.Fatalf("X-Emby-Client-Version = %q, want 1.3.1", got)
	}
	if got := headers.Get("X-Emby-Device-Name"); got != snap.DeviceName {
		t.Fatalf("X-Emby-Device-Name = %q, want %q", got, snap.DeviceName)
	}
	if got := headers.Get("X-Emby-Device-Id"); got != wantDeviceID {
		t.Fatalf("X-Emby-Device-Id = %q, want %q", got, wantDeviceID)
	}
	if got := headers.Get("X-Emby-Authorization"); got != buildHillsAuthorization(snap) {
		t.Fatalf("X-Emby-Authorization = %q, want Hills auth", got)
	}
	if got := headers.Get("X-Emby-Token"); got != "source-token" {
		t.Fatalf("X-Emby-Token = %q, want source-token", got)
	}
	for _, key := range []string{
		"Authorization", "X-Authorization", "X-Application", "X-Emby-Language",
		"X-MediaBrowser-Authorization", "X-MediaBrowser-Client", "X-MediaBrowser-Client-Version", "X-MediaBrowser-Device-Name", "X-MediaBrowser-Device-Id", "X-MediaBrowser-Token",
	} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want dropped for Hills impersonation", key, got)
		}
	}
}

func TestApplyToURLMigratesYambyAllowedQueryAuth(t *testing.T) {
	manager := NewManager(nil)
	tests := []struct {
		queryKey string
		header   string
	}{
		{queryKey: "authorization", header: "Authorization"},
		{queryKey: "x-authorization", header: "X-Authorization"},
		{queryKey: "x-emby-authorization", header: "X-Emby-Authorization"},
		{queryKey: "x-emby-token", header: "X-Emby-Token"},
		{queryKey: "x-mediabrowser-authorization", header: "X-MediaBrowser-Authorization"},
		{queryKey: "x-mediabrowser-token", header: "X-MediaBrowser-Token"},
		{queryKey: "X_eMbY_ToKeN", header: "X-Emby-Token"},
	}

	for _, tt := range tests {
		t.Run(tt.queryKey, func(t *testing.T) {
			headers := http.Header{}
			u := parseIdentityURL(t, tt.queryKey+"=query-value&tag=v1")

			manager.ApplyToURL(u, headers, "yamby")

			query := u.Query()
			if headers.Get(tt.header) != "query-value" {
				t.Fatalf("%s header behavior did not match expectation", tt.header)
			}
			if query.Has(tt.queryKey) {
				t.Fatalf("%s query was not removed", tt.queryKey)
			}
			if got := query.Get("tag"); got != "v1" {
				t.Fatal("ordinary query parameter was not preserved")
			}
		})
	}
}

func TestApplyToURLPromotesYambyQueryToken(t *testing.T) {
	manager := NewManager(nil)
	tests := []struct {
		name     string
		headers  http.Header
		rawQuery string
		want     string
	}{
		{
			name:     "uses first query value",
			headers:  http.Header{},
			rawQuery: "x-emby-token=first-value&x-emby-token=second-value",
			want:     "first-value",
		},
		{
			name:     "keeps existing header",
			headers:  http.Header{"X-Emby-Token": {"header-value"}},
			rawQuery: "x-emby-token=query-value",
			want:     "header-value",
		},
		{
			name:     "fills empty existing header",
			headers:  http.Header{"X-Emby-Token": {""}},
			rawQuery: "x-emby-token=query-value",
			want:     "query-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := parseIdentityURL(t, tt.rawQuery)

			manager.ApplyToURL(u, tt.headers, "yamby")

			if got := tt.headers.Get("X-Emby-Token"); got != tt.want {
				t.Fatalf("X-Emby-Token = %q, want %q", got, tt.want)
			}
			if u.Query().Has("x-emby-token") {
				t.Fatal("x-emby-token query was not removed")
			}
		})
	}
}

func TestApplyToURLMovesQueryAuthorizationToken(t *testing.T) {
	manager := NewManager(nil)
	encodedAuth := url.QueryEscape(testSourceEmbyTokenAuth)
	tests := []struct {
		name              string
		profile           string
		rawQuery          string
		headers           http.Header
		wantToken         string
		wantRemovedQuery  []string
		wantNoQueryToken  bool
		wantOrdinaryQuery bool
	}{
		{name: "yamby", profile: "yamby", rawQuery: "X-Emby-Authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantRemovedQuery: []string{"X-Emby-Authorization"}, wantOrdinaryQuery: true},
		{name: "yamby x authorization alias", profile: "yamby", rawQuery: "x-authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantRemovedQuery: []string{"x-authorization"}, wantOrdinaryQuery: true},
		{name: "hills android", profile: "hills_android", rawQuery: "X-Emby-Authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantOrdinaryQuery: true},
		{name: "hills windows", profile: "hills_windows", rawQuery: "X-Emby-Authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantOrdinaryQuery: true},
		{name: "existing header token wins", profile: "hills_windows", rawQuery: "X-Emby-Authorization=" + encodedAuth, headers: http.Header{"X-Emby-Token": {"existing-token"}}, wantToken: "existing-token"},
		{name: "yamby query token wins", profile: "yamby", rawQuery: "x-emby-token=query-token&X-Emby-Authorization=" + encodedAuth, headers: http.Header{}, wantToken: "query-token", wantRemovedQuery: []string{"x-emby-token", "X-Emby-Authorization"}},
		{name: "bare token ignored", profile: "hills_windows", rawQuery: "X-Emby-Authorization=" + url.QueryEscape(`Token="source-token"`), headers: http.Header{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := parseIdentityURL(t, tt.rawQuery)

			manager.ApplyToURL(u, tt.headers, tt.profile)

			if got := tt.headers.Get("X-Emby-Token"); got != tt.wantToken {
				t.Fatalf("X-Emby-Token = %q, want %q", got, tt.wantToken)
			}
			query := u.Query()
			for _, key := range tt.wantRemovedQuery {
				if query.Has(key) {
					t.Fatalf("%s query was not removed: %s", key, u.RawQuery)
				}
			}
			if tt.wantNoQueryToken && strings.Contains(strings.ToLower(query.Get("X-Emby-Authorization")), "token=") {
				t.Fatalf("query X-Emby-Authorization still contains token: %q", query.Get("X-Emby-Authorization"))
			}
			if strings.HasPrefix(tt.profile, "hills_") && query.Get("X-Emby-Token") != tt.wantToken {
				t.Fatalf("query X-Emby-Token = %q, want %q", query.Get("X-Emby-Token"), tt.wantToken)
			}
			if tt.wantOrdinaryQuery && query.Get("tag") != "v1" {
				t.Fatalf("tag = %q, want v1", query.Get("tag"))
			}
		})
	}
}

func TestApplyToURLStripsOtherYambyIdentityQueryAndKeepsOrdinaryQuery(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	u := parseIdentityURL(t, "x-emby-client=Client&x-emby-device-id=device&x-mediabrowser-client=MediaBrowser&x-mediabrowser-device-id=media-device&X_MediaBrowser_Client_Version=1.2.3&DeviceId=source-device&DeviceName=source-name&quality=90&tag=v1&fields=Overview&maxwidth=600&api_key=api-value&playsessionid=session-value")

	manager.ApplyToURL(u, headers, "yamby")

	query := u.Query()
	for _, key := range []string{"x-emby-client", "x-emby-device-id", "x-mediabrowser-client", "x-mediabrowser-device-id", "X_MediaBrowser_Client_Version", "DeviceId", "DeviceName"} {
		if query.Has(key) {
			t.Fatalf("%s query was not removed", key)
		}
	}
	for _, key := range []string{"X-Emby-Client", "X-Emby-Device-Id", "X-MediaBrowser-Client", "X-MediaBrowser-Device-Id", "X-MediaBrowser-Client-Version"} {
		if headers.Get(key) != "" {
			t.Fatalf("%s header should not be set", key)
		}
	}
	for key, want := range map[string]string{
		"quality":       "90",
		"tag":           "v1",
		"fields":        "Overview",
		"maxwidth":      "600",
		"api_key":       "api-value",
		"playsessionid": "session-value",
	} {
		if query.Get(key) != want {
			t.Fatalf("%s query behavior did not match expectation", key)
		}
	}
}

func TestApplyToURLStripsControlBytesFromPromotedHeaderValues(t *testing.T) {
	manager := NewManager(nil)

	t.Run("yamby query auth header value", func(t *testing.T) {
		headers := http.Header{}
		// Authorization value decoded contains CR/LF and a NUL byte.
		u := parseIdentityURL(t, "Authorization="+url.QueryEscape("Emby\r\nX-Injected: 1\r\nClient=Yamby\x00"))

		manager.ApplyToURL(u, headers, "yamby")

		got := headers.Get("Authorization")
		if strings.ContainsAny(got, "\r\n\x00") {
			t.Fatalf("promoted Authorization still carries control bytes: %q", got)
		}
		if !strings.Contains(got, "Client=Yamby") {
			t.Fatalf("promoted Authorization dropped valid content: %q", got)
		}
	})

	t.Run("yamby query token header value", func(t *testing.T) {
		headers := http.Header{}
		// The token field's quoted value contains an embedded CR/LF.
		auth := `Emby Token="evil` + "\r\n" + `tail"`
		u := parseIdentityURL(t, "X-Emby-Authorization="+url.QueryEscape(auth))

		manager.ApplyToURL(u, headers, "yamby")

		got := headers.Get("X-Emby-Token")
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("promoted X-Emby-Token still carries control bytes: %q", got)
		}
		if got == "" {
			t.Fatalf("X-Emby-Token was not promoted")
		}
	})

	t.Run("hills query token header value", func(t *testing.T) {
		headers := http.Header{}
		auth := `Emby Token="evil` + "\r\n" + `tail"`
		u := parseIdentityURL(t, "X-Emby-Authorization="+url.QueryEscape(auth))

		manager.ApplyToURL(u, headers, "hills_windows")

		got := headers.Get("X-Emby-Token")
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("promoted X-Emby-Token still carries control bytes: %q", got)
		}
		if got == "" {
			t.Fatalf("X-Emby-Token was not promoted")
		}
	})
}

func TestApplyToURLKeepsHillsQueryIdentityBehavior(t *testing.T) {
	manager := NewManager(nil)
	hillsWindows := manager.Snapshot("hills_windows")
	u, err := url.Parse(`https://example.test/emby/Users/1?X-Emby-Authorization=Emby+Token%3D%22source-token%22%2C+Client%3D%22Synthetic+Client%22%2C+Device%3D%22SYNTHETIC-PC%22%2C+DeviceId%3D%22synthetic-source-device-id%22%2C+Version%3D%221.2.0%22&X-Emby-Client=Synthetic+Client&X-Emby-Device-Name=SYNTHETIC-PC&X-Emby-Device-Id=synthetic-source-device-id&X-Emby-Language=en-us&tag=v1`)
	if err != nil {
		t.Fatal(err)
	}

	headers := http.Header{}
	manager.ApplyToURL(u, headers, "hills_windows")

	got := u.RawQuery
	for _, want := range []string{"X-Emby-Authorization=", "Client%3D%22Hills+Windows%22", "X-Emby-Client=Hills+Windows", "X-Emby-Language=en-us", "X-Emby-Token=source-token"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RawQuery = %q, want to contain %q", got, want)
		}
	}
	for _, reject := range []string{"Synthetic+Client", "SYNTHETIC-PC"} {
		if strings.Contains(got, reject) {
			t.Fatalf("RawQuery = %q, want to reject %q", got, reject)
		}
	}
	query := u.Query()
	wantDeviceID := DeriveDeviceID("", "hills_windows", "synthetic-source-device-id", Profiles["hills_windows"])
	for key, want := range map[string]string{
		"X-Emby-Device-Name": hillsWindows.DeviceName,
		"X-Emby-Device-Id":   wantDeviceID,
		"X-Emby-Language":    "en-us",
		"X-Emby-Token":       "source-token",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if got := headers.Get("X-Emby-Token"); got != "source-token" {
		t.Fatalf("X-Emby-Token header = %q, want source-token", got)
	}
	if !strings.Contains(got, "tag=v1") {
		t.Fatalf("RawQuery = %q, want to preserve non-identity query", got)
	}
}

func TestApplyToURLKeepsHillsDefaultLanguageOutsideUsersRoot(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{"X-Emby-Token": {"header-token"}}
	u, err := url.Parse("https://example.test/emby/Users/1/Items?X-Emby-Language=en-us&tag=v1")
	if err != nil {
		t.Fatal(err)
	}

	manager.ApplyToURL(u, headers, "hills_windows")

	query := u.Query()
	if got := query.Get("X-Emby-Language"); got != "zh-cn" {
		t.Fatalf("X-Emby-Language = %q, want zh-cn", got)
	}
	if got := query.Get("tag"); got != "v1" {
		t.Fatalf("tag = %q, want v1", got)
	}
}

func TestApplyToURLNormalizesHillsQueryIdentity(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{"X-Emby-Token": {"header-token"}}
	u := parseIdentityURL(t, "x_emby_client=Original&X_EMBY_DEVICE_ID=source-device&X-MediaBrowser-Client=MediaClient&X_MediaBrowser_DeviceId=media-device&DeviceId=bare-device&DeviceName=bare-name&Version=0.0.0-test&Language=en-us&token=signed-token&client=signed-client&authorization=Bearer+direct-token&X-Emby-Token=query-token&X-Emby-Token=second-query-token&quality=90&tag=v1")

	manager.ApplyToURL(u, headers, "hills_android")

	snap := manager.Snapshot("hills_android")
	wantDeviceID := DeriveDeviceID("", "hills_android", "source-device", Profiles["hills_android"])
	snap.DeviceID = wantDeviceID
	query := u.Query()
	for key, want := range map[string]string{
		"X-Emby-Authorization":  buildHillsAuthorization(snap),
		"X-Emby-Client":         snap.ClientName,
		"X-Emby-Device-Name":    snap.DeviceName,
		"X-Emby-Device-Id":      snap.DeviceID,
		"X-Emby-Client-Version": snap.ClientVersion,
		"X-Emby-Language":       "en-us",
		"X-Emby-Token":          "header-token",
		"DeviceId":              "bare-device",
		"DeviceName":            "bare-name",
		"Version":               "0.0.0-test",
		"Language":              "en-us",
		"token":                 "signed-token",
		"client":                "signed-client",
		"authorization":         "Bearer direct-token",
		"quality":               "90",
		"tag":                   "v1",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
		if strings.HasPrefix(key, "X-Emby-") && len(query[key]) != 1 {
			t.Fatalf("%s values = %v, want one normalized value", key, query[key])
		}
	}
	for _, key := range []string{"x_emby_client", "X_EMBY_DEVICE_ID", "X-MediaBrowser-Client", "X_MediaBrowser_DeviceId"} {
		if query.Has(key) {
			t.Fatalf("%s query was not removed", key)
		}
	}
}

func TestApplyToResourceURLKeepsResourceQueryHeaderIdentity(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	u := parseIdentityURL(t, "x_emby_client=Original&X_EMBY_DEVICE_ID=source-device&X-MediaBrowser-Token=media-query-token&DeviceId=bare-device&api_key=api-token&mediaSourceId=media-source&quality=90&tag=v1")

	manager.ApplyToResourceURL(u, headers, "hills_windows")

	snap := manager.Snapshot("hills_windows")
	query := u.Query()
	for _, key := range []string{"x_emby_client", "X_EMBY_DEVICE_ID", "X-MediaBrowser-Token", "X-Emby-Authorization", "X-Emby-Client", "X-Emby-Token"} {
		if query.Has(key) {
			t.Fatalf("%s query was not removed: %s", key, u.RawQuery)
		}
	}
	for key, want := range map[string]string{
		"DeviceId":      "bare-device",
		"api_key":       "api-token",
		"mediaSourceId": "media-source",
		"quality":       "90",
		"tag":           "v1",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if got := headers.Get("User-Agent"); got != "" {
		t.Fatalf("User-Agent = %q, want unchanged", got)
	}
	if got := headers.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="`+snap.ClientName+`"`) {
		t.Fatalf("X-Emby-Authorization = %q, want Hills header identity", got)
	}
	if got := headers.Get("X-Emby-Token"); got != "media-query-token" {
		t.Fatalf("X-Emby-Token = %q, want media-query-token", got)
	}
}

func TestApplyToURLHillsTokenPriority(t *testing.T) {
	manager := NewManager(nil)
	encodedAuth := url.QueryEscape(testSourceEmbyTokenAuth)
	tests := []struct {
		name     string
		headers  http.Header
		rawQuery string
		want     string
	}{
		{
			name:     "header token wins",
			headers:  http.Header{"X-Emby-Token": {"header-token"}},
			rawQuery: "X-Emby-Token=query-token&X-Emby-Authorization=" + encodedAuth,
			want:     "header-token",
		},
		{
			name:     "normalized header token wins",
			headers:  http.Header{"X_Emby_Token": {"normalized-header-token"}},
			rawQuery: "X-Emby-Token=query-token&X-Emby-Authorization=" + encodedAuth,
			want:     "normalized-header-token",
		},
		{
			name:     "query token wins over auth token",
			headers:  http.Header{},
			rawQuery: "X-Emby-Token=query-token&X-Emby-Authorization=" + encodedAuth,
			want:     "query-token",
		},
		{
			name:     "media browser header token wins over auth token",
			headers:  http.Header{"X-MediaBrowser-Token": {"media-header-token"}},
			rawQuery: "X-Emby-Authorization=" + encodedAuth,
			want:     "media-header-token",
		},
		{
			name:     "normalized media browser header token wins",
			headers:  http.Header{"X_MediaBrowser_Token": {"normalized-media-header-token"}},
			rawQuery: "X-MediaBrowser-Token=media-query-token&X-Emby-Authorization=" + encodedAuth,
			want:     "normalized-media-header-token",
		},
		{
			name:     "media browser query token wins over auth token",
			headers:  http.Header{},
			rawQuery: "X-MediaBrowser-Token=media-query-token&X-Emby-Authorization=" + encodedAuth,
			want:     "media-query-token",
		},
		{
			name:     "auth token fills missing token",
			headers:  http.Header{},
			rawQuery: "X-Emby-Authorization=" + encodedAuth,
			want:     "source-token",
		},
		{
			name:     "bare token auth is ignored",
			headers:  http.Header{},
			rawQuery: "X-Emby-Authorization=" + url.QueryEscape(`Token="source-token"`),
			want:     "",
		},
		{
			name:     "bearer token auth is ignored",
			headers:  http.Header{},
			rawQuery: "X-Emby-Authorization=" + url.QueryEscape(`Bearer Token="source-token"`),
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := parseIdentityURL(t, tt.rawQuery)

			manager.ApplyToURL(u, tt.headers, "hills_windows")

			if got := tt.headers.Get("X-Emby-Token"); got != tt.want {
				t.Fatalf("X-Emby-Token header = %q, want %q", got, tt.want)
			}
			if got := u.Query().Get("X-Emby-Token"); got != tt.want {
				t.Fatalf("X-Emby-Token query = %q, want %q", got, tt.want)
			}
			if strings.Contains(strings.ToLower(u.Query().Get("X-Emby-Authorization")), "token=") {
				t.Fatalf("X-Emby-Authorization still contains token: %q", u.Query().Get("X-Emby-Authorization"))
			}
		})
	}
}

func parseIdentityURL(t *testing.T, rawQuery string) *url.URL {
	t.Helper()
	u, err := url.Parse("https://example.test/emby/Users/1?" + rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestProfileDeviceIdentityDefaults(t *testing.T) {
	manager := NewManager(nil)
	tests := []struct {
		name       string
		profile    string
		deviceName string
		idLength   int
		idFormat   string
	}{
		{
			name:       "yamby keeps original android strategy",
			profile:    "yamby",
			deviceName: "Android",
			idFormat:   "uuid",
		},
		{
			name:       "hills android keeps original diting strategy",
			profile:    "hills_android",
			deviceName: "diting",
			idLength:   16,
		},
		{
			name:     "hills windows keeps generated desktop strategy",
			profile:  "hills_windows",
			idLength: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := manager.Snapshot(tt.profile)
			if tt.deviceName != "" && snap.DeviceName != tt.deviceName {
				t.Fatalf("DeviceName = %q, want %q", snap.DeviceName, tt.deviceName)
			}
			if tt.profile == "hills_windows" && !strings.HasPrefix(snap.DeviceName, "DESKTOP-") {
				t.Fatalf("DeviceName = %q, want DESKTOP-*", snap.DeviceName)
			}
			switch tt.idFormat {
			case "uuid":
				if !isUUID(snap.DeviceID) {
					t.Fatalf("DeviceID = %q, want uuid", snap.DeviceID)
				}
			default:
				if !isHexLength(snap.DeviceID, tt.idLength) {
					t.Fatalf("DeviceID = %q, want %d hex chars", snap.DeviceID, tt.idLength)
				}
			}
		})
	}
}

func TestDeriveDeviceIDFormats(t *testing.T) {
	secret := "test-secret"
	inboundID := "client-inbound-device-id-12345"

	// 1. yamby UUIDv4
	yambyID := DeriveDeviceID(secret, "yamby", inboundID, Profiles["yamby"])
	if !isUUID(yambyID) {
		t.Fatalf("yamby derived ID %q is not a valid UUID", yambyID)
	}
	// UUIDv4 校验: version 4, variant 1 (8, 9, a, b)
	if yambyID[14] != '4' {
		t.Fatalf("yamby derived ID %q version byte is %c, want 4", yambyID, yambyID[14])
	}
	varChar := yambyID[19]
	if varChar != '8' && varChar != '9' && varChar != 'a' && varChar != 'b' {
		t.Fatalf("yamby derived ID %q variant char is %c, want 8/9/a/b", yambyID, varChar)
	}

	// 2. hills_android 16 hex
	hillsAndroidID := DeriveDeviceID(secret, "hills_android", inboundID, Profiles["hills_android"])
	if !isHexLength(hillsAndroidID, 16) {
		t.Fatalf("hills_android derived ID %q is not 16 hex", hillsAndroidID)
	}

	// 3. hills_windows 32 hex
	hillsWindowsID := DeriveDeviceID(secret, "hills_windows", inboundID, Profiles["hills_windows"])
	if !isHexLength(hillsWindowsID, 32) {
		t.Fatalf("hills_windows derived ID %q is not 32 hex", hillsWindowsID)
	}

	// 4. 纯函数确定性
	yambyID2 := DeriveDeviceID(secret, "yamby", inboundID, Profiles["yamby"])
	if yambyID != yambyID2 {
		t.Fatalf("same inputs must yield identical derived ID: %q != %q", yambyID, yambyID2)
	}

	// 5. 不同入站 DeviceId
	yambyOther := DeriveDeviceID(secret, "yamby", "different-device", Profiles["yamby"])
	if yambyID == yambyOther {
		t.Fatalf("different inbound IDs must yield different derived IDs")
	}

	// 6. 出站不是入站原文
	if yambyID == inboundID || hillsAndroidID == inboundID || hillsWindowsID == inboundID {
		t.Fatalf("outbound ID must not equal inbound ID raw value")
	}
}

func TestTokenAliasMapping(t *testing.T) {
	manager := NewManager(nil)
	if got := manager.LookupTokenDeviceID("non-existent"); got != "" {
		t.Fatalf("lookup non-existent token = %q, want empty", got)
	}

	manager.RememberTokenDeviceID("token-123", "derived-device-id-123")
	if got := manager.LookupTokenDeviceID("token-123"); got != "derived-device-id-123" {
		t.Fatalf("lookup token-123 = %q, want derived-device-id-123", got)
	}
}
