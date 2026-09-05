package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"embyproxy/internal/storage"
)

const identityKey = "system:upstream_identity"
const DefaultProfile = "yamby"

type Profile struct {
	Key            string
	Label          string
	ClientName     string
	ClientVersion  string
	DeviceName     string
	DeviceIDLength int
	DeviceIDFormat string
	UserAgent      string
}

type Snapshot struct {
	Profile       string `json:"profile"`
	Label         string `json:"label"`
	ClientName    string `json:"clientName"`
	ClientVersion string `json:"clientVersion"`
	DeviceName    string `json:"deviceName"`
	DeviceID      string `json:"deviceId"`
	ShortID       string `json:"shortId"`
	UserAgent     string `json:"userAgent"`
}

type deviceState struct {
	DeviceName string `json:"deviceName"`
	DeviceID   string `json:"deviceId"`
}

type persisted struct {
	ClientName    string                 `json:"clientName"`
	ClientVersion string                 `json:"clientVersion"`
	UserAgent     string                 `json:"userAgent"`
	Profiles      map[string]deviceState `json:"profiles"`
}

type Manager struct {
	store        *storage.Store
	mu           sync.Mutex
	profiles     map[string]deviceState
	initialized  bool
	tokenAliases map[string]string
}

var Profiles = map[string]Profile{
	"yamby": {
		Key:            "yamby",
		Label:          "Yamby Android",
		ClientName:     "Yamby",
		ClientVersion:  "2.0.4.6",
		DeviceName:     "Android",
		DeviceIDFormat: "uuid",
		UserAgent:      "Yamby/2.0.4.6(Android)",
	},
	"hills_android": {
		Key:            "hills_android",
		Label:          "Hills Android",
		ClientName:     "Hills",
		ClientVersion:  "1.7.2",
		DeviceName:     "diting",
		DeviceIDLength: 16,
		UserAgent:      "Hills/1.7.2 (android; 15)",
	},
	"hills_windows": {
		Key:            "hills_windows",
		Label:          "Hills Windows",
		ClientName:     "Hills Windows",
		ClientVersion:  "1.3.1",
		DeviceIDLength: 32,
		UserAgent:      "Hills Windows/1.3.1 (windows; 19041.vb_release.191206-1406)",
	},
}

var ProfileOrder = []string{DefaultProfile, "hills_android", "hills_windows"}

var (
	embyAuthorizationRE         = regexp.MustCompile(`(?i)^(?:MediaBrowser|Emby)(?:\s|$)`)
	embyAuthorizationTokenRE    = regexp.MustCompile(`(?i)^(?:MediaBrowser|Emby)(?:\s|$).*?\bToken\s*=\s*("[^"]*"|[^,\s]+)`)
	embyAuthorizationDeviceIDRE = regexp.MustCompile(`(?i)\bDeviceId\s*=\s*("[^"]*"|[^,\s]+)`)
	embyAuthorizationClientRE   = regexp.MustCompile(`(?i)\bClient\s*=\s*("[^"]*"|[^,\s]+)`)
	authorizationHeaderKeys     = []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization", "X-Authorization"}
)

func NewManager(store *storage.Store) *Manager {
	return &Manager{store: store, profiles: map[string]deviceState{}, tokenAliases: map[string]string{}}
}

func (m *Manager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var saved persisted
	_, _ = m.store.KV().GetJSON(ctx, identityKey, &saved)
	m.profiles = normalizeSavedProfiles(saved.Profiles)
	m.initialized = true
	current := m.persistedLocked()
	if !samePersisted(saved, current) {
		return m.store.KV().Put(ctx, identityKey, current)
	}
	return nil
}

func (m *Manager) Snapshot(profile string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureLocked()
	return m.snapshotLocked(profile)
}

func (m *Manager) snapshotLocked(profile string) Snapshot {
	selected := GetProfile(profile)
	state := m.deviceStateLocked(selected.Key)
	shortID := state.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	ua := selected.UserAgent
	if ua == "Yamby/2.0.4.6(Android" {
		ua = "Yamby/2.0.4.6(Android)"
	}
	return Snapshot{
		Profile:       selected.Key,
		Label:         selected.Label,
		ClientName:    selected.ClientName,
		ClientVersion: selected.ClientVersion,
		DeviceName:    state.DeviceName,
		DeviceID:      state.DeviceID,
		ShortID:       shortID,
		UserAgent:     ua,
	}
}

func (m *Manager) RememberTokenDeviceID(token, deviceID string) {
	token = strings.TrimSpace(token)
	deviceID = strings.TrimSpace(deviceID)
	if token == "" || deviceID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokenAliases == nil {
		m.tokenAliases = make(map[string]string)
	}
	if len(m.tokenAliases) > 10000 {
		m.tokenAliases = make(map[string]string)
	}
	m.tokenAliases[token] = deviceID
}

func (m *Manager) LookupTokenDeviceID(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokenAliases == nil {
		return ""
	}
	return m.tokenAliases[token]
}

func DeriveDeviceID(secret, profileKey, inboundDeviceID string, p Profile) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(profileKey + "\x00" + inboundDeviceID))
	sum := mac.Sum(nil)

	switch strings.ToLower(strings.TrimSpace(p.DeviceIDFormat)) {
	case "uuid":
		buf := make([]byte, 16)
		copy(buf, sum[:16])
		buf[6] = (buf[6] & 0x0f) | 0x40 // Version 4
		buf[8] = (buf[8] & 0x3f) | 0x80 // RFC 4122 variant
		hexed := hex.EncodeToString(buf)
		return hexed[:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:]
	default:
		length := p.DeviceIDLength
		if length <= 0 {
			length = 32
		}
		hexed := hex.EncodeToString(sum)
		if len(hexed) > length {
			return hexed[:length]
		}
		return hexed
	}
}

func inboundDeviceIDFromAuth(auth string) string {
	matches := embyAuthorizationDeviceIDRE.FindStringSubmatch(strings.TrimSpace(auth))
	if len(matches) < 2 {
		return ""
	}
	return unquoteAuthFieldValue(matches[1])
}

func InboundDeviceIDFromHeaders(headers http.Header) string {
	if headers == nil {
		return ""
	}
	if id := firstSanitizedToken(
		firstHeaderValue(headers, "X-Emby-Device-Id"),
		firstHeaderValue(headers, "X-MediaBrowser-DeviceId"),
		firstHeaderValueByNormalizedKey(headers, "xembydeviceid"),
		firstHeaderValueByNormalizedKey(headers, "xmediabrowserdeviceid"),
	); id != "" {
		return id
	}
	for _, key := range authorizationHeaderKeys {
		if id := inboundDeviceIDFromAuth(firstHeaderValue(headers, key)); id != "" {
			return id
		}
	}
	for key, values := range headers {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if id := inboundDeviceIDFromAuth(value); id != "" {
				return id
			}
		}
	}
	return ""
}

func (m *Manager) ResolveOutboundDeviceID(secret string, snap Snapshot, inboundDeviceID, token string) string {
	p := GetProfile(snap.Profile)
	inboundDeviceID = strings.TrimSpace(inboundDeviceID)
	token = strings.TrimSpace(token)

	if inboundDeviceID != "" {
		outboundID := DeriveDeviceID(secret, snap.Profile, inboundDeviceID, p)
		if token != "" {
			m.RememberTokenDeviceID(token, outboundID)
		}
		return outboundID
	}

	if token != "" {
		if cached := m.LookupTokenDeviceID(token); cached != "" {
			return cached
		}
	}

	return snap.DeviceID
}

func (m *Manager) ApplyToHeaders(headers http.Header, profile string, secret ...string) {
	snap := m.Snapshot(profile)
	sec := ""
	if len(secret) > 0 {
		sec = secret[0]
	}
	m.applyProfileIdentityToHeaders(headers, snap, sec)
}

func (m *Manager) applyProfileIdentityToHeaders(headers http.Header, snap Snapshot, secret string) {
	if headers == nil {
		return
	}
	token := identityTokenFromHeaders(headers)
	inboundDeviceID := InboundDeviceIDFromHeaders(headers)
	outboundDeviceID := m.ResolveOutboundDeviceID(secret, snap, inboundDeviceID, token)

	stripImpersonationHeaders(headers)

	currentSnap := snap
	currentSnap.DeviceID = outboundDeviceID

	headers.Set("X-Emby-Client", currentSnap.ClientName)
	headers.Set("X-Emby-Client-Version", currentSnap.ClientVersion)
	headers.Set("X-Emby-Device-Name", currentSnap.DeviceName)
	headers.Set("X-Emby-Device-Id", currentSnap.DeviceID)

	if usesHillsAuthFormat(currentSnap) {
		headers.Set("X-Emby-Authorization", buildHillsAuthorization(currentSnap))
	} else {
		headers.Set("X-Emby-Authorization", buildYambyAuthorization("", currentSnap))
	}
	if token != "" {
		headers.Set("X-Emby-Token", token)
	}
}

func stripImpersonationHeaders(headers http.Header) {
	for key := range cloneHeader(headers) {
		normalized := normalizeHeaderKey(key)
		switch {
		case normalized == "xembytoken":
			if !strings.EqualFold(key, "X-Emby-Token") {
				deleteHeaderKey(headers, key)
			}
			continue
		case normalized == "xembyauthorization":
			deleteHeaderKey(headers, key)
		case isStandaloneIdentityHeader(normalized):
			deleteHeaderKey(headers, key)
		case strings.HasPrefix(normalized, "xmediabrowser"):
			deleteHeaderKey(headers, key)
		case normalized == "xauthorization":
			deleteHeaderKey(headers, key)
		case normalized == "authorization" && isEmbyAuthorization(headers.Get(key)):
			deleteHeaderKey(headers, key)
		}
	}
}

func isStandaloneIdentityHeader(normalizedKey string) bool {
	switch normalizedKey {
	case "xembyclient", "xembyclientversion", "xembydevicename", "xembydeviceid", "xembylanguage", "xapplication":
		return true
	default:
		return false
	}
}

func deleteHeaderKey(headers http.Header, key string) {
	delete(headers, key)
	headers.Del(key)
}

func (m *Manager) ApplyToURL(u *url.URL, headers http.Header, profile string, secret ...string) {
	if u == nil {
		return
	}
	snap := m.Snapshot(profile)
	sec := ""
	if len(secret) > 0 {
		sec = secret[0]
	}
	if usesYambyAuthFormat(snap) {
		inboundDeviceID := firstSanitizedToken(
			firstQueryValueByNormalizedKey(u, "xembydeviceid"),
			firstQueryValueByNormalizedKey(u, "xmediabrowserdeviceid"),
			firstQueryValueByNormalizedKey(u, "deviceid"),
		)
		token := firstSanitizedToken(
			firstQueryValueByNormalizedKey(u, "xembytoken"),
			firstQueryValueByNormalizedKey(u, "xmediabrowsertoken"),
			firstQueryValueByNormalizedKey(u, "apikey"),
			firstQueryValueByNormalizedKey(u, "token"),
			authTokenFromURL(u),
			authTokenFromHeaders(headers),
		)
		if inboundDeviceID != "" && token != "" {
			outboundID := m.ResolveOutboundDeviceID(sec, snap, inboundDeviceID, token)
			m.RememberTokenDeviceID(token, outboundID)
		}
		applyYambyQueryAuthToHeaders(u, headers)
		setTokenHeaderIfMissing(headers, authTokenFromHeaders(headers))
		return
	}
	if usesHillsAuthFormat(snap) {
		m.applyHillsQueryIdentityToURL(u, headers, snap, sec)
		return
	}
	setTokenHeaderIfMissing(headers, authTokenFromURL(u))
	applyProfileIdentityToURL(u, snap)
}

func (m *Manager) ApplyToResourceURL(u *url.URL, headers http.Header, profile string, secret ...string) {
	if u == nil {
		return
	}
	snap := m.Snapshot(profile)
	sec := ""
	if len(secret) > 0 {
		sec = secret[0]
	}
	if usesYambyAuthFormat(snap) {
		applyYambyQueryAuthToHeaders(u, headers)
		setTokenHeaderIfMissing(headers, authTokenFromHeaders(headers))
		return
	}
	if usesHillsAuthFormat(snap) {
		m.applyHillsResourceIdentityToURL(u, headers, snap, sec)
		return
	}
	setTokenHeaderIfMissing(headers, authTokenFromURL(u))
	applyProfileIdentityToURL(u, snap)
}

func (m *Manager) ApplyToDirectURL(u *url.URL, headers http.Header, profile string, secret ...string) {
	snap := m.Snapshot(profile)
	setTokenHeaderIfMissing(headers, firstSanitizedToken(
		firstQueryValueByNormalizedKey(u, "xembytoken"),
		firstQueryValueByNormalizedKey(u, "xmediabrowsertoken"),
		firstQueryValueByNormalizedKey(u, "apikey"),
		firstQueryValueByNormalizedKey(u, "token"),
		authTokenFromURL(u),
	))
	if headers != nil && InboundDeviceIDFromHeaders(headers) == "" {
		if qDevID := firstSanitizedToken(
			firstQueryValueByNormalizedKey(u, "xembydeviceid"),
			firstQueryValueByNormalizedKey(u, "xmediabrowserdeviceid"),
			firstQueryValueByNormalizedKey(u, "deviceid"),
		); qDevID != "" {
			headers.Set("X-Emby-Device-Id", qDevID)
		}
	}
	sec := ""
	if len(secret) > 0 {
		sec = secret[0]
	}
	m.applyProfileIdentityToHeaders(headers, snap, sec)
}

func setTokenHeaderIfMissing(headers http.Header, token string) {
	if headers == nil || headersHaveNonEmptyValue(headers, "X-Emby-Token") || strings.TrimSpace(token) == "" {
		return
	}
	headers.Set("X-Emby-Token", sanitizeHeaderValue(token))
}

func (m *Manager) applyHillsQueryIdentityToURL(u *url.URL, headers http.Header, snap Snapshot, secret string) {
	q := u.Query()
	token := hillsTokenForURL(u, headers)
	inboundDeviceID := InboundDeviceIDFromHeaders(headers)
	if inboundDeviceID == "" {
		inboundDeviceID = firstSanitizedToken(
			firstQueryValueByNormalizedKey(u, "xembydeviceid"),
			firstQueryValueByNormalizedKey(u, "xmediabrowserdeviceid"),
			firstQueryValueByNormalizedKey(u, "deviceid"),
		)
	}
	currentSnap := snap
	if inboundDeviceID != "" || token != "" {
		outboundDeviceID := m.ResolveOutboundDeviceID(secret, snap, inboundDeviceID, token)
		currentSnap.DeviceID = outboundDeviceID
	}
	removeHillsQueryIdentity(q)
	q.Set("X-Emby-Authorization", buildHillsAuthorization(currentSnap))
	q.Set("X-Emby-Client", currentSnap.ClientName)
	q.Set("X-Emby-Device-Name", currentSnap.DeviceName)
	q.Set("X-Emby-Device-Id", currentSnap.DeviceID)
	q.Set("X-Emby-Client-Version", currentSnap.ClientVersion)
	q.Set("X-Emby-Language", hillsLanguageForURL(u))
	if token != "" {
		q.Set("X-Emby-Token", token)
		if headers != nil {
			headers.Set("X-Emby-Token", sanitizeHeaderValue(token))
		}
	}
	u.RawQuery = q.Encode()
}

func hillsLanguageForURL(u *url.URL) string {
	if isUsersRootPath(u) {
		return "en-us"
	}
	return "zh-cn"
}

func isUsersRootPath(u *url.URL) bool {
	if u == nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, part := range parts {
		if strings.EqualFold(part, "users") {
			return i+2 == len(parts) && strings.TrimSpace(parts[i+1]) != ""
		}
	}
	return false
}

func (m *Manager) applyHillsResourceIdentityToURL(u *url.URL, headers http.Header, snap Snapshot, secret string) {
	token := hillsTokenForURL(u, headers)
	q := u.Query()
	if removeHillsQueryIdentity(q) {
		u.RawQuery = q.Encode()
	}
	setTokenHeaderIfMissing(headers, token)
	m.applyProfileIdentityToHeaders(headers, snap, secret)
}

func removeHillsQueryIdentity(q url.Values) bool {
	changed := false
	for key, values := range q {
		if isHillsQueryIdentityParam(normalizeHeaderKey(key), values) {
			q.Del(key)
			changed = true
		}
	}
	return changed
}

func hillsTokenForURL(u *url.URL, headers http.Header) string {
	return firstSanitizedToken(
		firstHeaderValue(headers, "X-Emby-Token"),
		firstHeaderValue(headers, "X-MediaBrowser-Token"),
		firstHeaderValueByNormalizedKey(headers, "xembytoken"),
		firstHeaderValueByNormalizedKey(headers, "xmediabrowsertoken"),
		firstQueryValueByNormalizedKey(u, "xembytoken"),
		firstQueryValueByNormalizedKey(u, "xmediabrowsertoken"),
		authTokenFromURL(u),
		authTokenFromHeaders(headers),
	)
}

func firstSanitizedToken(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return sanitizeHeaderValue(value)
		}
	}
	return ""
}

func firstQueryValueByNormalizedKey(u *url.URL, normalizedKey string) string {
	if u == nil {
		return ""
	}
	for key, values := range u.Query() {
		if normalizeHeaderKey(key) != normalizedKey {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func authTokenFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	for key, values := range u.Query() {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if token := authTokenFromValue(value); token != "" {
				return token
			}
		}
	}
	return ""
}

func isAuthorizationKey(normalizedKey string) bool {
	switch normalizedKey {
	case "authorization", "xauthorization", "xembyauthorization", "xmediabrowserauthorization":
		return true
	default:
		return false
	}
}

func isHillsQueryIdentityParam(normalizedKey string, values []string) bool {
	if strings.HasPrefix(normalizedKey, "xemby") || strings.HasPrefix(normalizedKey, "xmediabrowser") {
		return true
	}
	switch normalizedKey {
	case "authorization", "xauthorization":
		for _, value := range values {
			if isEmbyAuthorization(value) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func applyProfileIdentityToURL(u *url.URL, snap Snapshot) {
	q := u.Query()
	changed := false
	for key, values := range q {
		if len(values) == 0 {
			continue
		}
		switch normalizeHeaderKey(key) {
		case "xembyclient", "xmediabrowserclient":
			q.Set(key, snap.ClientName)
			changed = true
		case "xembyclientversion", "xmediabrowserclientversion":
			q.Set(key, snap.ClientVersion)
			changed = true
		case "xembydevicename", "xmediabrowserdevicename", "devicename":
			q.Set(key, snap.DeviceName)
			changed = true
		case "xembydeviceid", "xmediabrowserdeviceid", "deviceid":
			q.Set(key, snap.DeviceID)
			changed = true
		case "xembyauthorization", "xmediabrowserauthorization", "xauthorization", "authorization":
			q.Set(key, RewriteMediaBrowserAuthorization(values[0], snap))
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
}

var yambyQueryAuthHeaders = map[string]string{
	"authorization":              "Authorization",
	"xauthorization":             "X-Authorization",
	"xembyauthorization":         "X-Emby-Authorization",
	"xembytoken":                 "X-Emby-Token",
	"xmediabrowserauthorization": "X-MediaBrowser-Authorization",
	"xmediabrowsertoken":         "X-MediaBrowser-Token",
}

func applyYambyQueryAuthToHeaders(u *url.URL, headers http.Header) {
	q := u.Query()
	changed := false

	for rawQuery := u.RawQuery; rawQuery != ""; {
		var part string
		part, rawQuery, _ = strings.Cut(rawQuery, "&")
		if part == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		normalizedKey := normalizeHeaderKey(key)
		if canonical, ok := yambyQueryAuthHeaders[normalizedKey]; ok {
			if headers != nil && !headersHaveNonEmptyValue(headers, canonical) {
				value, err := url.QueryUnescape(rawValue)
				if err != nil {
					value = rawValue
				}
				headers.Set(canonical, sanitizeHeaderValue(value))
			}
			q.Del(key)
			changed = true
			continue
		}
		if isYambyQueryIdentityKey(normalizedKey) {
			q.Del(key)
			changed = true
		}
	}

	if changed {
		u.RawQuery = q.Encode()
	}
}

func isYambyQueryIdentityKey(normalizedKey string) bool {
	if strings.HasPrefix(normalizedKey, "xemby") || strings.HasPrefix(normalizedKey, "xmediabrowser") {
		return true
	}
	switch normalizedKey {
	case "deviceid", "devicename", "client", "version":
		return true
	default:
		return false
	}
}

// sanitizeHeaderValue strips control characters (CR/LF and other bytes below
// space, plus the lone DEL) that net/http rejects when sending a request.
// Values promoted from URL query parameters are untrusted input, so removing
// them here keeps the request sendable instead of letting the transport fail
// with "invalid header field value".
func sanitizeHeaderValue(value string) string {
	if !strings.ContainsAny(value, "\r\n") && !containsHeaderValueControlByte(value) {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// containsHeaderValueControlByte reports whether value contains an ASCII
// control byte (0x00-0x1F) or DEL (0x7F) outside of the allowed HT (0x09).
func containsHeaderValueControlByte(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func RewriteMediaBrowserAuthorization(value string, snap Snapshot) string {
	raw := strings.TrimSpace(value)
	if !isEmbyAuthorization(raw) {
		return value
	}
	if usesYambyAuthFormat(snap) {
		return buildYambyAuthorization(raw, snap)
	}
	return buildHillsAuthorization(snap)
}

func isEmbyAuthorization(value string) bool {
	return embyAuthorizationRE.MatchString(strings.TrimSpace(value))
}

func NormalizeProfile(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	if _, ok := Profiles[key]; ok {
		return key
	}
	return DefaultProfile
}

func GetProfile(value string) Profile {
	return Profiles[NormalizeProfile(value)]
}

func ProfileKeys() []string {
	seen := map[string]bool{}
	keys := make([]string, 0, len(Profiles))
	for _, key := range ProfileOrder {
		if _, ok := Profiles[key]; ok && !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	extra := make([]string, 0, len(Profiles)-len(keys))
	for key := range Profiles {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	return append(keys, extra...)
}

func (m *Manager) persistedLocked() persisted {
	current := m.snapshotLocked(DefaultProfile)
	profiles := map[string]deviceState{}
	for key := range Profiles {
		profiles[key] = m.deviceStateLocked(key)
	}
	return persisted{
		ClientName:    current.ClientName,
		ClientVersion: current.ClientVersion,
		UserAgent:     current.UserAgent,
		Profiles:      profiles,
	}
}

func (m *Manager) ensureLocked() {
	if m.initialized && m.profiles != nil {
		return
	}
	m.profiles = normalizeSavedProfiles(m.profiles)
	m.initialized = true
}

func (m *Manager) deviceStateLocked(profile string) deviceState {
	selected := GetProfile(profile)
	if m.profiles == nil {
		m.profiles = map[string]deviceState{}
	}
	state := normalizeDeviceState(selected, m.profiles[selected.Key])
	m.profiles[selected.Key] = state
	return state
}

func normalizeSavedProfiles(saved map[string]deviceState) map[string]deviceState {
	out := map[string]deviceState{}
	for key := range Profiles {
		out[key] = normalizeDeviceState(Profiles[key], saved[key])
	}
	return out
}

func normalizeDeviceState(profile Profile, saved deviceState) deviceState {
	name := strings.TrimSpace(profile.DeviceName)
	if name == "" {
		name = strings.TrimSpace(saved.DeviceName)
	}
	if name == "" {
		name = createHillsWindowsDeviceName()
	}
	deviceID := strings.ToLower(strings.TrimSpace(saved.DeviceID))
	if !validDeviceID(profile, deviceID) {
		deviceID = randomDeviceID(profile)
	}
	return deviceState{DeviceName: name, DeviceID: deviceID}
}

func samePersisted(a, b persisted) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func isHexLength(value string, length int) bool {
	if length <= 0 {
		length = 32
	}
	if len(value) != length {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func validDeviceID(profile Profile, value string) bool {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return isUUID(value)
	default:
		return isHexLength(value, profile.DeviceIDLength)
	}
}

func randomDeviceID(profile Profile) string {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return randomUUID()
	default:
		return randomHex(profile.DeviceIDLength)
	}
}

func randomHex(length int) string {
	if length <= 0 {
		length = 32
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(buf)[:length]
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
				continue
			}
			return false
		}
	}
	return true
}

func randomUUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	hexed := hex.EncodeToString(buf)
	return hexed[:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:]
}

func createHillsWindowsDeviceName() string {
	return "DESKTOP-" + strings.ToUpper(randomHex(6))
}

func formatMediaBrowserValue(value string, quoted bool) string {
	if quoted {
		return `"` + escapeMediaBrowserValue(value) + `"`
	}
	return value
}

func escapeMediaBrowserValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`)
}

func usesYambyAuthFormat(snap Snapshot) bool {
	profile := NormalizeProfile(snap.Profile)
	if snap.Profile == "" {
		profile = strings.ToLower(strings.TrimSpace(snap.ClientName))
	}
	return profile == DefaultProfile
}

func usesHillsAuthFormat(snap Snapshot) bool {
	profile := NormalizeProfile(snap.Profile)
	return profile == "hills_android" || profile == "hills_windows"
}

func buildYambyAuthorization(_ string, snap Snapshot) string {
	parts := []string{
		"Client=" + snap.ClientName,
		"Device=" + snap.DeviceName,
		"DeviceId=" + snap.DeviceID,
		"Version=" + snap.ClientVersion,
	}
	return "Emby " + strings.Join(parts, ",")
}

func buildHillsAuthorization(snap Snapshot) string {
	parts := []string{
		"Client=" + formatMediaBrowserValue(snap.ClientName, true),
		"Device=" + formatMediaBrowserValue(snap.DeviceName, true),
		"DeviceId=" + formatMediaBrowserValue(snap.DeviceID, true),
		"Version=" + formatMediaBrowserValue(snap.ClientVersion, true),
	}
	return "Emby " + strings.Join(parts, ", ")
}

func authTokenFromValue(auth string) string {
	matches := embyAuthorizationTokenRE.FindStringSubmatch(strings.TrimSpace(auth))
	if len(matches) < 2 {
		return ""
	}
	return unquoteAuthFieldValue(matches[1])
}

func authTokenFromHeaders(headers http.Header) string {
	for _, key := range authorizationHeaderKeys {
		if token := authTokenFromValue(firstHeaderValue(headers, key)); token != "" {
			return token
		}
	}
	for key, values := range headers {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if token := authTokenFromValue(value); token != "" {
				return token
			}
		}
	}
	return ""
}

func identityTokenFromHeaders(headers http.Header) string {
	return firstSanitizedToken(
		firstHeaderValue(headers, "X-Emby-Token"),
		firstHeaderValue(headers, "X-MediaBrowser-Token"),
		firstHeaderValueByNormalizedKey(headers, "xembytoken"),
		firstHeaderValueByNormalizedKey(headers, "xmediabrowsertoken"),
		authTokenFromHeaders(headers),
	)
}

func firstEmbyAuthorizationHeader(headers http.Header) string {
	for _, key := range authorizationHeaderKeys {
		value := firstHeaderValue(headers, key)
		if isEmbyAuthorization(value) {
			return value
		}
	}
	for key, values := range headers {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if isEmbyAuthorization(value) {
				return value
			}
		}
	}
	return ""
}

func unquoteAuthFieldValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
		value = strings.ReplaceAll(value, `\"`, `"`)
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	return value
}

func firstHeaderValue(headers http.Header, canonical string) string {
	if headers == nil {
		return ""
	}
	for key, values := range headers {
		if !strings.EqualFold(key, canonical) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func firstHeaderValueByNormalizedKey(headers http.Header, normalizedKey string) string {
	if headers == nil {
		return ""
	}
	for key, values := range headers {
		if normalizeHeaderKey(key) != normalizedKey {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func headersHaveNonEmptyValue(headers http.Header, canonical string) bool {
	return firstHeaderValue(headers, canonical) != ""
}

func normalizeHeaderKey(value string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(value))
}

func cloneHeader(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
