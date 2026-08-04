package capture

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

type contextKey struct{}

// ErrRequestBodyTooLarge reports that the request exceeded the replay buffer limit.
var ErrRequestBodyTooLarge = errors.New("request body exceeds replay limit")

type Recorder struct {
	cfg   config.Config
	store *storage.Store
	log   *logging.Logger
}

type state struct {
	StartedAt     time.Time
	Meta          map[string]any
	RequestBody   []byte
	ParsedBody    any
	ResponseBody  bytes.Buffer
	ResponseBytes int64
	Truncated     bool
	Suppressed    bool
}

type BodySummary struct {
	Kind      string `json:"kind"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type Record struct {
	ID              string         `json:"id"`
	TS              int64          `json:"ts"`
	Time            string         `json:"time"`
	Mode            string         `json:"mode"`
	Node            string         `json:"node"`
	AdminAction     string         `json:"adminAction"`
	Impersonated    bool           `json:"impersonated"`
	Stage           string         `json:"stage"`
	Method          string         `json:"method"`
	Status          int            `json:"status"`
	InboundURL      string         `json:"inboundUrl"`
	InboundHeaders  map[string]any `json:"inboundHeaders"`
	InboundBody     BodySummary    `json:"inboundBody"`
	TargetURL       string         `json:"targetUrl"`
	OutboundHeaders map[string]any `json:"outboundHeaders"`
	ResponseHeaders map[string]any `json:"responseHeaders"`
	ResponseBody    BodySummary    `json:"responseBody"`
	ResponseBytes   int64          `json:"responseBytes"`
	DurationMS      float64        `json:"durationMs"`
	Meta            any            `json:"meta"`
	CaseSignature   string         `json:"caseSignature,omitempty"`
}

type captureWriter struct {
	http.ResponseWriter
	state  *state
	status int
	max    int64
}

func New(cfg config.Config, store *storage.Store, log *logging.Logger) *Recorder {
	return &Recorder{cfg: cfg, store: store, log: log}
}

func (r *Recorder) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		captureCfg, err := r.captureConfig(req.Context())
		if err != nil {
			r.log.Warn("traffic", "capture config lookup failed", map[string]any{"event": "captureConfigLookupFailed", "error": err.Error()})
			next.ServeHTTP(w, req)
			return
		}
		if !captureCfg.TrafficCaptureEnabled {
			next.ServeHTTP(w, req)
			return
		}
		st := &state{StartedAt: time.Now(), Meta: map[string]any{}}
		req = req.WithContext(context.WithValue(req.Context(), contextKey{}, st))
		cw := &captureWriter{ResponseWriter: w, state: st, status: http.StatusOK, max: captureBodyMax(captureCfg)}
		next.ServeHTTP(cw, req)
		if Suppressed(req) {
			return
		}
		r.appendHTTP(req, cw, captureCfg)
	})
}

func (r *Recorder) captureConfig(ctx context.Context) (storage.SystemConfig, error) {
	fallback := storage.DefaultSystemConfig()
	if r.store == nil {
		return fallback, nil
	}
	return r.store.GetSystemConfig(ctx, fallback)
}

func captureBodyMax(cfg storage.SystemConfig) int64 {
	if cfg.TrafficCaptureBodyMax > 0 {
		return cfg.TrafficCaptureBodyMax
	}
	return storage.DefaultSystemConfig().TrafficCaptureBodyMax
}

func SetMeta(req *http.Request, meta map[string]any) {
	st := State(req)
	if st == nil || meta == nil {
		return
	}
	if st.Meta == nil {
		st.Meta = map[string]any{}
	}
	for key, value := range meta {
		st.Meta[key] = value
	}
}

func SetErrorMeta(req *http.Request, stage string, err error, fields map[string]any) {
	if err == nil {
		return
	}
	update := map[string]any{}
	for key, value := range fields {
		if key == "meta" {
			continue
		}
		update[key] = value
	}
	meta := existingMeta(req)
	if _, ok := meta["errorClass"]; !ok {
		meta["errorClass"] = classifyError(err)
	}
	if stage != "" {
		if _, ok := meta["errorStage"]; !ok {
			meta["errorStage"] = stage
		}
	}
	if extraMeta, ok := fields["meta"].(map[string]any); ok {
		for key, value := range extraMeta {
			meta[key] = value
		}
	}
	update["meta"] = meta
	SetMeta(req, update)
}

func SetRetryableStatusMeta(req *http.Request, stage string, status int, attemptMS int64) {
	meta := existingMeta(req)
	if _, ok := meta["errorClass"]; ok {
		SetMeta(req, map[string]any{"meta": meta})
		return
	}
	meta["errorClass"] = "retryable-upstream-status"
	meta["upstreamStatus"] = status
	meta["targetAttemptMs"] = attemptMS
	if stage != "" {
		meta["errorStage"] = stage
	}
	SetMeta(req, map[string]any{"meta": meta})
}

func ClearErrorMeta(req *http.Request) {
	st := State(req)
	if st == nil || st.Meta == nil {
		return
	}
	current, ok := st.Meta["meta"].(map[string]any)
	if !ok {
		return
	}
	meta := cloneAnyMap(current)
	for _, key := range []string{
		"error", "errorClass", "errorStage", "upstreamStatus", "targetAttemptMs",
		"contentEncoding", "contentType", "contentLength",
		"strmReadError", "strmSourceStatus", "strmSourceContentEncoding", "strmSourceContentType", "strmSourceContentLength",
	} {
		delete(meta, key)
	}
	SetMeta(req, map[string]any{"meta": meta})
}

func AppendErrorAttempt(req *http.Request, stage string, err error, fields map[string]any) {
	if err == nil {
		return
	}
	attempt := map[string]any{"errorClass": classifyError(err)}
	if stage != "" {
		attempt["stage"] = stage
	}
	for key, value := range fields {
		attempt[key] = value
	}
	appendAttempt(req, attempt)
}

func AppendRetryableStatusAttempt(req *http.Request, stage string, status int, attemptMS int64, target string) {
	attempt := map[string]any{
		"errorClass":      "retryable-upstream-status",
		"upstreamStatus":  status,
		"targetAttemptMs": attemptMS,
	}
	if target != "" {
		attempt["target"] = target
	}
	if stage != "" {
		attempt["stage"] = stage
	}
	appendAttempt(req, attempt)
}

func appendAttempt(req *http.Request, attempt map[string]any) {
	meta := existingMeta(req)
	copyAttemptDiagnostics(meta, attempt)
	attempts := []any{}
	if current, ok := meta["attempts"].([]any); ok {
		attempts = append(attempts, current...)
	}
	meta["attempts"] = append(attempts, attempt)
	SetMeta(req, map[string]any{"meta": meta})
}

func copyAttemptDiagnostics(meta, attempt map[string]any) {
	for _, key := range []string{
		"error", "errorStage", "upstreamStatus",
		"contentEncoding", "contentType", "contentLength",
		"strmReadError", "strmSourceStatus", "strmSourceContentEncoding", "strmSourceContentType", "strmSourceContentLength",
	} {
		if _, exists := attempt[key]; exists {
			continue
		}
		if value, ok := meta[key]; ok {
			attempt[key] = value
		}
	}
}

func existingMeta(req *http.Request) map[string]any {
	meta := map[string]any{}
	st := State(req)
	if st == nil || st.Meta == nil {
		return meta
	}
	current, ok := st.Meta["meta"].(map[string]any)
	if !ok {
		return meta
	}
	return cloneAnyMap(current)
}

func cloneAnyMap(current map[string]any) map[string]any {
	meta := map[string]any{}
	for key, value := range current {
		meta[key] = value
	}
	return meta
}

func classifyError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "context-canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return classifyError(urlErr.Err)
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "connectex"):
		return "connection-refused"
	case strings.Contains(msg, "connection reset") || strings.Contains(msg, "reset by peer"):
		return "connection-reset"
	case strings.Contains(msg, "no such host"):
		return "dns"
	case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate"):
		return "tls"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network"
	}
	return "upstream-error"
}

func RememberRequestBody(req *http.Request, body []byte) {
	st := State(req)
	if st == nil {
		return
	}
	st.RequestBody = append(st.RequestBody[:0], body...)
}

func RememberParsedBody(req *http.Request, value any) {
	st := State(req)
	if st == nil {
		return
	}
	st.ParsedBody = value
}

// Suppress skips persisting the current request in traffic capture output.
func Suppress(req *http.Request) {
	st := State(req)
	if st == nil {
		return
	}
	st.Suppressed = true
}

// Suppressed reports whether the current request should be skipped by capture.
func Suppressed(req *http.Request) bool {
	st := State(req)
	return st != nil && st.Suppressed
}

func State(req *http.Request) *state {
	if req == nil {
		return nil
	}
	st, _ := req.Context().Value(contextKey{}).(*state)
	return st
}

func (w *captureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureWriter) Write(chunk []byte) (int, error) {
	if len(chunk) > 0 {
		w.state.ResponseBytes += int64(len(chunk))
		max := int(w.stateMax())
		if w.state.ResponseBody.Len() < max {
			take := max - w.state.ResponseBody.Len()
			if take > len(chunk) {
				take = len(chunk)
			}
			_, _ = w.state.ResponseBody.Write(chunk[:take])
		}
		if w.state.ResponseBytes > w.stateMax() {
			w.state.Truncated = true
		}
	}
	return w.ResponseWriter.Write(chunk)
}

func (w *captureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *captureWriter) stateMax() int64 {
	return captureBodyMax(storage.SystemConfig{TrafficCaptureBodyMax: w.max})
}

func (r *Recorder) appendHTTP(req *http.Request, cw *captureWriter, cfg storage.SystemConfig) {
	st := cw.state
	meta := st.Meta
	responseHeaders := http.Header{}
	for key, values := range cw.Header() {
		responseHeaders[key] = values
	}
	inboundBody := BodySummary{Kind: "none", Bytes: 0}
	if st.ParsedBody != nil {
		b, _ := json.Marshal(st.ParsedBody)
		inboundBody = summarizeBuffer(b, int64(len(b)), req.Header.Get("Content-Type"), false, cfg)
	} else if st.RequestBody != nil {
		inboundBody = summarizeBuffer(st.RequestBody, int64(len(st.RequestBody)), req.Header.Get("Content-Type"), false, cfg)
	}
	now := time.Now()
	record := Record{
		ID:              requestID(req, r.log),
		TS:              now.UnixMilli(),
		Time:            formatCaptureTime(now),
		Mode:            stringMeta(meta, "mode", inferMode(req, meta)),
		Node:            stringMeta(meta, "node", ""),
		AdminAction:     stringMeta(meta, "adminAction", ""),
		Impersonated:    boolMeta(meta, "impersonated", false),
		Stage:           stringMeta(meta, "stage", ""),
		Method:          strings.ToUpper(req.Method),
		Status:          cw.status,
		InboundURL:      inboundURL(req, meta),
		InboundHeaders:  inboundHeadersToMap(req),
		InboundBody:     inboundBody,
		TargetURL:       stringMeta(meta, "targetUrl", ""),
		OutboundHeaders: headersToMap(headerMeta(meta["outboundHeaders"])),
		ResponseHeaders: headersToMap(responseHeaders),
		ResponseBody:    summarizeResponseBuffer(st.ResponseBody.Bytes(), st.ResponseBytes, responseHeaders, st.Truncated || cw.status == http.StatusPartialContent || responseHeaders.Get("Content-Range") != "", cfg),
		ResponseBytes:   st.ResponseBytes,
		DurationMS:      float64(time.Since(st.StartedAt).Microseconds()) / 1000,
		Meta:            meta["meta"],
	}
	r.appendRecord(record, cfg)
}

func (r *Recorder) appendRecord(record Record, cfg storage.SystemConfig) {
	file := r.captureFilePath(cfg)
	_ = WithFileLock(file, func() error {
		r.appendRecordLocked(file, record)
		return nil
	})
}

func (r *Recorder) appendRecordLocked(file string, record Record) {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		r.log.Warn("traffic", "capture mkdir failed", map[string]any{"event": "captureMkdirFailed", "error": err.Error()})
		return
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		r.log.Warn("traffic", "capture open failed", map[string]any{"event": "captureOpenFailed", "error": err.Error()})
		return
	}
	defer f.Close()
	_ = f.Chmod(0600)
	b, err := json.Marshal(record)
	if err != nil {
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		r.log.Warn("traffic", "capture write failed", map[string]any{"event": "captureWriteFailed", "error": err.Error()})
	}
}

func (r *Recorder) captureFilePath(cfg storage.SystemConfig) string {
	file := safeCaptureFile(cfg.TrafficCaptureFile)
	if file == "" {
		file = safeCaptureFile(storage.DefaultSystemConfig().TrafficCaptureFile)
	}
	if file == "" {
		file = filepath.Join("data", "traffic-captures.jsonl")
	}
	return filepath.Join(r.cfg.CWD, file)
}

func safeCaptureFile(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	normalized := strings.NewReplacer("\\", string(filepath.Separator), "/", string(filepath.Separator)).Replace(value)
	cleaned := filepath.Clean(normalized)
	if cleaned == "" || cleaned == "." || cleaned == "data" {
		return ""
	}
	if filepath.IsAbs(cleaned) || filepath.VolumeName(cleaned) != "" {
		return ""
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return ""
	}
	if !strings.HasPrefix(cleaned, "data"+string(filepath.Separator)) {
		return ""
	}
	return cleaned
}

func summarizeBuffer(buf []byte, bytesLen int64, contentType string, truncated bool, cfg storage.SystemConfig) BodySummary {
	if bytesLen == 0 {
		return BodySummary{Kind: "none", Bytes: 0}
	}
	max := captureBodyMax(cfg)
	if truncated || bytesLen > max {
		return BodySummary{Kind: "truncated", Bytes: bytesLen, Truncated: true}
	}
	sha := sha256.Sum256(buf)
	base := contentTypeBase(contentType)
	if !isTextContentType(base, cfg) {
		return BodySummary{Kind: "binary", Bytes: bytesLen, SHA256: hex.EncodeToString(sha[:])}
	}
	text := string(buf)
	kind := "text"
	if strings.Contains(base, "json") {
		kind = "json"
	}
	return BodySummary{Kind: kind, Bytes: bytesLen, SHA256: hex.EncodeToString(sha[:]), Text: text}
}

func summarizeResponseBuffer(buf []byte, bytesLen int64, headers http.Header, truncated bool, cfg storage.SystemConfig) BodySummary {
	contentType := headers.Get("Content-Type")
	if truncated || bytesLen == 0 {
		return summarizeBuffer(buf, bytesLen, contentType, truncated, cfg)
	}
	encodings := responseContentEncodings(headers.Get("Content-Encoding"))
	if len(encodings) == 0 {
		return summarizeBuffer(buf, bytesLen, contentType, false, cfg)
	}
	decoded, decodedTruncated, err := decodeCapturedResponseBody(buf, encodings, captureBodyMax(cfg))
	if err != nil {
		sha := sha256.Sum256(buf)
		return BodySummary{Kind: "binary", Bytes: bytesLen, SHA256: hex.EncodeToString(sha[:])}
	}
	if decodedTruncated {
		return summarizeBuffer(decoded, int64(len(decoded)), contentType, true, cfg)
	}
	return summarizeBuffer(decoded, int64(len(decoded)), contentType, false, cfg)
}

func responseContentEncodings(value string) []string {
	parts := strings.Split(value, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		encoding := strings.ToLower(strings.TrimSpace(part))
		if encoding == "" || encoding == "identity" {
			continue
		}
		encodings = append(encodings, encoding)
	}
	return encodings
}

func decodeCapturedResponseBody(encoded []byte, encodings []string, max int64) ([]byte, bool, error) {
	decoded := encoded
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, err := capturedResponseDecoder(decoded, encodings[i])
		if err != nil {
			return nil, false, err
		}
		decoded, err = io.ReadAll(io.LimitReader(reader, max+1))
		_ = reader.Close()
		if err != nil {
			return nil, false, err
		}
		if int64(len(decoded)) > max {
			return decoded, true, nil
		}
	}
	return decoded, false, nil
}

func capturedResponseDecoder(encoded []byte, encoding string) (io.ReadCloser, error) {
	switch encoding {
	case "br":
		return io.NopCloser(brotli.NewReader(bytes.NewReader(encoded))), nil
	case "zstd":
		reader, err := zstd.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		return zstdReadCloser{Decoder: reader}, nil
	case "gzip", "x-gzip":
		return gzip.NewReader(bytes.NewReader(encoded))
	case "deflate":
		if reader, err := zlib.NewReader(bytes.NewReader(encoded)); err == nil {
			return reader, nil
		}
		return flate.NewReader(bytes.NewReader(encoded)), nil
	default:
		return nil, fmt.Errorf("unsupported content encoding: %s", encoding)
	}
}

type zstdReadCloser struct {
	*zstd.Decoder
}

func (r zstdReadCloser) Close() error {
	r.Decoder.Close()
	return nil
}

func inferMode(req *http.Request, meta map[string]any) string {
	if v := stringMeta(meta, "mode", ""); v != "" {
		return v
	}
	path := req.URL.Path
	if strings.HasPrefix(path, "/admin") {
		return "admin"
	}
	if strings.HasPrefix(path, "/static") {
		return "static"
	}
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return "ws"
	}
	return "proxy"
}

func inboundURL(req *http.Request, meta map[string]any) string {
	return req.URL.RequestURI()
}

func requestID(req *http.Request, log *logging.Logger) string {
	if id := req.Context().Value("requestID"); id != nil {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return log.NextRequestID("traffic")
}

func headersToMap(headers http.Header) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lower := strings.ToLower(key)
		value := strings.Join(headers.Values(key), ", ")
		out[lower] = value
	}
	return out
}

func inboundHeadersToMap(req *http.Request) map[string]any {
	if req == nil {
		return map[string]any{}
	}
	out := headersToMap(req.Header)
	if req.Host != "" {
		out["host"] = req.Host
	}
	if len(req.TransferEncoding) > 0 {
		out["transfer-encoding"] = strings.Join(req.TransferEncoding, ", ")
	}
	if _, ok := out["content-length"]; !ok && req.ContentLength > 0 {
		out["content-length"] = strconv.FormatInt(req.ContentLength, 10)
	}
	if _, ok := out["connection"]; !ok && req.Close {
		out["connection"] = "close"
	}
	if _, ok := out["trailer"]; !ok && len(req.Trailer) > 0 {
		out["trailer"] = headerKeysToValue(req.Trailer)
	}
	return out
}

func headerKeysToValue(headers http.Header) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func headerMeta(value any) http.Header {
	headers := http.Header{}
	switch v := value.(type) {
	case http.Header:
		for key, values := range v {
			headers[key] = append([]string(nil), values...)
		}
	case map[string]string:
		for key, val := range v {
			headers.Set(key, val)
		}
	case map[string][]string:
		for key, values := range v {
			headers[key] = append([]string(nil), values...)
		}
	}
	return headers
}

func isTextContentType(base string, cfg storage.SystemConfig) bool {
	if strings.HasPrefix(base, "text/") {
		return true
	}
	if strings.HasSuffix(base, "+json") || strings.HasSuffix(base, "+xml") {
		return true
	}
	for _, item := range strings.Split(cfg.TrafficCaptureTextTypes, ",") {
		if strings.TrimSpace(strings.ToLower(item)) == base {
			return true
		}
	}
	return false
}

func contentTypeBase(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
}

func stringMeta(meta map[string]any, key, fallback string) string {
	if meta == nil {
		return fallback
	}
	if value, ok := meta[key]; ok && value != nil {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return fallback
}

func boolMeta(meta map[string]any, key string, fallback bool) bool {
	if meta == nil {
		return fallback
	}
	switch value := meta[key].(type) {
	case bool:
		return value
	case string:
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "true" || value == "1" || value == "yes" {
			return true
		}
		if value == "false" || value == "0" || value == "no" {
			return false
		}
	}
	return fallback
}

func formatCaptureTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04:05.000 -07:00")
}

func ReadJSONL(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 32*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, s.Err()
}

func DrainAndRemember(req *http.Request, max int64) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	originalBody := req.Body
	defer originalBody.Close()
	var reader io.Reader = originalBody
	if max > 0 {
		reader = io.LimitReader(originalBody, max+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if max > 0 && int64(len(body)) > max {
		req.Body = http.NoBody
		return nil, ErrRequestBodyTooLarge
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	RememberRequestBody(req, body)
	return body, nil
}
