package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type okRoundTripper struct{}

func (okRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return textResponse(http.StatusOK, "ok", nil), nil
}

func newProxyTestHandler(t *testing.T, node storage.Node) *Handler {
	t.Helper()
	if node.Name == "" {
		node.Name = "node"
	}
	if node.Secret == "" {
		node.Secret = "secret"
	}
	if node.Target == "" {
		node.Target = "https://upstream.example"
	}
	store := newProxyTestStore(t)
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	return New(config.Config{}, store, nil, logging.New("silent", false))
}

func noRedirectClient(rt roundTripFunc) *http.Client {
	return &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func failRoundTripClient(t *testing.T, message string) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Helper()
		t.Fatalf("%s: %s", message, req.URL.String())
		return nil, nil
	})}
}

func decodeJSONMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertSignedRawLink(t *testing.T, h *Handler, got, origin, selfPrefix, raw string) {
	t.Helper()
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("raw link is invalid URL %q: %v", got, err)
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		t.Fatalf("origin is invalid URL %q: %v", origin, err)
	}
	if u.Scheme != originURL.Scheme || u.Host != originURL.Host {
		t.Fatalf("raw link origin = %s://%s, want %s://%s", u.Scheme, u.Host, originURL.Scheme, originURL.Host)
	}
	if wantPath := selfPrefix + "/__raw__"; u.Path != wantPath {
		t.Fatalf("raw link path = %q, want %q", u.Path, wantPath)
	}
	q := u.Query()
	payloadValues := q[rawLinkURLParam]
	if len(payloadValues) != 1 {
		t.Fatalf("raw link %s count = %d, want 1", rawLinkURLParam, len(payloadValues))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payloadValues[0])
	if err != nil {
		t.Fatalf("raw link payload is invalid base64url: %v", err)
	}
	if string(decoded) != raw {
		t.Fatalf("raw link payload = %q, want %q", decoded, raw)
	}
	if len(q[rawLinkExpParam]) != 1 || len(q[rawLinkSigParam]) != 1 {
		t.Fatalf("raw link signature query is incomplete: %q", u.RawQuery)
	}
	req := httptest.NewRequest(http.MethodGet, got, nil)
	gotRaw, trusted := h.signedRawURLFromQuery(req, selfPrefix)
	if !trusted || gotRaw != raw {
		t.Fatalf("signedRawURLFromQuery() = raw %q trusted %v, want %q true", gotRaw, trusted, raw)
	}
	if stripped := stripRawLinkSignatureQuery(req.URL.RawQuery); stripped != "" {
		t.Fatalf("raw link has unexpected non-signature query: %q", stripped)
	}
}

func assertRelativeSignedRawLink(t *testing.T, h *Handler, got, selfPrefix, raw string) {
	t.Helper()
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("raw link is invalid URL %q: %v", got, err)
	}
	if u.Scheme != "" || u.Host != "" {
		t.Fatalf("raw link origin = %s://%s, want relative URL", u.Scheme, u.Host)
	}
	if wantPath := "/__raw__"; u.Path != wantPath {
		t.Fatalf("raw link path = %q, want %q", u.Path, wantPath)
	}
	q := u.Query()
	payloadValues := q[rawLinkURLParam]
	if len(payloadValues) != 1 {
		t.Fatalf("raw link %s count = %d, want 1", rawLinkURLParam, len(payloadValues))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payloadValues[0])
	if err != nil {
		t.Fatalf("raw link payload is invalid base64url: %v", err)
	}
	if string(decoded) != raw {
		t.Fatalf("raw link payload = %q, want %q", decoded, raw)
	}
	if len(q[rawLinkExpParam]) != 1 || len(q[rawLinkSigParam]) != 1 {
		t.Fatalf("raw link signature query is incomplete: %q", u.RawQuery)
	}
	req := httptest.NewRequest(http.MethodGet, got, nil)
	gotRaw, trusted := h.signedRawURLFromQuery(req, selfPrefix)
	if !trusted || gotRaw != raw {
		t.Fatalf("signedRawURLFromQuery() = raw %q trusted %v, want %q true", gotRaw, trusted, raw)
	}
	if stripped := stripRawLinkSignatureQuery(req.URL.RawQuery); stripped != "" {
		t.Fatalf("raw link has unexpected non-signature query: %q", stripped)
	}
}

func newRawServeHTTPHarness(t *testing.T, cfg config.Config, roundTrip func(*http.Request) (*http.Response, error)) (*Handler, *int) {
	t.Helper()
	store := newProxyTestStore(t)
	if err := store.SaveNode(context.Background(), "admin", storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}); err != nil {
		t.Fatal(err)
	}
	rawCalls := 0
	h := New(cfg, store, nil, logging.New("silent", false))
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rawCalls++
		if roundTrip != nil {
			return roundTrip(req)
		}
		return textResponse(http.StatusOK, "unexpected", nil), nil
	})}
	return h, &rawCalls
}

type trackedBody struct {
	reader    *strings.Reader
	readCalls int
	closed    bool
}

func newTrackedBody(value string) *trackedBody {
	return &trackedBody{reader: strings.NewReader(value)}
}

func (b *trackedBody) Read(p []byte) (int, error) {
	b.readCalls++
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func TestDoFetchDoesNotDowngradeHTTPS(t *testing.T) {
	body := newTrackedBody("first")
	schemes := []string{}

	h := &Handler{
		noRedirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			return &http.Response{StatusCode: 530, Header: http.Header{}, Body: body, Request: req}, nil
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.doFetch(context.Background(), h.noRedirectClient, target, http.MethodGet, http.Header{}, nil)
	if err != nil {
		t.Fatalf("doFetch() error = %v", err)
	}
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	if res.Body != body {
		t.Fatal("doFetch() did not return the original response")
	}
	if got := strings.Join(schemes, ","); got != "https" {
		t.Fatalf("schemes = %q, want https", got)
	}
	if body.closed {
		t.Fatal("returned response body was closed too early")
	}
}

func TestSendResponsePreservesContentLengthForPassthrough(t *testing.T) {
	body := []byte("media-body")
	wantLength := fmt.Sprintf("%d", len(body))
	res := bytesResponse(http.StatusPartialContent, body, http.Header{
		"Accept-Ranges":  []string{"bytes"},
		"Content-Length": []string{wantLength},
		"Content-Range":  []string{"bytes 0-9/100"},
		"Content-Type":   []string{"video/mp4"},
	})
	rec := httptest.NewRecorder()

	(&Handler{}).sendResponse(rec, httptest.NewRequest(http.MethodGet, "/video", nil), res)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	if got := rec.Header().Get("Content-Length"); got != wantLength {
		t.Fatalf("Content-Length = %q, want %q", got, wantLength)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 0-9/100" {
		t.Fatalf("Content-Range = %q", got)
	}
	if got := rec.Body.String(); got != string(body) {
		t.Fatalf("body = %q, want %q", got, string(body))
	}
}

func TestSendResponseDropsContentLengthForDecodedBody(t *testing.T) {
	res := bytesResponse(http.StatusOK, []byte("decoded"), http.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Length":   []string{"99"},
		"Content-Type":     []string{"text/plain"},
	})
	res.Uncompressed = true
	rec := httptest.NewRecorder()

	(&Handler{}).sendResponse(rec, httptest.NewRequest(http.MethodGet, "/text", nil), res)

	if got := rec.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
}

func TestSendResponsePreservesContentEncodingForEncodedBody(t *testing.T) {
	body := gzipTestBody(t, "encoded")
	res := bytesResponse(http.StatusOK, body, http.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Length":   []string{fmt.Sprintf("%d", len(body))},
		"Content-Type":     []string{"text/plain"},
	})
	rec := httptest.NewRecorder()

	(&Handler{}).sendResponse(rec, httptest.NewRequest(http.MethodGet, "/text", nil), res)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rec.Header().Get("Content-Length"); got != fmt.Sprintf("%d", len(body)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(body))
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("body was not preserved as encoded bytes")
	}
}

func TestReadProxyRewriteResponseBodyDecodesEncodedBody(t *testing.T) {
	tests := []struct {
		name            string
		contentEncoding string
		body            []byte
	}{
		{
			name:            "gzip",
			contentEncoding: "gzip",
			body:            gzipTestBody(t, "decoded"),
		},
		{
			name:            "brotli",
			contentEncoding: "br",
			body:            brotliTestBody(t, "decoded"),
		},
		{
			name:            "zstd",
			contentEncoding: "zstd",
			body:            zstdTestBody(t, "decoded"),
		},
		{
			name:            "encoding chain",
			contentEncoding: "gzip, br",
			body:            brotliTestBytes(t, gzipTestBody(t, "decoded")),
		},
		{
			name:            "encoding chain with zstd",
			contentEncoding: "gzip, zstd",
			body:            zstdTestBytes(t, gzipTestBody(t, "decoded")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := bytesResponse(http.StatusOK, tt.body, http.Header{
				"Content-Encoding": []string{tt.contentEncoding},
				"Content-Type":     []string{"application/json"},
			})

			body, encodings, err := readProxyRewriteResponseBody(res)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(encodings, ", "); got != tt.contentEncoding {
				t.Fatalf("encodings = %q, want %q", got, tt.contentEncoding)
			}
			if got := string(body); got != "decoded" {
				t.Fatalf("body = %q, want decoded", got)
			}
		})
	}
}

func TestEncodeProxyRewriteResponseBodyRecompressesWithOriginalEncoding(t *testing.T) {
	tests := []struct {
		name            string
		contentEncoding string
	}{
		{name: "gzip", contentEncoding: "gzip"},
		{name: "brotli", contentEncoding: "br"},
		{name: "zstd", contentEncoding: "zstd"},
		{name: "encoding chain", contentEncoding: "gzip, br"},
		{name: "encoding chain with zstd", contentEncoding: "gzip, zstd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Content-Encoding", tt.contentEncoding)
			headers.Set("Content-Length", "999")
			headers.Set("Content-MD5", "stale")
			encodings := responseContentEncodings(tt.contentEncoding)

			encoded, err := encodeProxyRewriteResponseBody([]byte("rewritten"), encodings, headers)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeProxyRewriteBody(encoded, encodings)
			if err != nil {
				t.Fatal(err)
			}

			if got := string(decoded); got != "rewritten" {
				t.Fatalf("decoded body = %q, want rewritten", got)
			}
			if got := headers.Get("Content-Encoding"); got != tt.contentEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, tt.contentEncoding)
			}
			if got := headers.Get("Content-Length"); got != fmt.Sprintf("%d", len(encoded)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(encoded))
			}
			if got := headers.Get("Content-MD5"); got != "" {
				t.Fatalf("Content-MD5 = %q, want empty", got)
			}
		})
	}
}

func gzipTestBody(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func brotliTestBody(t *testing.T, body string) []byte {
	t.Helper()
	return brotliTestBytes(t, []byte(body))
}

func brotliTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdTestBody(t *testing.T, body string) []byte {
	t.Helper()
	return zstdTestBytes(t, []byte(body))
}

func zstdTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBodyCopyUsesSharedBufferSize(t *testing.T) {
	tests := []struct {
		name string
		copy func(*bodyCopyBufferRecorder) error
	}{
		{
			name: "standard response copy",
			copy: func(body *bodyCopyBufferRecorder) error {
				res := &http.Response{Body: body}
				_, err := (&Handler{}).copyResponseBody(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/video", nil), res)
				return err
			},
		},
		{
			name: "resume chunk copy",
			copy: func(body *bodyCopyBufferRecorder) error {
				buf := getBodyCopyBuffer()
				defer putBodyCopyBuffer(buf)
				_, readErr, writeErr := copyStreamResumeChunk(&bodyCopyWriter{writer: io.Discard}, &bodyCopyReader{reader: body}, buf)
				if writeErr != nil {
					return writeErr
				}
				if !errors.Is(readErr, io.EOF) {
					return fmt.Errorf("read error = %v, want EOF", readErr)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &bodyCopyBufferRecorder{}
			if err := tt.copy(body); err != nil {
				t.Fatalf("copy() error = %v", err)
			}
			if body.maxReadLen != bodyCopyBufferSize {
				t.Fatalf("max read buffer = %d, want %d", body.maxReadLen, bodyCopyBufferSize)
			}
			if bodyCopyBufferSize != 256*1024 {
				t.Fatalf("bodyCopyBufferSize = %d, want 256KB", bodyCopyBufferSize)
			}
		})
	}
}

type bodyCopyBufferRecorder struct {
	maxReadLen int
	reads      int
}

func (r *bodyCopyBufferRecorder) Read(p []byte) (int, error) {
	if len(p) > r.maxReadLen {
		r.maxReadLen = len(p)
	}
	if r.reads > 0 {
		return 0, io.EOF
	}
	r.reads++
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}

func (r *bodyCopyBufferRecorder) Close() error {
	return nil
}

func TestFillContentLengthFromContentRange(t *testing.T) {
	headers := http.Header{
		"Content-Range": []string{"bytes 1024-2047/4096"},
	}

	fillContentLengthFromContentRange(headers)

	if got := headers.Get("Content-Length"); got != "1024" {
		t.Fatalf("Content-Length = %q, want 1024", got)
	}
}

type failingReadBody struct {
	err error
}

func (b failingReadBody) Read([]byte) (int, error) {
	return 0, b.err
}

func (b failingReadBody) Close() error {
	return nil
}

type partialFailBody struct {
	data   []byte
	err    error
	done   bool
	closed bool
}

func (b *partialFailBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, b.err
	}
	b.done = true
	n := copy(p, b.data)
	return n, b.err
}

func (b *partialFailBody) Close() error {
	b.closed = true
	return nil
}

type failingWriteResponseWriter struct {
	header http.Header
	status int
	err    error
}

func (w *failingWriteResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *failingWriteResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingWriteResponseWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestStreamResumeValidatorRequiresStrongValidator(t *testing.T) {
	lastModified := "Tue, 09 Jun 2026 10:00:00 GMT"
	laterDate := "Tue, 09 Jun 2026 10:00:01 GMT"
	sameSecondDate := "Tue, 09 Jun 2026 10:00:00 GMT"
	for _, tt := range []struct {
		name        string
		header      http.Header
		wantOK      bool
		wantIfRange string
	}{
		{
			name: "strong etag wins without date",
			header: http.Header{
				"ETag":          []string{`"media-v1"`},
				"Last-Modified": []string{lastModified},
			},
			wantOK:      true,
			wantIfRange: `"media-v1"`,
		},
		{
			name: "weak etag disables date fallback",
			header: http.Header{
				"ETag":          []string{`W/"media-v1"`},
				"Last-Modified": []string{lastModified},
				"Date":          []string{laterDate},
			},
		},
		{
			name: "last modified needs date",
			header: http.Header{
				"Last-Modified": []string{lastModified},
			},
		},
		{
			name: "last modified same second is not strong enough",
			header: http.Header{
				"Last-Modified": []string{lastModified},
				"Date":          []string{sameSecondDate},
			},
		},
		{
			name: "invalid last modified is rejected",
			header: http.Header{
				"Last-Modified": []string{"not-a-date"},
				"Date":          []string{laterDate},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			validator, ok := newStreamResumeValidator(tt.header)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v; validator=%+v", ok, tt.wantOK, validator)
			}
			if ok && validator.ifRange != tt.wantIfRange {
				t.Fatalf("If-Range = %q, want %q", validator.ifRange, tt.wantIfRange)
			}
		})
	}
}

func TestSendResponseResumesInterruptedPlaybackStream(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-10")
	upstreamErr := errors.New("upstream reset")
	resumeRanges := []string{}
	resumeIfRanges := []string{}
	body := &partialFailBody{data: []byte("hello "), err: upstreamErr}
	client := &http.Client{Transport: roundTripFunc(func(resumeReq *http.Request) (*http.Response, error) {
		resumeRanges = append(resumeRanges, resumeReq.Header.Get("Range"))
		resumeIfRanges = append(resumeIfRanges, resumeReq.Header.Get("If-Range"))
		out := bytesResponse(http.StatusPartialContent, []byte("world"), http.Header{
			"Content-Length": []string{"5"},
			"Content-Range":  []string{"bytes 6-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		})
		out.Request = resumeReq
		return out, nil
	})}
	upstreamReq := httptest.NewRequest(http.MethodGet, "https://cdn.example/video/original.mkv", nil)
	upstreamReq.Header.Set("Range", "bytes=0-10")
	res := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		ContentLength: 11,
		Header: http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"11"},
			"Content-Range":  []string{"bytes 0-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		},
		Body:    body,
		Request: upstreamReq,
	}
	h := &Handler{log: logging.New("silent", false), targetAttemptTimeout: time.Second}
	wrappedRes, err := h.runTargetAttempt(ctx, func(attemptCtx context.Context) (*http.Response, error) {
		res.Request = res.Request.WithContext(attemptCtx)
		attachUpstreamClient(res, client)
		markStreamResumeCandidate(res, "playback")
		startTargetAttemptTimer(attemptCtx)
		return res, nil
	})
	if err != nil {
		t.Fatalf("runTargetAttempt() error = %v", err)
	}
	res = wrappedRes
	if _, ok := h.streamResumePlan(req, res); !ok {
		validator, hasValidator := newStreamResumeValidator(res.Header)
		t.Fatalf("streamResumePlan disabled: source=%q client=%v media=%v accepts=%v validator=%v hasValidator=%v range=%q contentRange=%q", streamResumeSource(res), upstreamClientForResponse(res), streamResumeResponseLooksLikeMedia(res), streamResumeAcceptsBytes(res.Header), validator, hasValidator, res.Request.Header.Get("Range"), res.Header.Get("Content-Range"))
	}
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	if got := rec.Body.String(); got != "hello world" {
		t.Fatalf("body = %q, want hello world; ranges=%v ifRanges=%v fields=%v", got, resumeRanges, resumeIfRanges, AccessLogFields(ctx))
	}
	if !body.closed {
		t.Fatal("original response body was not closed after resume")
	}
	if got := rec.Header().Get("Content-Length"); got != "11" {
		t.Fatalf("Content-Length = %q, want 11", got)
	}
	if got := strings.Join(resumeRanges, ","); got != "bytes=6-10" {
		t.Fatalf("resume ranges = %q, want bytes=6-10", got)
	}
	if got := strings.Join(resumeIfRanges, ","); got != `"media-v1"` {
		t.Fatalf("resume If-Range = %q, want media-v1", got)
	}
	fields := AccessLogFields(ctx)
	if got := fields["streamResumeAttempts"]; got != 1 {
		t.Fatalf("streamResumeAttempts = %v, want 1", got)
	}
	if got := fields["streamResumeFrom"]; got != int64(6) {
		t.Fatalf("streamResumeFrom = %v, want 6", got)
	}
	if got := fields["streamResumeBytes"]; got != int64(5) {
		t.Fatalf("streamResumeBytes = %v, want 5", got)
	}
	if _, ok := fields["streamResumeError"]; ok {
		t.Fatalf("streamResumeError was set on successful resume: %v", fields["streamResumeError"])
	}
}

func TestSendResponseOmitsStreamResumeErrorBeforeResumeAttempt(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-10")
	upstreamReq := httptest.NewRequest(http.MethodGet, "https://cdn.example/video/original.mkv", nil)
	upstreamReq.Header.Set("Range", "bytes=0-10")
	res := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		ContentLength: 11,
		Header: http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"11"},
			"Content-Range":  []string{"bytes 0-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		},
		Body:    io.NopCloser(strings.NewReader("hello world")),
		Request: upstreamReq,
	}
	attachUpstreamClient(res, failRoundTripClient(t, "resume request should not be attempted"))
	markStreamResumeCandidate(res, "playback")
	writer := &failingWriteResponseWriter{err: errors.New("broken pipe")}

	(&Handler{log: logging.New("silent", false)}).sendResponse(writer, req, res)

	fields := AccessLogFields(ctx)
	if got := fields["streamResumeAttempts"]; got != 0 {
		t.Fatalf("streamResumeAttempts = %v, want 0", got)
	}
	if _, ok := fields["streamResumeError"]; ok {
		t.Fatalf("streamResumeError was set before a resume attempt: %v", fields["streamResumeError"])
	}
}

func TestSendResponseLogsStreamResumeErrorForResumeValidationFailure(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-10")
	upstreamErr := errors.New("upstream reset")
	client := &http.Client{Transport: roundTripFunc(func(resumeReq *http.Request) (*http.Response, error) {
		out := bytesResponse(http.StatusPartialContent, []byte("world"), http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"5"},
			"Content-Range":  []string{"bytes 7-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		})
		out.Request = resumeReq
		return out, nil
	})}
	upstreamReq := httptest.NewRequest(http.MethodGet, "https://cdn.example/video/original.mkv", nil)
	upstreamReq.Header.Set("Range", "bytes=0-10")
	res := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		ContentLength: 11,
		Header: http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"11"},
			"Content-Range":  []string{"bytes 0-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		},
		Body:    &partialFailBody{data: []byte("hello "), err: upstreamErr},
		Request: upstreamReq,
	}
	attachUpstreamClient(res, client)
	markStreamResumeCandidate(res, "playback")
	rec := httptest.NewRecorder()

	(&Handler{log: logging.New("silent", false)}).sendResponse(rec, req, res)

	fields := AccessLogFields(ctx)
	if got := fields["streamResumeAttempts"]; got != 1 {
		t.Fatalf("streamResumeAttempts = %v, want 1", got)
	}
	if got := fields["streamResumeFrom"]; got != int64(6) {
		t.Fatalf("streamResumeFrom = %v, want 6", got)
	}
	if got, ok := fields["streamResumeError"].(string); !ok || got == "" {
		t.Fatalf("streamResumeError = %v, want non-empty string", fields["streamResumeError"])
	}
}

func TestSendResponseLogsBodyCopyReadError(t *testing.T) {
	log := logging.New("debug", false)
	h := &Handler{log: log}
	wantErr := errors.New("upstream stalled")
	res := &http.Response{
		StatusCode: http.StatusPartialContent,
		Status:     "206 Partial Content",
		Header: http.Header{
			"Content-Range": []string{"bytes 1024-2047/4096"},
		},
		Body: failingReadBody{err: wantErr},
	}
	ctx := WithAccessLogFields(context.Background())
	ctx = context.WithValue(ctx, "requestID", "req-copy")
	ctx = requestlog.WithAccessLogState(ctx)
	requestlog.SetRequestURI(ctx, "/node/<secret>/emby/videos/1/original.mkv")
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=1024-")
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	line := entries[0].Line
	for _, want := range []string{"event=bodyCopyInterrupted", "id=req-copy", "method=GET", "uri=\"/node/<secret>/emby/videos/1/original.mkv\"", "range=\"bytes=1024-\"", "firstReadStatus=none", "side=upstream-read", "error=\"upstream stalled\""} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line = %q, want %q", line, want)
		}
	}
	if got := AccessLogFields(ctx)["firstReadStatus"]; got != "none" {
		t.Fatalf("firstReadStatus access log field = %v, want none", got)
	}
}

func TestSendResponseStoresFirstReadDurationForAccessLog(t *testing.T) {
	h := &Handler{log: logging.New("silent", false)}
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	res := &http.Response{
		StatusCode: http.StatusPartialContent,
		Status:     "206 Partial Content",
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("hello")),
	}
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	firstReadMs, ok := AccessLogFields(ctx)["firstReadMs"].(int64)
	if !ok {
		t.Fatalf("firstReadMs access log field = %T, want int64", AccessLogFields(ctx)["firstReadMs"])
	}
	if firstReadMs < 0 {
		t.Fatalf("firstReadMs = %d, want non-negative", firstReadMs)
	}
}

func TestBodyCopyIssueSidePrefersContextCancellation(t *testing.T) {
	side := bodyCopyIssueSide(
		context.Canceled,
		context.Canceled,
		&bodyCopyReader{lastErr: context.Canceled},
		&bodyCopyWriter{},
	)

	if side != "context" {
		t.Fatalf("side = %q, want context", side)
	}
}

func TestSendResponseOmitsUnredactedURIWhenRequestLogURIIsMissing(t *testing.T) {
	log := logging.New("debug", false)
	h := &Handler{log: log}
	res := &http.Response{
		StatusCode: http.StatusPartialContent,
		Status:     "206 Partial Content",
		Header:     http.Header{},
		Body:       failingReadBody{err: errors.New("upstream stalled")},
	}
	req := httptest.NewRequest(http.MethodGet, "/node/raw-secret/emby/videos/1/original.mkv?api_key=secret-token", nil)
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	line := entries[0].Line
	if strings.Contains(line, "raw-secret") || strings.Contains(line, "secret-token") || strings.Contains(line, "uri=") {
		t.Fatalf("log line leaked or included unredacted uri: %q", line)
	}
}

func TestServeHTTPMarksAccessLogURIWithRedactedSecret(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	if err := store.SaveNode(ctx, "admin", storage.Node{Name: "node", Secret: "raw-secret", Target: upstream.URL}); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	reqCtx := requestlog.WithAccessLogState(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/raw-secret/emby/System/Info?api_key=token", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	got, ok := requestlog.RequestURI(reqCtx)
	if !ok {
		t.Fatal("request URI was not marked for access log")
	}
	if strings.Contains(got, "raw-secret") || strings.Contains(got, "token") {
		t.Fatalf("redacted URI leaked sensitive data: %q", got)
	}
	if got != "/node/<secret>/emby/System/Info" {
		t.Fatalf("redacted URI = %q", got)
	}
}

func TestDoFetchDoesNotRetryHTTPAfterHTTPSError(t *testing.T) {
	schemes := []string{}
	wantErr := errors.New("upstream timeout")
	h := &Handler{
		noRedirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			return nil, wantErr
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.doFetch(context.Background(), h.noRedirectClient, target, http.MethodGet, http.Header{}, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("doFetch() error = %v, want %v", err, wantErr)
	}
	if got := strings.Join(schemes, ","); got != "https" {
		t.Fatalf("schemes = %q, want https", got)
	}
}

func TestHandleOneTargetClosesDiscardedGeneral403ResponsesWithoutReadingBodies(t *testing.T) {
	store := newProxyTestStore(t)
	bodies := []*trackedBody{
		newTrackedBody("first forbidden"),
		newTrackedBody("second forbidden"),
		newTrackedBody("third forbidden"),
		newTrackedBody("fourth forbidden"),
		newTrackedBody("success"),
	}
	calls := 0
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls >= len(bodies) {
			return nil, fmt.Errorf("unexpected upstream call %d", calls+1)
		}
		body := bodies[calls]
		status := http.StatusForbidden
		if calls == len(bodies)-1 {
			status = http.StatusOK
		}
		calls++
		return &http.Response{
			StatusCode:    status,
			Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Header:        http.Header{"Content-Type": []string{"text/plain"}},
			Body:          body,
			ContentLength: int64(body.reader.Len()),
			Request:       req,
		}, nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/Users/AuthenticateByName", nil)
	parsed := parsedRoute{URL: req.URL, Name: "node", Path: "/Users/AuthenticateByName"}
	node := storage.Node{Name: "node", Target: "https://upstream.example"}

	res, err := h.handleOneTarget(context.Background(), req, node, parsed, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleOneTarget() error = %v", err)
	}
	defer res.Body.Close()
	if calls != len(bodies) {
		t.Fatalf("upstream calls = %d, want %d", calls, len(bodies))
	}
	for i, body := range bodies[:len(bodies)-1] {
		if !body.closed {
			t.Fatalf("discarded body %d was not closed", i+1)
		}
		if body.readCalls != 0 {
			t.Fatalf("discarded body %d read calls = %d, want 0", i+1, body.readCalls)
		}
	}
	finalBody := bodies[len(bodies)-1]
	if finalBody.closed {
		t.Fatal("final response body was closed too early")
	}
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll(final response) error = %v", err)
	}
	if string(got) != "success" {
		t.Fatalf("final response body = %q, want success", got)
	}
}

func TestNewProxyHTTPClientUsesTransportTimeouts(t *testing.T) {
	client := newProxyHTTPClient(false)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext is nil")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("ResponseHeaderTimeout was not configured")
	}
	if !transport.DisableCompression {
		t.Fatal("DisableCompression should preserve client Accept-Encoding exactly")
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("TLSHandshakeTimeout was not configured")
	}
	if client.CheckRedirect == nil {
		t.Fatal("no-redirect client should disable automatic redirects")
	}

	defaultFollowClient := newProxyHTTPClient(true)
	if defaultFollowClient.CheckRedirect != nil {
		t.Fatal("default follow client should use default redirect behavior")
	}
}

func TestNewHandlerSeparatesPlaybackConnectionPools(t *testing.T) {
	h := New(config.Config{}, nil, nil, logging.New("silent", false))
	if h.playbackActionClient.Transport == nil || h.playbackStreamClient.Transport == nil || h.playbackStreamProbeClient.Transport == nil {
		t.Fatal("playback clients should have transports")
	}
	if h.playbackActionClient.Transport == h.playbackStreamClient.Transport {
		t.Fatal("playback action and stream clients should use separate transports")
	}
	if h.playbackStreamClient.Transport != h.playbackStreamProbeClient.Transport {
		t.Fatal("playback stream and probe clients should share one transport")
	}
	if h.playbackStreamProbeClient.CheckRedirect == nil {
		t.Fatal("playback stream probe client should disable automatic redirects")
	}
	if h.playbackActionClient.CheckRedirect != nil || h.playbackStreamClient.CheckRedirect != nil {
		t.Fatal("playback action and stream clients should follow redirects")
	}
}

func TestDoFetchStoresUpstreamPoolAccessLogField(t *testing.T) {
	okClient := func() *http.Client {
		return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, "ok", nil), nil
		})}
	}
	h := &Handler{
		noRedirectClient:          okClient(),
		defaultFollowClient:       okClient(),
		playbackActionClient:      okClient(),
		playbackStreamClient:      okClient(),
		playbackStreamProbeClient: okClient(),
		imageFollowClient:         okClient(),
		rawDirectClient:           &http.Client{Transport: okRoundTripper{}},
	}
	protectedRawClient := &http.Client{Transport: h.rawDirectClient.Transport}
	undefinedClient := okClient()
	target, err := url.Parse("https://upstream.example/emby/System/Ping")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		client *http.Client
		want   string
	}{
		{name: "no redirect", client: h.noRedirectClient, want: upstreamPoolNoRedirect},
		{name: "default follow", client: h.defaultFollowClient, want: upstreamPoolDefaultFollow},
		{name: "playback action", client: h.playbackActionClient, want: upstreamPoolPlaybackAction},
		{name: "playback stream", client: h.playbackStreamClient, want: upstreamPoolPlaybackStream},
		{name: "playback stream probe", client: h.playbackStreamProbeClient, want: upstreamPoolPlaybackStreamProbe},
		{name: "image follow", client: h.imageFollowClient, want: upstreamPoolImageFollow},
		{name: "raw direct", client: h.rawDirectClient, want: upstreamPoolRawDirect},
		{name: "protected raw direct", client: protectedRawClient, want: upstreamPoolRawDirect},
		{name: "undefined", client: undefinedClient, want: upstreamPoolUndefined},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			res, err := h.doFetch(ctx, tt.client, target, http.MethodGet, http.Header{}, nil)
			if err != nil {
				t.Fatalf("doFetch() error = %v", err)
			}
			_ = res.Body.Close()
			if got := AccessLogFields(ctx)[accessLogFieldUpstreamPool]; got != tt.want {
				t.Fatalf("upstreamPool = %v, want %s", got, tt.want)
			}
		})
	}
}

func TestHandleMediaProxyChoosesUpstreamClient(t *testing.T) {
	tests := []struct {
		name        string
		requestURI  string
		targetURL   string
		routePath   string
		node        storage.Node
		isPlayback  bool
		isImage     bool
		wantClient  string
		wantStatus  int
		newResponse func() *http.Response
	}{
		{
			name:       "stream playback",
			requestURI: "https://proxy.example/node/emby/Videos/1/stream.mp4",
			targetURL:  "https://upstream.example/emby/Videos/1/stream.mp4",
			routePath:  "/emby/Videos/1/stream.mp4",
			node:       storage.Node{Name: "node", Target: "https://upstream.example"},
			isPlayback: true,
			wantClient: upstreamPoolPlaybackStream,
			wantStatus: http.StatusPartialContent,
			newResponse: func() *http.Response {
				return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
					"Accept-Ranges": []string{"bytes"},
					"Content-Range": []string{"bytes 0-4/5"},
					"Content-Type":  []string{"video/mp4"},
				})
			},
		},
		{
			name:       "direct external non-stream playback action",
			requestURI: "https://proxy.example/node/emby/Sessions/Playing",
			targetURL:  "https://upstream.example/emby/Sessions/Playing",
			routePath:  "/emby/Sessions/Playing",
			node:       storage.Node{Name: "node", Target: "https://upstream.example", DirectExternal: true},
			isPlayback: true,
			wantClient: upstreamPoolPlaybackAction,
			wantStatus: http.StatusOK,
			newResponse: func() *http.Response {
				return textResponse(http.StatusOK, "{}", http.Header{
					"Content-Type": []string{"application/json"},
				})
			},
		},
		{
			name:       "image",
			requestURI: "https://proxy.example/node/emby/Items/1/Images/Primary",
			targetURL:  "https://upstream.example/emby/Items/1/Images/Primary",
			routePath:  "/emby/Items/1/Images/Primary",
			node:       storage.Node{Name: "node", Target: "https://upstream.example"},
			isImage:    true,
			wantClient: upstreamPoolImageFollow,
			wantStatus: http.StatusOK,
			newResponse: func() *http.Response {
				return bytesResponse(http.StatusOK, []byte("image"), http.Header{
					"Content-Type": []string{"image/jpeg"},
				})
			},
		},
		{
			name:       "direct external image path that looks streaming",
			requestURI: "https://proxy.example/node/emby/Items/1/Images/Primary.mp4",
			targetURL:  "https://upstream.example/emby/Items/1/Images/Primary.mp4",
			routePath:  "/emby/Items/1/Images/Primary.mp4",
			node:       storage.Node{Name: "node", Target: "https://upstream.example", DirectExternal: true},
			isPlayback: true,
			isImage:    true,
			wantClient: upstreamPoolImageFollow,
			wantStatus: http.StatusOK,
			newResponse: func() *http.Response {
				return bytesResponse(http.StatusOK, []byte("image"), http.Header{
					"Content-Type": []string{"image/jpeg"},
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			calls := map[string]int{}
			successClient := func(name string) *http.Client {
				return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls[name]++
					return tt.newResponse(), nil
				})}
			}
			h := &Handler{
				noRedirectClient:          failRoundTripClient(t, "no-redirect client should not handle "+tt.name),
				defaultFollowClient:       failRoundTripClient(t, "default follow client should not handle "+tt.name),
				playbackActionClient:      failRoundTripClient(t, "playback action client should not handle "+tt.name),
				playbackStreamClient:      failRoundTripClient(t, "playback stream client should not handle "+tt.name),
				playbackStreamProbeClient: failRoundTripClient(t, "playback stream probe client should not handle "+tt.name),
				imageFollowClient:         failRoundTripClient(t, "image follow client should not handle "+tt.name),
			}
			switch tt.wantClient {
			case upstreamPoolPlaybackAction:
				h.playbackActionClient = successClient(tt.wantClient)
			case upstreamPoolPlaybackStream:
				h.playbackStreamClient = successClient(tt.wantClient)
			case upstreamPoolImageFollow:
				h.imageFollowClient = successClient(tt.wantClient)
			default:
				t.Fatalf("unsupported expected client %q", tt.wantClient)
			}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil).WithContext(ctx)
			targetURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatal(err)
			}

			res, err := h.handleMediaProxy(ctx, req, tt.node, parsedRoute{Name: tt.node.Name, Path: tt.routePath}, targetURL, nil, config.ProxyEnv{}, tt.isPlayback, tt.isImage, false, "", "127.0.0.1")
			if err != nil {
				t.Fatalf("handleMediaProxy() error = %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if calls[tt.wantClient] != 1 {
				t.Fatalf("%s calls = %d, want 1", tt.wantClient, calls[tt.wantClient])
			}
		})
	}
}

func TestHandleMediaProxyAddsHillsIdentityToMediaAndImageTargets(t *testing.T) {
	tests := []struct {
		name              string
		requestURI        string
		targetURL         string
		routePath         string
		isPlayback        bool
		isImage           bool
		clientName        string
		status            int
		headers           http.Header
		body              []byte
		wantQueryIdentity bool
	}{
		{
			name:       "media stream",
			requestURI: "https://proxy.example/node/emby/Videos/1/stream.mp4?tag=v1",
			targetURL:  "https://upstream.example/emby/Videos/1/stream.mp4?tag=v1&X_Emby_Device_Id=source-device",
			routePath:  "/emby/Videos/1/stream.mp4",
			isPlayback: true,
			clientName: upstreamPoolPlaybackStream,
			status:     http.StatusPartialContent,
			headers: http.Header{
				"Accept-Ranges": []string{"bytes"},
				"Content-Range": []string{"bytes 0-4/5"},
				"Content-Type":  []string{"video/mp4"},
			},
			body: []byte("video"),
		},
		{
			name:       "image",
			requestURI: "https://proxy.example/node/emby/Items/1/Images/Primary?tag=v1",
			targetURL:  "https://upstream.example/emby/Items/1/Images/Primary?tag=v1&X-Emby-Language=en-us",
			routePath:  "/emby/Items/1/Images/Primary",
			isImage:    true,
			clientName: upstreamPoolImageFollow,
			status:     http.StatusOK,
			headers: http.Header{
				"Content-Type": []string{"image/jpeg"},
			},
			body: []byte("image"),
		},
		{
			name:              "playback info",
			requestURI:        "https://proxy.example/node/emby/Items/1/PlaybackInfo?tag=v1",
			targetURL:         "https://upstream.example/emby/Items/1/PlaybackInfo?tag=v1&X_Emby_Device_Id=source-device",
			routePath:         "/emby/Items/1/PlaybackInfo",
			isPlayback:        true,
			clientName:        upstreamPoolPlaybackAction,
			status:            http.StatusOK,
			headers:           http.Header{"Content-Type": []string{"application/json"}},
			body:              []byte(`{"MediaSources":[]}`),
			wantQueryIdentity: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			ids := identity.NewManager(nil)
			var upstreamReq *http.Request
			successClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				upstreamReq = req.Clone(req.Context())
				upstreamReq.Header = cloneHeader(req.Header)
				return bytesResponse(tt.status, tt.body, tt.headers), nil
			})}
			h := &Handler{
				ids:                  ids,
				log:                  logging.New("silent", false),
				playbackActionClient: failRoundTripClient(t, "playback action client should not handle "+tt.name),
				playbackStreamClient: failRoundTripClient(t, "playback stream client should not handle "+tt.name),
				imageFollowClient:    failRoundTripClient(t, "image follow client should not handle "+tt.name),
			}
			switch tt.clientName {
			case upstreamPoolPlaybackAction:
				h.playbackActionClient = successClient
			case upstreamPoolPlaybackStream:
				h.playbackStreamClient = successClient
			case upstreamPoolImageFollow:
				h.imageFollowClient = successClient
			default:
				t.Fatalf("unsupported client %q", tt.clientName)
			}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil).WithContext(ctx)
			req.Header.Set("X-Emby-Token", "header-token")
			targetURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatal(err)
			}
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "hills_android"}

			res, err := h.handleMediaProxy(ctx, req, node, parsedRoute{Name: "node", Path: tt.routePath}, targetURL, nil, config.ProxyEnv{}, tt.isPlayback, tt.isImage, false, "", "127.0.0.1")
			if err != nil {
				t.Fatalf("handleMediaProxy() error = %v", err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()

			if upstreamReq == nil {
				t.Fatal("upstream request was not sent")
			}
			assertHillsOutboundHeaderIdentityApplied(t, ids, upstreamReq, "hills_android", "header-token")
			if tt.wantQueryIdentity {
				assertHillsOutboundQueryIdentityApplied(t, ids, upstreamReq, "hills_android", "header-token")
			} else {
				assertHillsIdentityQueryAbsent(t, upstreamReq)
			}
			if got := upstreamReq.URL.Query().Get("tag"); got != "v1" {
				t.Fatalf("tag = %q, want v1", got)
			}
		})
	}
}

func TestHandleNodeRoutesDirectExternalPlaybackActionToPlaybackActionClient(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	actionCalls := 0
	h := newProxyTestHandler(t, storage.Node{DirectExternal: true})
	h.noRedirectClient = failRoundTripClient(t, "general no-redirect client should not handle DirectExternal playback action")
	h.defaultFollowClient = failRoundTripClient(t, "default follow client should not handle DirectExternal playback action")
	h.playbackStreamProbeClient = failRoundTripClient(t, "playback stream probe client should not handle DirectExternal playback action")
	h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not handle DirectExternal playback action")
	h.imageFollowClient = failRoundTripClient(t, "image follow client should not handle DirectExternal playback action")
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		if req.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", req.Method)
		}
		if req.URL.String() != "https://upstream.example/emby/Sessions/Playing/Progress?reqformat=json" {
			t.Fatalf("upstream request URL = %q", req.URL.String())
		}
		return textResponse(http.StatusNoContent, "", nil), nil
	})}

	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret/emby/Sessions/Playing/Progress?reqformat=json", nil).WithContext(ctx)
	res, err := h.handleNode(ctx, req, storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", DirectExternal: true}, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/Sessions/Playing/Progress"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_ = res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusNoContent)
	}
	if actionCalls != 1 {
		t.Fatalf("playback action upstream calls = %d, want 1", actionCalls)
	}
	if got := AccessLogFields(ctx)[accessLogFieldUpstreamPool]; got != upstreamPoolPlaybackAction {
		t.Fatalf("upstreamPool = %v, want %s", got, upstreamPoolPlaybackAction)
	}
}

func TestIsPlaybackStreamRequestClassifiesPlaybackTraffic(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		range_ string
		want   bool
	}{
		{name: "progress", method: http.MethodPost, path: "/emby/Sessions/Playing/Progress"},
		{name: "playback info", method: http.MethodGet, path: "/emby/Items/1/PlaybackInfo"},
		{name: "bare playback info", method: http.MethodGet, path: "/Items/1/PlaybackInfo"},
		{name: "additional parts", method: http.MethodGet, path: "/emby/Videos/1/AdditionalParts"},
		{name: "bare additional parts", method: http.MethodGet, path: "/Videos/1/AdditionalParts"},
		{name: "original media", method: http.MethodGet, path: "/emby/Videos/1/original.mkv", want: true},
		{name: "bare original media", method: http.MethodGet, path: "/Videos/1/original.mkv", want: true},
		{name: "stream endpoint", method: http.MethodGet, path: "/emby/Videos/1/stream", want: true},
		{name: "bare stream endpoint", method: http.MethodGet, path: "/Videos/1/stream", want: true},
		{name: "dynamic hls", method: http.MethodGet, path: "/emby/Videos/1/hls1/main/0.ts", want: true},
		{name: "universal audio", method: http.MethodGet, path: "/emby/Audio/1/universal", want: true},
		{name: "ranged video path", method: http.MethodGet, path: "/emby/Videos/1/file", range_: "bytes=0-", want: true},
		{name: "item download", method: http.MethodGet, path: "/emby/Items/1/Download", want: true},
		{name: "bare smartstrm", method: http.MethodGet, path: "/smartstrm", want: true},
		{name: "bare strm stream special", method: http.MethodGet, path: "/Videos/1/stream.strm", want: true},
		{name: "media post", method: http.MethodPost, path: "/emby/Videos/1/original.mkv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://proxy.example"+tt.path, nil)
			if tt.range_ != "" {
				req.Header.Set("Range", tt.range_)
			}
			targetURL, err := url.Parse("https://upstream.example" + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := isPlaybackStreamRequest(req, targetURL); got != tt.want {
				t.Fatalf("isPlaybackStreamRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleMediaProxyUsesImageClientForImageRetries(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	imageCalls := 0
	h := &Handler{
		noRedirectClient:     failRoundTripClient(t, "no-redirect client should not handle image retry"),
		defaultFollowClient:  failRoundTripClient(t, "default follow client should not handle image retry"),
		playbackStreamClient: failRoundTripClient(t, "playback stream client should not handle image retry"),
		imageFollowClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			imageCalls++
			if imageCalls == 1 {
				return textResponse(http.StatusForbidden, "forbidden", nil), nil
			}
			return bytesResponse(http.StatusOK, []byte("image"), http.Header{
				"Content-Type": []string{"image/jpeg"},
			}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary", nil).WithContext(ctx)
	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, targetURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	_ = res.Body.Close()
	if imageCalls != 2 {
		t.Fatalf("image upstream calls = %d, want 2", imageCalls)
	}
}

func TestDialWebSocketTimesOutWaitingForUpgradeResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-stop
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	target, err := url.Parse("http://" + ln.Addr().String() + "/emby/socket")
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, conn, _, err := (&Handler{}).dialWebSocket(ctx, target, http.Header{})
		if conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("dialWebSocket() error = nil, want timeout")
		}
	case <-time.After(750 * time.Millisecond):
		close(stop)
		_ = ln.Close()
		<-done
		t.Fatal("dialWebSocket() did not time out waiting for upgrade response")
	}
	close(stop)
	_ = ln.Close()
	<-done
}

func TestRawHTTPClientUsesProtectedDirectDialer(t *testing.T) {
	client := newRawHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("raw client should not use environment proxies")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("raw client dialer allowed loopback address")
	}
}

func TestServeHTTPRejectsOversizedRequestBody(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{Name: "node", Secret: "secret"})
	h.cfg.Defaults.MaxRetryBodyBytes = 4

	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret/emby/System/Ping", strings.NewReader("12345"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestReadProxyRewriteBodyRejectsOversizedBody(t *testing.T) {
	_, err := readProxyRewriteBody(io.LimitReader(repeatingReader{}, proxyRewriteBodyMaxBytes+1))
	if !errors.Is(err, errProxyRewriteBodyTooLarge) {
		t.Fatalf("readProxyRewriteBody() error = %v, want %v", err, errProxyRewriteBodyTooLarge)
	}
}

func TestHandleNodeHidesTargetErrorDetails(t *testing.T) {
	h := &Handler{
		log:          logging.New("silent", false),
		lineBan:      newTTLMap(),
		activeTarget: map[string]string{},
	}
	req := httptest.NewRequest(http.MethodGet, "/node/emby/System/Info", nil)
	node := storage.Node{Name: "node", Target: "http://[::1"}
	parsed := parsedRoute{Name: "node", Path: "/emby/System/Info"}

	res, err := h.handleNode(context.Background(), req, node, parsed, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "::1") || strings.Contains(strings.ToLower(string(body)), "missing") {
		t.Fatalf("response leaked target error details: %q", body)
	}
	if strings.TrimSpace(string(body)) != "Bad Gateway" {
		t.Fatalf("body = %q, want Bad Gateway", body)
	}
}

func TestHandleNodeStoresTargetDurationForAccessLog(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/System/Ping", nil).WithContext(ctx)
	res, err := h.handleNode(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	if _, ok := AccessLogFields(ctx)["responseReadyMs"].(int64); !ok {
		t.Fatalf("responseReadyMs access log field = %T, want int64", AccessLogFields(ctx)["responseReadyMs"])
	}
}

func TestHandleNodeFailsOverAfterPerTargetTimeout(t *testing.T) {
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.targetAttemptTimeout = 25 * time.Millisecond
	var hosts []string
	var hostsMu sync.Mutex
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hostsMu.Lock()
		hosts = append(hosts, req.URL.Host)
		hostsMu.Unlock()
		if req.URL.Host != "good.example" {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}

	node := storage.Node{
		Name:   "node",
		Target: "https://bad-one.example\nhttps://bad-two.example\nhttps://good.example",
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/System/Ping", nil)
	res, err := h.handleNode(context.Background(), req, node, parsedRoute{Name: "node", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	hostsMu.Lock()
	gotHosts := strings.Join(hosts, ",")
	hostsMu.Unlock()
	if want := "bad-one.example,bad-two.example,good.example"; gotHosts != want {
		t.Fatalf("attempted hosts = %q, want %q", gotHosts, want)
	}
	if got := h.getActiveTarget("admin:node", storage.SplitTargets(node.Target)); got != "https://good.example" {
		t.Fatalf("active target = %q, want good target", got)
	}
}

func TestHandleNodeDoesNotBanOrContinueAfterClientCancellation(t *testing.T) {
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.targetAttemptTimeout = time.Second
	var hosts []string
	var hostsMu sync.Mutex
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hostsMu.Lock()
		hosts = append(hosts, req.URL.Host)
		hostsMu.Unlock()
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(25*time.Millisecond, cancel)
	node := storage.Node{Name: "node", Target: "https://first.example\nhttps://second.example"}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/System/Ping", nil).WithContext(ctx)
	res, err := h.handleNode(ctx, req, node, parsedRoute{Name: "node", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if res != nil {
		defer res.Body.Close()
		t.Fatalf("response status = %d, want nil response", res.StatusCode)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("handleNode() error = %v, want context canceled", err)
	}

	hostsMu.Lock()
	gotHosts := strings.Join(hosts, ",")
	hostsMu.Unlock()
	if gotHosts != "first.example" {
		t.Fatalf("attempted hosts = %q, want only first target", gotHosts)
	}
	for _, target := range storage.SplitTargets(node.Target) {
		if _, banned := h.lineBan.Get("admin:node|" + target); banned {
			t.Fatalf("target %q was banned after client cancellation", target)
		}
	}
}

func TestRunTargetAttemptKeepsSuccessfulResponseAliveUntilBodyClose(t *testing.T) {
	h := &Handler{targetAttemptTimeout: 25 * time.Millisecond}
	var attemptCtx context.Context
	res, err := h.runTargetAttempt(context.Background(), func(ctx context.Context) (*http.Response, error) {
		attemptCtx = ctx
		startTargetAttemptTimer(ctx)
		return bytesResponse(http.StatusOK, []byte("ok"), nil), nil
	})
	if err != nil {
		t.Fatalf("runTargetAttempt() error = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case <-attemptCtx.Done():
		t.Fatalf("successful attempt context ended before body close: %v", context.Cause(attemptCtx))
	default:
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-attemptCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("attempt context stayed alive after body close")
	}
}

func TestRunTargetAttemptDoesNotCountLocalWorkAgainstUpstreamTimeout(t *testing.T) {
	h := &Handler{targetAttemptTimeout: 25 * time.Millisecond}
	res, err := h.runTargetAttempt(context.Background(), func(context.Context) (*http.Response, error) {
		time.Sleep(50 * time.Millisecond)
		return bytesResponse(http.StatusOK, []byte("ok"), nil), nil
	})
	if err != nil {
		t.Fatalf("runTargetAttempt() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

func TestTrafficCaptureKeepsTargetAttemptsOffSuccessfulErrorMeta(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://bad.example/emby\nhttps://upstream.example/emby",
	}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "bad.example" {
			return nil, errors.New("connect: connection refused")
		}
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Ping", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	meta, ok := records[0].Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", records[0].Meta)
	}
	if _, ok := meta["errorClass"]; ok {
		t.Fatalf("successful record should not have final errorClass: %#v", meta)
	}
	attempts, ok := meta["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("attempts = %#v, want one failed attempt", meta["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("attempt = %T, want map", attempts[0])
	}
	if got := attempt["errorClass"]; got != "connection-refused" {
		t.Fatalf("attempt errorClass = %v, want connection-refused", got)
	}
	if got := attempt["target"]; got != "https://bad.example/emby" {
		t.Fatalf("attempt target = %v, want https://bad.example/emby", got)
	}
	if _, ok := attempt["targetAttemptMs"]; !ok {
		t.Fatal("attempt targetAttemptMs missing")
	}
}

func TestTrafficCaptureRecordsRetryableStatusAttemptTarget(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://same.example/emby\nhttps://same.example/jellyfin",
	}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasPrefix(req.URL.Path, "/emby/") {
			return bytesResponse(http.StatusInternalServerError, []byte("fail"), nil), nil
		}
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Ping", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	meta, ok := records[0].Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", records[0].Meta)
	}
	if _, ok := meta["errorClass"]; ok {
		t.Fatalf("successful record should not have final errorClass: %#v", meta)
	}
	attempts, ok := meta["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("attempts = %#v, want one retryable attempt", meta["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("attempt = %T, want map", attempts[0])
	}
	if got := attempt["errorClass"]; got != "retryable-upstream-status" {
		t.Fatalf("attempt errorClass = %v, want retryable-upstream-status", got)
	}
	if got := attempt["upstreamStatus"]; got != float64(http.StatusInternalServerError) {
		t.Fatalf("attempt upstreamStatus = %v, want %d", got, http.StatusInternalServerError)
	}
	if got := attempt["target"]; got != "https://same.example/emby" {
		t.Fatalf("attempt target = %v, want https://same.example/emby", got)
	}
}

func TestTrafficCaptureClearsImageAttemptErrorMetaOnSuccessfulTarget(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://bad.example/images\nhttps://upstream.example/images",
	}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "bad.example" {
			return nil, errors.New("connect: connection refused")
		}
		return bytesResponse(http.StatusOK, []byte("image"), http.Header{"Content-Type": []string{"image/jpeg"}}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Items/1/Images/Primary?tag=ok", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	meta, ok := records[0].Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", records[0].Meta)
	}
	if _, ok := meta["errorClass"]; ok {
		t.Fatalf("successful image record should not have final errorClass: %#v", meta)
	}
	attempts, ok := meta["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("attempts = %#v, want one failed attempt", meta["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("attempt = %T, want map", attempts[0])
	}
	if got := attempt["errorClass"]; got != "connection-refused" {
		t.Fatalf("attempt errorClass = %v, want connection-refused", got)
	}
	if got := attempt["target"]; got != "https://bad.example/images" {
		t.Fatalf("attempt target = %v, want https://bad.example/images", got)
	}
}

func TestTrafficCaptureKeepsLastImageAttemptErrorMetaWhenAllTargetsFail(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://bad.example/images\nhttps://upstream.example/images",
	}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "bad.example" {
			return nil, errors.New("connect: connection refused")
		}
		return nil, errors.New("remote error: tls: handshake failure")
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Items/1/Images/Primary?tag=fail", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	meta, ok := records[0].Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", records[0].Meta)
	}
	if got := meta["errorClass"]; got != "tls" {
		t.Fatalf("final errorClass = %v, want tls: %#v", got, meta)
	}
	attempts, ok := meta["attempts"].([]any)
	if !ok || len(attempts) != 2 {
		t.Fatalf("attempts = %#v, want two failed attempts", meta["attempts"])
	}
	first, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("first attempt = %T, want map", attempts[0])
	}
	if got := first["errorClass"]; got != "connection-refused" {
		t.Fatalf("first attempt errorClass = %v, want connection-refused", got)
	}
	if got := first["target"]; got != "https://bad.example/images" {
		t.Fatalf("first attempt target = %v, want https://bad.example/images", got)
	}
	second, ok := attempts[1].(map[string]any)
	if !ok {
		t.Fatalf("second attempt = %T, want map", attempts[1])
	}
	if got := second["errorClass"]; got != "tls" {
		t.Fatalf("second attempt errorClass = %v, want tls", got)
	}
	if got := second["target"]; got != "https://upstream.example/images" {
		t.Fatalf("second attempt target = %v, want https://upstream.example/images", got)
	}
}

func TestTrafficCaptureRecordsResponseRewriteFailure(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := []byte(`{"WanAddress":"https://upstream.example"}`)
		return bytesResponse(http.StatusOK, body, http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Length":   []string{fmt.Sprintf("%d", len(body))},
			"Content-Type":     []string{"application/json"},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if record.Stage != "systeminfo-rewrite" {
		t.Fatalf("stage = %q, want systeminfo-rewrite", record.Stage)
	}
	if record.TargetURL != "https://upstream.example/emby/System/Info/Public" {
		t.Fatalf("targetUrl = %q, want upstream system info URL", record.TargetURL)
	}
	meta, ok := record.Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", record.Meta)
	}
	if got := meta["errorClass"]; got != "response-rewrite" {
		t.Fatalf("errorClass = %v, want response-rewrite: %#v", got, meta)
	}
	if got := meta["errorStage"]; got != "systeminfo-rewrite" {
		t.Fatalf("errorStage = %v, want systeminfo-rewrite", got)
	}
	if got := meta["contentEncoding"]; got != "gzip" {
		t.Fatalf("contentEncoding = %v, want gzip", got)
	}
	if got := meta["contentType"]; got != "application/json" {
		t.Fatalf("contentType = %v, want application/json", got)
	}
	if got := meta["upstreamStatus"]; got != float64(http.StatusOK) {
		t.Fatalf("upstreamStatus = %v, want %d", got, http.StatusOK)
	}
	errText, ok := meta["error"].(string)
	if !ok || !strings.Contains(strings.ToLower(errText), "gzip") {
		t.Fatalf("error = %#v, want gzip decode error", meta["error"])
	}
}

func TestTrafficCaptureClearsResponseRewriteErrorMetaOnSuccessfulTarget(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://bad.example\nhttps://upstream.example",
	}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := []byte(`{"WanAddress":"https://upstream.example"}`)
		headers := http.Header{
			"Content-Length": []string{fmt.Sprintf("%d", len(body))},
			"Content-Type":   []string{"application/json"},
		}
		if req.URL.Host == "bad.example" {
			headers.Set("Content-Encoding", "gzip")
		}
		return bytesResponse(http.StatusOK, body, headers), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if record.Stage != "systeminfo-rewrite" {
		t.Fatalf("stage = %q, want systeminfo-rewrite", record.Stage)
	}
	if record.TargetURL != "https://upstream.example/emby/System/Info/Public" {
		t.Fatalf("targetUrl = %q, want successful upstream system info URL", record.TargetURL)
	}
	meta, ok := record.Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", record.Meta)
	}
	for _, key := range []string{"error", "errorClass", "errorStage", "upstreamStatus", "targetAttemptMs", "contentEncoding", "contentType", "contentLength"} {
		if _, ok := meta[key]; ok {
			t.Fatalf("successful record should not have final %s: %#v", key, meta)
		}
	}
	attempts, ok := meta["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("attempts = %#v, want one failed rewrite attempt", meta["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("attempt = %T, want map", attempts[0])
	}
	if got := attempt["target"]; got != "https://bad.example/" {
		t.Fatalf("attempt target = %v, want https://bad.example/", got)
	}
}

func TestHandleMediaProxyStoresRangeFieldsForStreamingAccessLog(t *testing.T) {
	tests := []struct {
		name       string
		requestURI string
		targetURL  string
	}{
		{
			name:       "video path",
			requestURI: "https://proxy.example/node/emby/videos/1/original.mp4",
			targetURL:  "https://upstream.example/emby/videos/1/original.mp4",
		},
		{
			name:       "smartstrm path",
			requestURI: "https://proxy.example/node/emby/smartstrm?item_id=1&media_id=2",
			targetURL:  "https://upstream.example/emby/smartstrm?item_id=1&media_id=2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			store := newProxyTestStore(t)
			h := New(config.Config{}, store, nil, logging.New("silent", false))
			h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Get("Range"); got != "bytes=1024-" {
					t.Fatalf("Range = %q, want bytes=1024-", got)
				}
				if req.URL.String() != tt.targetURL {
					t.Fatalf("upstream request URL = %q, want %q", req.URL.String(), tt.targetURL)
				}
				return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
					"Accept-Ranges":  []string{"bytes"},
					"Content-Range":  []string{"bytes 1024-2047/4096"},
					"Content-Type":   []string{"video/mp4"},
					"Content-Length": []string{"1024"},
				}), nil
			})}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil).WithContext(ctx)
			req.Header.Set("Range", "bytes=1024-")
			targetURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatal(err)
			}

			res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: targetURL.Path}, targetURL, nil, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
			if err != nil {
				t.Fatalf("handleMediaProxy() error = %v", err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()

			assertAccessLogRangeFields(t, ctx, "bytes=1024-", "bytes 1024-2047/4096")
		})
	}
}

func TestHandleMediaProxySkipsRangeFieldsForProgressAccessLog(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	actionCalls := 0
	h.defaultFollowClient = failRoundTripClient(t, "default follow client should not handle progress requests")
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		return textResponse(http.StatusNoContent, "", http.Header{
			"Content-Range": []string{"bytes 0-0/1"},
		}), nil
	})}
	h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not handle progress requests")
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/emby/Sessions/Playing/Progress", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-")
	targetURL, err := url.Parse("https://upstream.example/emby/Sessions/Playing/Progress")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Sessions/Playing/Progress"}, targetURL, nil, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	_ = res.Body.Close()
	if actionCalls != 1 {
		t.Fatalf("playback action upstream calls = %d, want 1", actionCalls)
	}

	fields := AccessLogFields(ctx)
	if _, ok := fields["range"]; ok {
		t.Fatalf("range access log field should be absent for progress requests: %v", fields["range"])
	}
	if _, ok := fields["contentRange"]; ok {
		t.Fatalf("contentRange access log field should be absent for progress requests: %v", fields["contentRange"])
	}
}

func TestHandleMediaProxyThrottlesProgressWithOptionalEmbyPrefix(t *testing.T) {
	for _, path := range []string{"/emby/Sessions/Playing/Progress", "/Sessions/Playing/Progress"} {
		t.Run(path, func(t *testing.T) {
			store := newProxyTestStore(t)
			h := New(config.Config{Defaults: config.Defaults{ProgressThrottleMS: 1200}}, store, nil, logging.New("silent", false))
			actionCalls := 0
			h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				actionCalls++
				return textResponse(http.StatusNoContent, "", nil), nil
			})}
			h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not handle progress requests")

			targetURL, err := url.Parse("https://upstream.example" + path)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node"+path, nil)
				req.Header.Set("X-Emby-Device-Id", "device-1")
				res, err := h.handleMediaProxy(context.Background(), req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: path}, cloneURL(targetURL), nil, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
				if err != nil {
					t.Fatalf("handleMediaProxy() error = %v", err)
				}
				_ = res.Body.Close()
				if res.StatusCode != http.StatusNoContent {
					t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusNoContent)
				}
			}
			if actionCalls != 1 {
				t.Fatalf("playback action upstream calls = %d, want 1", actionCalls)
			}
		})
	}
}

func TestServeHTTPLogsThrottledPlaybackProgressDuration(t *testing.T) {
	store := newProxyTestStore(t)
	if err := store.SaveNode(context.Background(), "admin", storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://upstream.example",
	}); err != nil {
		t.Fatal(err)
	}

	h := New(config.Config{Defaults: config.Defaults{ProgressThrottleMS: 5000}}, store, nil, logging.New("silent", false))
	actionCalls := 0
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		return textResponse(http.StatusNoContent, "", nil), nil
	})}

	sendPlaybackAction := func(path, body string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "throttle-duration-client")
		req.Header.Set("X-Emby-Device-Id", "device-1")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d, want %d; body = %s", path, rr.Code, http.StatusNoContent, rr.Body.String())
		}
	}

	sendPlaybackAction("/emby/Sessions/Playing", `{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":true}`)
	time.Sleep(10 * time.Millisecond)
	sendPlaybackAction("/emby/Sessions/Playing/Progress", `{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`)
	time.Sleep(50 * time.Millisecond)
	sendPlaybackAction("/emby/Sessions/Playing/Progress", `{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":300000,"IsPaused":false}`)

	if actionCalls != 2 {
		t.Fatalf("playback action upstream calls = %d, want 2", actionCalls)
	}

	deadline := time.Now().Add(2 * time.Second)
	var lastPlaybackMillis int64
	for {
		stats, err := h.store.GetTodayStats(context.Background())
		if err != nil {
			t.Fatalf("GetTodayStats() error = %v", err)
		}
		for _, row := range stats.Today {
			if row.Node == "node" && row.Client == "throttle-duration-client" {
				lastPlaybackMillis = row.PlaybackMillis
				if row.PlaybackMillis > 0 {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("playback millis = %d, want throttled progress to add playback duration", lastPlaybackMillis)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeHTTPTracksConcurrentPlaybackSessionsWithoutQuerySessionID(t *testing.T) {
	store := newProxyTestStore(t)
	if err := store.SaveNode(context.Background(), "admin", storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://upstream.example",
	}); err != nil {
		t.Fatal(err)
	}

	h := New(config.Config{Defaults: config.Defaults{ProgressThrottleMS: 5000}}, store, nil, logging.New("silent", false))
	actionCalls := 0
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		return textResponse(http.StatusNoContent, "", nil), nil
	})}
	send := func(path, playSessionID string, positionTicks int64) {
		t.Helper()
		body := fmt.Sprintf(
			`{"ItemId":"item-%s","PlaySessionId":"%s","PositionTicks":%d,"IsPaused":false}`,
			playSessionID,
			playSessionID,
			positionTicks,
		)
		req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "concurrent-duration-client")
		req.Header.Set("X-Emby-Device-Id", "shared-device")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s %s status = %d, want %d; body = %s", path, playSessionID, rr.Code, http.StatusNoContent, rr.Body.String())
		}
	}

	send("/emby/Sessions/Playing", "play-1", 0)
	send("/emby/Sessions/Playing", "play-2", 0)
	send("/emby/Sessions/Playing/Progress", "play-1", 300_000)
	send("/emby/Sessions/Playing/Progress", "play-2", 400_000)

	if actionCalls != 3 {
		t.Fatalf("playback action upstream calls = %d, want 3 with the second Progress throttled", actionCalls)
	}
	var states int
	var positions int64
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*), COALESCE(SUM(last_position_ticks), 0)
		FROM playback_states WHERE closed = 0
	`).Scan(&states, &positions); err != nil {
		t.Fatalf("query playback states error = %v", err)
	}
	if states != 2 || positions != 700_000 {
		t.Fatalf("playback states = %d positions = %d; want 2 and 700000", states, positions)
	}
}

func TestServeHTTPClosesPlaybackStateWithTargetPathWhenStoppedUpstreamFails(t *testing.T) {
	store := newProxyTestStore(t)
	if err := store.SaveNode(context.Background(), "admin", storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://upstream.example/proxy",
	}); err != nil {
		t.Fatal(err)
	}

	h := New(config.Config{}, store, nil, logging.New("silent", false))
	assertState := func(wantPosition int64, wantClosed int) {
		t.Helper()
		var position int64
		var closed int
		if err := store.DB().QueryRowContext(context.Background(), `
			SELECT last_position_ticks, closed
			FROM playback_states
			WHERE k = 'node|play|play-session-1'
		`).Scan(&position, &closed); err != nil {
			t.Fatalf("query playback state error = %v", err)
		}
		if position != wantPosition || closed != wantClosed {
			t.Fatalf("playback state position = %d closed = %d; want %d and %d", position, closed, wantPosition, wantClosed)
		}
	}
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/proxy/emby/Sessions/Playing" {
			t.Fatalf("upstream playing path = %q, want %q", req.URL.Path, "/proxy/emby/Sessions/Playing")
		}
		assertState(0, 0)
		return textResponse(http.StatusNoContent, "", nil), nil
	})}
	send := func(path, body string, wantStatus int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "failed-stop-client")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != wantStatus {
			t.Fatalf("%s status = %d, want %d; body = %s", path, rr.Code, wantStatus, rr.Body.String())
		}
	}

	send("/emby/Sessions/Playing", `{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`, http.StatusNoContent)
	time.Sleep(10 * time.Millisecond)
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/proxy/emby/Sessions/Playing/Stopped" {
			t.Fatalf("upstream stopped path = %q, want %q", req.URL.Path, "/proxy/emby/Sessions/Playing/Stopped")
		}
		assertState(1_000_000, 1)
		return nil, errors.New("upstream stopped failure")
	})}
	send("/emby/Sessions/Playing/Stopped", `{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":1000000,"IsPaused":false}`, http.StatusBadGateway)
	assertState(1_000_000, 1)
}

func TestHandleMediaProxyRecordsStoppedWithCanceledRequestContext(t *testing.T) {
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":1000000,"IsPaused":false}`)
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/emby/Sessions/Playing/Stopped", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("User-Agent", "canceled-stop-client")
	targetURL, err := url.Parse("https://upstream.example/emby/Sessions/Playing/Stopped")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Sessions/Playing/Stopped"}, targetURL, body, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
	if err == nil {
		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
		t.Fatal("handleMediaProxy() error = nil, want canceled upstream request")
	}

	var closed int
	if err := store.DB().QueryRowContext(context.Background(), `SELECT closed FROM playback_states`).Scan(&closed); err != nil {
		t.Fatalf("query playback state error = %v", err)
	}
	if closed != 1 {
		t.Fatalf("closed = %d, want 1", closed)
	}
}

func TestResponseReadyLogFieldsUsesResponseTarget(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	SetAccessLogField(ctx, "responseReadyMs", int64(68))
	req := httptest.NewRequest(http.MethodGet, "https://www.google.com/search?q=emby", nil)
	res := &http.Response{StatusCode: http.StatusOK, Request: req}

	fields := responseReadyLogFields(ctx, res, map[string]any{
		"id":              "req-1",
		"node":            "node",
		"target":          "https://emby.example",
		"status":          http.StatusOK,
		"responseReadyMs": int64(71),
	})

	if fields["target"] != "https://www.google.com" {
		t.Fatalf("target = %v, want actual target", fields["target"])
	}
	if fields["nodeTarget"] != "https://emby.example" {
		t.Fatalf("nodeTarget = %v, want original node target", fields["nodeTarget"])
	}
	if fields["responseReadyMs"] != int64(68) {
		t.Fatalf("responseReadyMs = %v, want direct response ready duration", fields["responseReadyMs"])
	}
}

func TestHandleNodeStripsClientIPHeadersFromForwardedRequest(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	var upstreamHeaders http.Header
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamHeaders = cloneHeader(req.Header)
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/System/Ping", nil)
	setClientIPHeaders(req)

	res, err := h.handleNode(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	assertHeadersAbsent(t, upstreamHeaders, clientIPHeaderKeys...)
}

func TestHandleNodeAddsHillsIdentityToProxyTarget(t *testing.T) {
	ctx := context.Background()
	ids := identity.NewManager(nil)
	var upstreamReq *http.Request
	h := New(config.Config{}, newProxyTestStore(t), ids, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamReq = req.Clone(req.Context())
		upstreamReq.Header = cloneHeader(req.Header)
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "hills_windows"}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Ping?tag=v1&x_emby_device_id=source-device&X-Emby-Language=en-us", nil)
	req.Header.Set("X-Emby-Token", "header-token")

	res, err := h.handleNode(ctx, req, node, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	if upstreamReq == nil {
		t.Fatal("upstream request was not sent")
	}
	assertHillsOutboundIdentityApplied(t, ids, upstreamReq, "hills_windows", "header-token")
	if got := upstreamReq.URL.Query().Get("tag"); got != "v1" {
		t.Fatalf("tag = %q, want v1", got)
	}
}

func TestHandleSTRMStripsClientIPHeadersFromSourceRequest(t *testing.T) {
	var upstreamHeaders http.Header
	h := &Handler{
		playbackActionClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamHeaders = cloneHeader(req.Header)
			return bytesResponse(http.StatusForbidden, []byte("forbidden"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	setClientIPHeaders(req)
	sourceURL, err := url.Parse("https://upstream.example/movie.strm")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleSTRM(context.Background(), req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/movie.strm"}, sourceURL, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	assertHeadersAbsent(t, upstreamHeaders, clientIPHeaderKeys...)
}

func TestHandleSTRMAddsHillsIdentityToSourceRequest(t *testing.T) {
	ids := identity.NewManager(nil)
	var upstreamReq *http.Request
	h := &Handler{
		ids: ids,
		playbackActionClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamReq = req.Clone(req.Context())
			upstreamReq.Header = cloneHeader(req.Header)
			return bytesResponse(http.StatusForbidden, []byte("forbidden"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	req.Header.Set("X-Emby-Token", "header-token")
	sourceURL, err := url.Parse("https://upstream.example/movie.strm?X_MediaBrowser_Client=Original&DeviceId=source-device&tag=v1")
	if err != nil {
		t.Fatal(err)
	}
	node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "hills_android"}

	res, err := h.handleSTRM(context.Background(), req, node, parsedRoute{Name: "node", Path: "/movie.strm"}, sourceURL, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	if upstreamReq == nil {
		t.Fatal("STRM source request was not sent")
	}
	assertHillsOutboundHeaderIdentityApplied(t, ids, upstreamReq, "hills_android", "header-token")
	assertHillsIdentityQueryAbsent(t, upstreamReq)
	if got := upstreamReq.URL.Query().Get("tag"); got != "v1" {
		t.Fatalf("tag = %q, want v1", got)
	}
}

func TestHandleSTRMImpersonatesSourceRequestUserAgent(t *testing.T) {
	var upstreamHeaders http.Header
	h := &Handler{
		ids: identity.NewManager(nil),
		playbackActionClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamHeaders = cloneHeader(req.Header)
			return bytesResponse(http.StatusForbidden, []byte("forbidden"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	sourceUA := "ActualClient/9.9"
	req.Header.Set("User-Agent", sourceUA)
	sourceURL, err := url.Parse("https://upstream.example/movie.strm")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleSTRM(context.Background(), req, storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: identity.DefaultProfile}, parsedRoute{Name: "node", Path: "/movie.strm"}, sourceURL, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	wantUA := identity.GetProfile(identity.DefaultProfile).UserAgent
	if got := upstreamHeaders.Get("User-Agent"); got != wantUA {
		t.Fatalf("User-Agent = %q, want impersonated user agent %q", got, wantUA)
	}
}

func TestHandleSTRMDecodesEncodedSourceResponse(t *testing.T) {
	var sourceAcceptEncoding string
	var directURL string
	h := newProxyTestHandler(t, storage.Node{})
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sourceAcceptEncoding = req.Header.Get("Accept-Encoding")
		body := gzipTestBody(t, "https://8.8.8.8/video.mp4")
		return bytesResponse(http.StatusOK, body, http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Length":   []string{fmt.Sprintf("%d", len(body))},
			"Content-Type":     []string{"text/plain"},
		}), nil
	})}
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		directURL = req.URL.String()
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"video/mp4"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	sourceURL, err := url.Parse("https://upstream.example/movie.strm")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleSTRM(context.Background(), req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/movie.strm"}, sourceURL, nil, config.ProxyEnv{ExternalAllowAny: true})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if sourceAcceptEncoding != "gzip, br" {
		t.Fatalf("source Accept-Encoding = %q, want gzip, br", sourceAcceptEncoding)
	}
	if directURL != "https://8.8.8.8/video.mp4" {
		t.Fatalf("direct URL = %q, want decoded STRM target", directURL)
	}
}

func TestTrafficCaptureRecordsSTRMSourceReadError(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header: http.Header{
				"Content-Encoding": []string{"gzip"},
				"Content-Length":   []string{"42"},
				"Content-Type":     []string{"text/plain"},
			},
			Body: failingReadBody{err: errors.New("unexpected EOF")},
		}, nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/movie.strm", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if record.Stage != "strm-parse-error" {
		t.Fatalf("stage = %q, want strm-parse-error", record.Stage)
	}
	meta, ok := record.Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", record.Meta)
	}
	if got := meta["errorClass"]; got != "upstream-error" {
		t.Fatalf("errorClass = %v, want upstream-error", got)
	}
	if got := meta["errorStage"]; got != "strm-parse-error" {
		t.Fatalf("errorStage = %v, want strm-parse-error", got)
	}
	if got := meta["strmReadError"]; got != "unexpected EOF" {
		t.Fatalf("strmReadError = %v, want unexpected EOF", got)
	}
	if got := meta["strmSourceStatus"]; got != float64(http.StatusOK) {
		t.Fatalf("strmSourceStatus = %v, want %d", got, http.StatusOK)
	}
	if got := meta["strmSourceContentEncoding"]; got != "gzip" {
		t.Fatalf("strmSourceContentEncoding = %v, want gzip", got)
	}
	if got := meta["strmSourceContentType"]; got != "text/plain" {
		t.Fatalf("strmSourceContentType = %v, want text/plain", got)
	}
	if got := meta["strmSourceContentLength"]; got != "42" {
		t.Fatalf("strmSourceContentLength = %v, want 42", got)
	}
}

func TestTrafficCaptureKeepsSTRMSourceReadErrorOnSuccessfulFailover(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{
		Name:   "node",
		Secret: "secret",
		Target: "https://8.8.4.4\nhttps://8.8.8.8",
	}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "8.8.4.4" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Encoding": []string{"gzip"},
					"Content-Length":   []string{"42"},
					"Content-Type":     []string{"text/plain"},
				},
				Body: failingReadBody{err: errors.New("unexpected EOF")},
			}, nil
		}
		return bytesResponse(http.StatusOK, []byte("https://8.8.8.8/video.mp4"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"video/mp4"}}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/movie.strm", nil)
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	meta, ok := records[0].Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", records[0].Meta)
	}
	if _, ok := meta["strmReadError"]; ok {
		t.Fatalf("successful record should not have final strmReadError: %#v", meta)
	}
	attempts, ok := meta["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("attempts = %#v, want one failed STRM attempt", meta["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("attempt = %T, want map", attempts[0])
	}
	if got := attempt["upstreamStatus"]; got != float64(http.StatusBadGateway) {
		t.Fatalf("attempt upstreamStatus = %v, want %d", got, http.StatusBadGateway)
	}
	if got := attempt["strmReadError"]; got != "unexpected EOF" {
		t.Fatalf("attempt strmReadError = %v, want unexpected EOF", got)
	}
	if got := attempt["strmSourceStatus"]; got != float64(http.StatusOK) {
		t.Fatalf("attempt strmSourceStatus = %v, want %d", got, http.StatusOK)
	}
	if got := attempt["strmSourceContentEncoding"]; got != "gzip" {
		t.Fatalf("attempt strmSourceContentEncoding = %v, want gzip", got)
	}
	if got := attempt["strmSourceContentType"]; got != "text/plain" {
		t.Fatalf("attempt strmSourceContentType = %v, want text/plain", got)
	}
	if got := attempt["strmSourceContentLength"]; got != "42" {
		t.Fatalf("attempt strmSourceContentLength = %v, want 42", got)
	}
	if got := attempt["errorStage"]; got != "strm-parse-error" {
		t.Fatalf("attempt errorStage = %v, want strm-parse-error", got)
	}
}

func TestHandleSTRMBlocksPrivateDirectTarget(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	rawCalls := 0
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("http://127.0.0.1/private"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rawCalls++
		return bytesResponse(http.StatusOK, []byte("unexpected"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	sourceURL, err := url.Parse("https://upstream.example/movie.strm")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleSTRM(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/movie.strm"}, sourceURL, nil, config.ProxyEnv{ExternalAllowAny: true})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusForbidden)
	}
	if rawCalls != 0 {
		t.Fatalf("raw direct calls = %d, want 0", rawCalls)
	}
}

func TestHandleDirectDoesNotAppendRequestQuery(t *testing.T) {
	ctx := context.Background()
	rawCalls := 0
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rawCalls++
			if req.URL.String() != "http://8.8.8.8/video.mkv?sign=abc" {
				t.Fatalf("raw URL = %q, want direct URL without request query", req.URL.String())
			}
			return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/smartstrm?item_id=1&media_id=2", nil)

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/video.mkv?sign=abc", config.ProxyEnv{ExternalAllowAny: true}, storage.Node{Name: "node", Target: "https://upstream.example"}, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if rawCalls != 1 {
		t.Fatalf("raw direct calls = %d, want 1", rawCalls)
	}
}

func TestHandleDirectPromotesYambyQueryAuthWithoutMutatingURLOrInboundHeaders(t *testing.T) {
	ctx := context.Background()
	rawCalls := 0
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		ids: identity.NewManager(nil),
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rawCalls++
			if req.Header.Get("X-Emby-Token") == "" {
				t.Fatal("upstream X-Emby-Token header was not set")
			}
			if got := req.URL.Query().Get("x-emby-token"); got != "query-value" {
				t.Fatalf("upstream x-emby-token query = %q, want preserved", got)
			}
			if got := req.URL.Query().Get("tag"); got != "v1" {
				t.Fatal("ordinary upstream query parameter was not preserved")
			}
			return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items", nil)
	node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: identity.DefaultProfile}

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/video.mkv?x-emby-token=query-value&tag=v1", config.ProxyEnv{ExternalAllowAny: true}, node, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if rawCalls != 1 {
		t.Fatalf("raw direct calls = %d, want 1", rawCalls)
	}
	if req.Header.Get("X-Emby-Token") != "" {
		t.Fatal("inbound request header was mutated")
	}
}

func TestHandleDirectPreservesSignedQueryAndAddsHillsHeaderIdentity(t *testing.T) {
	ctx := context.Background()
	ids := identity.NewManager(nil)
	var upstreamReq *http.Request
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		ids: ids,
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamReq = req.Clone(req.Context())
			upstreamReq.Header = cloneHeader(req.Header)
			return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items", nil)
	req.Header.Set("X-Emby-Token", "header-token")
	node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "hills_windows"}

	res, err := h.handleDirect(ctx, req, `http://8.8.8.8/video.mkv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-SignedHeaders=host&X-Amz-Signature=sig-value&token=signed-token&client=cdn-client&version=cdn-version&language=cdn-lang&authorization=Bearer%20direct-token&tag=v1`, config.ProxyEnv{ExternalAllowAny: true}, node, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if upstreamReq == nil {
		t.Fatal("direct upstream request was not sent")
	}
	snap := ids.Snapshot("hills_windows")
	if got := upstreamReq.Header.Get("User-Agent"); got != snap.UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, snap.UserAgent)
	}
	if got := upstreamReq.Header.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="`+snap.ClientName+`"`) {
		t.Fatalf("X-Emby-Authorization header = %q, want Hills identity", got)
	}
	if got := upstreamReq.Header.Get("X-Emby-Token"); got != "header-token" {
		t.Fatalf("X-Emby-Token header = %q, want header-token", got)
	}
	for key, want := range map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-SignedHeaders": "host",
		"X-Amz-Signature":     "sig-value",
		"token":               "signed-token",
		"client":              "cdn-client",
		"version":             "cdn-version",
		"language":            "cdn-lang",
		"authorization":       "Bearer direct-token",
		"tag":                 "v1",
	} {
		if got := upstreamReq.URL.Query().Get(key); got != want {
			t.Fatalf("%s = %q, want %q; raw query: %s", key, got, want, upstreamReq.URL.RawQuery)
		}
	}
	for _, key := range []string{"X-Emby-Authorization", "X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Name", "X-Emby-Device-Id", "X-Emby-Language", "X-Emby-Token"} {
		if got := upstreamReq.URL.Query().Get(key); got != "" {
			t.Fatalf("%s query = %q, want absent for direct target; raw query: %s", key, got, upstreamReq.URL.RawQuery)
		}
	}
	if req.Header.Get("X-Emby-Token") != "header-token" {
		t.Fatal("inbound request header was mutated")
	}
}

func TestHandleDirectStoresRangeFieldsForStreamingAccessLog(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Range"); got != "bytes=4096-" {
				t.Fatalf("Range = %q, want bytes=4096-", got)
			}
			return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
				"Accept-Ranges":  []string{"bytes"},
				"Content-Range":  []string{"bytes 4096-8191/16384"},
				"Content-Type":   []string{"video/x-matroska"},
				"Content-Length": []string{"4096"},
			}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/http%3A%2F%2F8.8.8.8%2Fvideo.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=4096-")

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/video.mkv", config.ProxyEnv{ExternalAllowAny: true}, storage.Node{Name: "node", Target: "https://upstream.example"}, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	assertAccessLogRangeFields(t, ctx, "bytes=4096-", "bytes 4096-8191/16384")
}

func TestServeHTTPManualRawURLRequiresExternalAllow(t *testing.T) {
	h, rawCalls := newRawServeHTTPHarness(t, config.Config{}, nil)
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/__raw__/http%3A%2F%2F8.8.8.8%2Fvideo.mkv", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if *rawCalls != 0 {
		t.Fatalf("raw direct calls = %d, want 0", *rawCalls)
	}
}

func TestServeHTTPSignedRawURLBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		extraQuery string
		wantStatus int
		wantCalls  int
		check      func(t *testing.T, req *http.Request)
	}{
		{
			name:       "bypasses external allow and strips signature query",
			raw:        "http://8.8.8.8/video.mkv?token=x",
			wantStatus: http.StatusOK,
			wantCalls:  1,
			check: func(t *testing.T, req *http.Request) {
				t.Helper()
				if got, want := req.URL.String(), "http://8.8.8.8/video.mkv?token=x"; got != want {
					t.Fatalf("upstream raw URL = %q, want %q", got, want)
				}
				for _, key := range []string{rawLinkURLParam, rawLinkExpParam, rawLinkSigParam} {
					if req.URL.Query().Has(key) {
						t.Fatalf("upstream URL leaked proxy signature parameter %q: %s", key, req.URL.String())
					}
				}
			},
		},
		{
			name:       "preserves encoded upstream query",
			raw:        "http://8.8.8.8/video.mkv?X-Amz-Credential=AKIA%2F20260708%2Fs3&X-Amz-Signature=sig-value",
			wantStatus: http.StatusOK,
			wantCalls:  1,
			check: func(t *testing.T, req *http.Request) {
				t.Helper()
				if got, want := req.URL.String(), "http://8.8.8.8/video.mkv?X-Amz-Credential=AKIA%2F20260708%2Fs3&X-Amz-Signature=sig-value"; got != want {
					t.Fatalf("upstream raw URL = %q, want %q", got, want)
				}
				if !strings.Contains(req.URL.RawQuery, "AKIA%2F20260708%2Fs3") {
					t.Fatalf("upstream raw query lost encoded slashes: %s", req.URL.RawQuery)
				}
			},
		},
		{
			name:       "extra proxy query requires external allow",
			raw:        "http://8.8.8.8/video.mkv",
			extraQuery: "&client-added=1",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "still blocks private target",
			raw:        "http://127.0.0.1/private",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamReqs := []*http.Request{}
			h, rawCalls := newRawServeHTTPHarness(t, config.Config{AdminToken: "test-admin-token"}, func(req *http.Request) (*http.Response, error) {
				upstreamReqs = append(upstreamReqs, req.Clone(req.Context()))
				return textResponse(http.StatusOK, "ok", nil), nil
			})
			req := httptest.NewRequest(http.MethodGet, h.signedRawLink("https://proxy.example", "/node/secret", tt.raw)+tt.extraQuery, nil)
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if *rawCalls != tt.wantCalls {
				t.Fatalf("raw direct calls = %d, want %d", *rawCalls, tt.wantCalls)
			}
			if tt.check != nil {
				if len(upstreamReqs) != 1 {
					t.Fatalf("upstream request count = %d, want 1", len(upstreamReqs))
				}
				tt.check(t, upstreamReqs[0])
			}
		})
	}
}

func TestServeHTTPSignedRawURLBypassAppliesToPublicRedirects(t *testing.T) {
	calls := []string{}
	h, _ := newRawServeHTTPHarness(t, config.Config{AdminToken: "test-admin-token"}, func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.URL.String())
		switch req.URL.Host {
		case "8.8.8.8":
			return textResponse(http.StatusFound, "", http.Header{"Location": []string{"http://8.8.4.4/final"}}), nil
		case "8.8.4.4":
			return textResponse(http.StatusOK, "ok", nil), nil
		default:
			t.Fatalf("unexpected direct target: %s", req.URL.String())
			return nil, nil
		}
	})
	req := httptest.NewRequest(http.MethodGet, h.signedRawLink("https://proxy.example", "/node/secret", "http://8.8.8.8/start"), nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; calls=%v; body=%q", rec.Code, http.StatusOK, calls, rec.Body.String())
	}
	if len(calls) != 2 || calls[0] != "http://8.8.8.8/start" || calls[1] != "http://8.8.4.4/final" {
		t.Fatalf("direct calls = %v, want start then final redirect", calls)
	}
}

func TestRewriteBodyLinksSignsExternalRawLinks(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	h := New(config.Config{AdminToken: "test-admin-token"}, store, nil, logging.New("silent", false))
	raw := "https://cdn.example/segments/1.ts?sig=abc"

	out := h.rewriteBodyLinks(ctx, "#EXTM3U\n"+raw, "https://proxy.example/node/secret/playlist.m3u8", node, "node", "secret")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("rewritten manifest lines = %q", lines)
	}
	assertSignedRawLink(t, h, lines[1], "https://proxy.example", "/node/secret", raw)
}

func TestRetryableStatusReasonDetectsLocalForbiddenResponses(t *testing.T) {
	res := localForbiddenResponse("direct", "https://115.example/video.mkv?sign=abc")

	fields := retryableStatusLogFields(res, map[string]any{"target": "https://emby.example"})
	if fields["reason"] != "direct-host-not-allowed" {
		t.Fatalf("reason = %v, want direct-host-not-allowed", fields["reason"])
	}
	if fields["target"] != "https://115.example" {
		t.Fatalf("target = %v, want actual target", fields["target"])
	}
	if fields["nodeTarget"] != "https://emby.example" {
		t.Fatalf("nodeTarget = %v, want original node target", fields["nodeTarget"])
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "Forbidden direct host" {
		t.Fatalf("body = %q, want original body", body)
	}

	res = localForbiddenResponse("raw", "https://raw.example/video.mkv")
	fields = retryableStatusLogFields(res, map[string]any{})
	if fields["reason"] != "raw-host-not-allowed" {
		t.Fatalf("raw reason = %v, want raw-host-not-allowed", fields["reason"])
	}
}

func TestHandleDirectBlocksPrivateRedirect(t *testing.T) {
	ctx := context.Background()
	rawCalls := 0
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rawCalls++
			return textResponse(http.StatusFound, "", http.Header{"Location": []string{"http://127.0.0.1/private"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/http%3A%2F%2F8.8.8.8%2Fstart", nil)

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/start", config.ProxyEnv{ExternalAllowAny: true}, storage.Node{Name: "node", Target: "https://upstream.example"}, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusForbidden)
	}
	if rawCalls != 1 {
		t.Fatalf("raw direct calls = %d, want 1", rawCalls)
	}
}

func TestFinishGeneralResponseRewritesSystemInfoAddresses(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	targetURL, err := url.Parse("https://upstream.example/emby/System/Info/Public")
	if err != nil {
		t.Fatal(err)
	}
	res := bytesResponse(http.StatusOK, []byte(`{"ServerName":"demo","Version":"4.9.3.0","WanAddress":"https://upstream.example","LocalAddress":"http://192.168.1.2:8096"}`), http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Length": []string{"128"},
	})

	out, err := h.finishGeneralResponse(context.Background(), req, res, storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/System/Info/Public"}, targetURL, targetURL, http.Header{}, config.ProxyEnv{}, "", false, false, false)
	if err != nil {
		t.Fatalf("finishGeneralResponse() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := out.Header.Get("Content-Length"), fmt.Sprintf("%d", len(body)); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}
	if strings.Contains(string(body), "upstream.example") || strings.Contains(string(body), "192.168.1.2") {
		t.Fatalf("system info leaked upstream address: %s", body)
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	want := "https://proxy.example/node/secret"
	if payload["WanAddress"] != want {
		t.Fatalf("WanAddress = %q, want %q", payload["WanAddress"], want)
	}
	if payload["LocalAddress"] != want {
		t.Fatalf("LocalAddress = %q, want %q", payload["LocalAddress"], want)
	}
}

func TestFinishGeneralResponseDoesNotRewritePartialSystemInfo(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	targetURL, err := url.Parse("https://upstream.example/emby/System/Info/Public")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"WanAddress":"https://upstream.example"}`)
	res := bytesResponse(http.StatusPartialContent, raw, http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Range":  []string{"bytes 0-39/40"},
		"Content-Length": []string{fmt.Sprintf("%d", len(raw))},
	})

	out, err := h.finishGeneralResponse(context.Background(), req, res, storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/System/Info/Public"}, targetURL, targetURL, http.Header{}, config.ProxyEnv{}, "", false, false, false)
	if err != nil {
		t.Fatalf("finishGeneralResponse() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, raw) {
		t.Fatalf("body = %q, want original partial body %q", body, raw)
	}
	if got := out.Header.Get("Content-Range"); got != "bytes 0-39/40" {
		t.Fatalf("Content-Range = %q, want original range", got)
	}
}

func TestFinishGeneralResponseRewritesMediaSourceURLsInItemDetails(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	if err := store.SaveNode(ctx, "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Users/u1/Items/201602?Fields=MediaSources,ExternalUrls", nil)
	targetURL, err := url.Parse("https://upstream.example/emby/Users/u1/Items/201602?Fields=MediaSources,ExternalUrls")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{
		"Id":"201602",
		"MediaSources":[{
			"Id":"m1",
			"Size":9223372036854775807,
			"DirectStreamUrl":"https://upstream.example/videos/201602/original.mkv?api_key=abc&sign=1",
			"TranscodingUrl":"https://upstream.example:443/Videos/201602/master.m3u8?MediaSourceId=m1",
			"StreamUrl":"https://public.example/Videos/201602/stream.mkv?sig=abc"
		},{
			"Id":"m2",
			"DirectStreamUrl":"https://cdn.example/video.mp4?token=x"
		}],
		"ExternalUrls":[{"Name":"IMDb","Url":"https://www.imdb.com/title/tt123"}]
	}`)
	res := bytesResponse(http.StatusOK, raw, http.Header{"Content-Type": []string{"application/json"}})

	out, err := h.finishGeneralResponse(ctx, req, res, node, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/Users/u1/Items/201602"}, targetURL, targetURL, http.Header{}, config.ProxyEnv{}, "", false, false, false)
	if err != nil {
		t.Fatalf("finishGeneralResponse() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("9223372036854775807")) {
		t.Fatalf("large numeric media source value was not preserved: %s", body)
	}
	payload := decodeJSONMap(t, body)
	sources := payload["MediaSources"].([]any)
	first := sources[0].(map[string]any)
	if got, want := first["DirectStreamUrl"], "/videos/201602/original.mkv?api_key=abc&sign=1"; got != want {
		t.Fatalf("DirectStreamUrl = %q, want %q", got, want)
	}
	if got, want := first["TranscodingUrl"], "/Videos/201602/master.m3u8?MediaSourceId=m1"; got != want {
		t.Fatalf("TranscodingUrl = %q, want %q", got, want)
	}
	assertRelativeSignedRawLink(t, h, first["StreamUrl"].(string), "/node/secret", "https://public.example/Videos/201602/stream.mkv?sig=abc")
	second := sources[1].(map[string]any)
	assertRelativeSignedRawLink(t, h, second["DirectStreamUrl"].(string), "/node/secret", "https://cdn.example/video.mp4?token=x")
	external := payload["ExternalUrls"].([]any)[0].(map[string]any)
	if got, want := external["Url"], "https://www.imdb.com/title/tt123"; got != want {
		t.Fatalf("ExternalUrls[0].Url = %q, want %q", got, want)
	}
}

func TestFinishGeneralResponseRewritesMediaSourceURLsInPlaybackInfo(t *testing.T) {
	ctx := context.Background()
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	h := New(config.Config{}, newProxyTestStore(t), nil, logging.New("silent", false))
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Items/1/PlaybackInfo", nil)
	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/PlaybackInfo")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"MediaSources":[{"DirectStreamUrl":"https://upstream.example/videos/1/original.mkv","TranscodingUrl":"/videos/1/master.m3u8","StreamUrl":"https://unknown.example/stream.mkv"}]}`)
	res := bytesResponse(http.StatusOK, raw, http.Header{"Content-Type": []string{"application/json"}})

	out, err := h.finishGeneralResponse(ctx, req, res, node, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/Items/1/PlaybackInfo"}, targetURL, targetURL, http.Header{}, config.ProxyEnv{}, "", false, false, false)
	if err != nil {
		t.Fatalf("finishGeneralResponse() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	source := decodeJSONMap(t, body)["MediaSources"].([]any)[0].(map[string]any)
	if got, want := source["DirectStreamUrl"], "/videos/1/original.mkv"; got != want {
		t.Fatalf("DirectStreamUrl = %q, want %q", got, want)
	}
	if got, want := source["TranscodingUrl"], "/videos/1/master.m3u8"; got != want {
		t.Fatalf("TranscodingUrl = %q, want %q", got, want)
	}
	assertRelativeSignedRawLink(t, h, source["StreamUrl"].(string), "/node/secret", "https://unknown.example/stream.mkv")
}

func TestHandleMediaProxyRewritesPlaybackInfoMediaSourceURLs(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	h := New(config.Config{}, newProxyTestStore(t), nil, logging.New("silent", false))
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte(`{"MediaSources":[{"DirectStreamUrl":"https://upstream.example/videos/1/original.mkv","TranscodingUrl":"/videos/1/master.m3u8","StreamUrl":"https://cdn.example/video.mp4?token=x"}]}`), http.Header{"Content-Type": []string{"application/json"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Items/1/PlaybackInfo", nil).WithContext(ctx)
	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/PlaybackInfo")
	if err != nil {
		t.Fatal(err)
	}

	out, err := h.handleMediaProxy(ctx, req, node, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/Items/1/PlaybackInfo"}, targetURL, nil, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	source := decodeJSONMap(t, body)["MediaSources"].([]any)[0].(map[string]any)
	if got, want := source["DirectStreamUrl"], "/videos/1/original.mkv"; got != want {
		t.Fatalf("DirectStreamUrl = %q, want %q", got, want)
	}
	if got, want := source["TranscodingUrl"], "/videos/1/master.m3u8"; got != want {
		t.Fatalf("TranscodingUrl = %q, want %q", got, want)
	}
	assertRelativeSignedRawLink(t, h, source["StreamUrl"].(string), "/node/secret", "https://cdn.example/video.mp4?token=x")
}

func TestFinishGeneralResponseKeepsMediaSourceURLsWhenDirectExternalEnabled(t *testing.T) {
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", DirectExternal: true}
	h := New(config.Config{}, newProxyTestStore(t), nil, logging.New("silent", false))
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Items/1/PlaybackInfo", nil)
	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/PlaybackInfo")
	if err != nil {
		t.Fatal(err)
	}
	rawURL := "https://upstream.example/videos/1/original.mkv?sign=abc"
	res := bytesResponse(http.StatusOK, []byte(`{"MediaSources":[{"DirectStreamUrl":"`+rawURL+`"}]}`), http.Header{"Content-Type": []string{"application/json"}})

	out, err := h.finishGeneralResponse(context.Background(), req, res, node, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/Items/1/PlaybackInfo"}, targetURL, targetURL, http.Header{}, config.ProxyEnv{}, "", false, false, false)
	if err != nil {
		t.Fatalf("finishGeneralResponse() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	source := decodeJSONMap(t, body)["MediaSources"].([]any)[0].(map[string]any)
	if got := source["DirectStreamUrl"]; got != rawURL {
		t.Fatalf("DirectStreamUrl = %q, want %q", got, rawURL)
	}
}

func TestFinishGeneralResponseBlocksUnsafeCrossHostLocations(t *testing.T) {
	tests := []struct {
		name       string
		requestURI string
		location   string
		node       storage.Node
		route      parsedRoute
		env        config.ProxyEnv
	}{
		{
			name:       "private direct location",
			requestURI: "https://proxy.example/node/emby/redirect",
			location:   "http://127.0.0.1/private",
			node:       storage.Node{Name: "node", Target: "https://upstream.example"},
			route:      parsedRoute{Name: "node", Path: "/emby/redirect"},
			env:        config.ProxyEnv{ExternalAllowAny: true},
		},
		{
			name:       "untrusted public location",
			requestURI: "https://proxy.example/node/secret/emby/redirect-public",
			location:   "http://8.8.8.8/video.mkv?sign=abc",
			node:       storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"},
			route:      parsedRoute{Name: "node", Secret: "secret", Path: "/emby/redirect-public"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawCalls := 0
			h := New(config.Config{}, nil, nil, logging.New("silent", false))
			h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				rawCalls++
				return bytesResponse(http.StatusOK, []byte("unexpected"), http.Header{"Content-Type": []string{"text/plain"}}), nil
			})}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil)
			targetURL, err := url.Parse("https://upstream.example" + tt.route.Path)
			if err != nil {
				t.Fatal(err)
			}
			res := textResponse(http.StatusFound, "", http.Header{"Location": []string{tt.location}})

			out, err := h.finishGeneralResponse(context.Background(), req, res, tt.node, tt.route, targetURL, targetURL, http.Header{}, tt.env, "", false, false, false)
			if err != nil {
				t.Fatalf("finishGeneralResponse() error = %v", err)
			}
			defer out.Body.Close()
			if out.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", out.StatusCode, http.StatusForbidden)
			}
			if rawCalls != 0 {
				t.Fatalf("raw direct calls = %d, want 0", rawCalls)
			}
		})
	}
}

func TestServeHTTPRewritesSystemInfoAddressesWithTargetPathPrefix(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	if err := store.SaveNode(ctx, "admin", storage.Node{
		Name:           "node",
		Secret:         "secret",
		Target:         "https://upstream.example/proxy",
		DirectExternal: false,
	}); err != nil {
		t.Fatal(err)
	}

	var upstreamRequestURL string
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamRequestURL = req.URL.String()
		return bytesResponse(http.StatusOK, []byte(`{"ServerName":"demo","Version":"4.9.3.0","WanAddress":"https://upstream.example","LocalAddress":"http://192.168.1.2:8096"}`), http.Header{
			"Content-Type": []string{"application/json"},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if upstreamRequestURL != "https://upstream.example/proxy/emby/System/Info/Public" {
		t.Fatalf("upstream request URL = %q", upstreamRequestURL)
	}
	if strings.Contains(rr.Body.String(), "upstream.example") || strings.Contains(rr.Body.String(), "192.168.1.2") {
		t.Fatalf("proxied system info leaked upstream address: %s", rr.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want := "https://proxy.example/node/secret"
	if payload["WanAddress"] != want || payload["LocalAddress"] != want {
		t.Fatalf("addresses = WanAddress %q, LocalAddress %q; want %q", payload["WanAddress"], payload["LocalAddress"], want)
	}
}

func TestDirectExternalPlaybackUsesObservedUpstreamResponse(t *testing.T) {
	tests := []struct {
		name            string
		requestURI      string
		wantUpstreamURL string
		rangeHeader     string
		upstream        *http.Response
		wantStatus      int
		wantLocation    string
		wantBody        string
		wantMode        string
	}{
		{
			name:            "video non redirect stays proxied",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
			rangeHeader:     "bytes=0-",
			upstream: bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
				"Accept-Ranges":  []string{"bytes"},
				"Content-Range":  []string{"bytes 0-4/5"},
				"Content-Type":   []string{"video/mp4"},
				"Content-Length": []string{"5"},
			}),
			wantStatus: http.StatusPartialContent,
			wantBody:   "video",
		},
		{
			name:            "video external redirect is forwarded",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
			upstream: textResponse(http.StatusFound, "", http.Header{
				"Location": []string{"http://cdn.example/video.mp4?sign=abc"},
			}),
			wantStatus:   http.StatusFound,
			wantLocation: "http://cdn.example/video.mp4?sign=abc",
			wantMode:     "direct",
		},
		{
			name:            "video same-host redirect is rewritten",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
			upstream: textResponse(http.StatusFound, "", http.Header{
				"Location": []string{"https://upstream.example/emby/Videos/2/stream.mp4?Static=true"},
			}),
			wantStatus:   http.StatusFound,
			wantLocation: "https://proxy.example/node/secret/emby/Videos/2/stream.mp4?Static=true",
			wantMode:     "proxy",
		},
		{
			name:            "smartstrm external redirect is forwarded",
			requestURI:      "https://proxy.example/node/secret/emby/smartstrm?item_id=1&media_id=2",
			wantUpstreamURL: "https://upstream.example/emby/smartstrm?item_id=1&media_id=2",
			upstream: textResponse(http.StatusFound, "", http.Header{
				"Location": []string{"http://cdn.example/smartstrm.mp4?sign=abc"},
			}),
			wantStatus:   http.StatusFound,
			wantLocation: "http://cdn.example/smartstrm.mp4?sign=abc",
			wantMode:     "direct",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamCalls := 0
			h := newProxyTestHandler(t, storage.Node{DirectExternal: true})
			h.playbackStreamProbeClient = noRedirectClient(func(req *http.Request) (*http.Response, error) {
				upstreamCalls++
				if req.URL.String() != tt.wantUpstreamURL {
					t.Fatalf("upstream request URL = %q, want %q", req.URL.String(), tt.wantUpstreamURL)
				}
				if tt.rangeHeader != "" && req.Header.Get("Range") != tt.rangeHeader {
					t.Fatalf("Range = %q, want %q", req.Header.Get("Range"), tt.rangeHeader)
				}
				return tt.upstream, nil
			})
			h.noRedirectClient = failRoundTripClient(t, "general no-redirect client should not be used for DirectExternal playback probe")
			h.defaultFollowClient = failRoundTripClient(t, "default follow client should not be used for DirectExternal playback probe")
			h.playbackActionClient = failRoundTripClient(t, "playback action client should not be used for DirectExternal playback probe")
			h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not be used for DirectExternal playback probe")
			h.rawDirectClient = failRoundTripClient(t, "raw direct client should not be used for DirectExternal playback response")

			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil)
			if tt.rangeHeader != "" {
				req.Header.Set("Range", tt.rangeHeader)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if got := rr.Header().Get("Location"); got != tt.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tt.wantLocation)
			}
			if tt.wantBody != "" && rr.Body.String() != tt.wantBody {
				t.Fatalf("body = %q, want %q", rr.Body.String(), tt.wantBody)
			}
			if tt.wantMode != "" {
				result := rr.Result()
				defer result.Body.Close()
				if mode := playbackRedirectMode(req, result); mode != tt.wantMode {
					t.Fatalf("playbackRedirectMode = %q, want %q", mode, tt.wantMode)
				}
			}
			if upstreamCalls != 1 {
				t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
			}
		})
	}
}

func TestSmartSTRMUsesPlaybackProxyWithoutWhitelist(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://upstream.example/emby/smartstrm?item_id=1&media_id=2" {
			t.Fatalf("upstream request URL = %q", req.URL.String())
		}
		return bytesResponse(http.StatusPartialContent, []byte("smartstrm-video"), http.Header{
			"Accept-Ranges": []string{"bytes"},
			"Content-Type":  []string{"video/mp4"},
		}), nil
	})}
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("raw client should not be used for /smartstrm playback proxy")
		return nil, nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/smartstrm?item_id=1&media_id=2", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if rr.Body.String() != "smartstrm-video" {
		t.Fatalf("body = %q, want smartstrm-video", rr.Body.String())
	}
}

func TestOriginalSTRMPathUsesPlaybackStreamProxy(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.playbackActionClient = failRoundTripClient(t, "original.strm should not be parsed as STRM source")
	h.noRedirectClient = failRoundTripClient(t, "general proxy should not handle original.strm playback")
	h.defaultFollowClient = failRoundTripClient(t, "default proxy should not handle original.strm playback")
	var upstreamRange string
	h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://upstream.example/emby/Videos/1/original.strm?MediaSourceId=ms1" {
			t.Fatalf("upstream request URL = %q", req.URL.String())
		}
		upstreamRange = req.Header.Get("Range")
		return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"5"},
			"Content-Range":  []string{"bytes 0-4/722182583"},
			"Content-Type":   []string{"video/x-matroska"},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Videos/1/original.strm?MediaSourceId=ms1", nil)
	req.Header.Set("Range", "bytes=0-")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if got := rr.Body.String(); got != "video" {
		t.Fatalf("body = %q, want video", got)
	}
	if upstreamRange != "bytes=0-" {
		t.Fatalf("upstream Range = %q, want bytes=0-", upstreamRange)
	}
}

func TestServeHTTPLogsPlaybackReadAndWriteBytes(t *testing.T) {
	tests := []struct {
		name            string
		requestURI      string
		wantUpstreamURL string
	}{
		{
			name:            "emby stream",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
		},
		{
			name:            "bare original stream",
			requestURI:      "https://proxy.example/node/secret/Videos/1/original.mkv?Static=true",
			wantUpstreamURL: "https://upstream.example/Videos/1/original.mkv?Static=true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newProxyTestHandler(t, storage.Node{})
			h.noRedirectClient = failRoundTripClient(t, "general no-redirect client should not handle playback streams")
			h.defaultFollowClient = failRoundTripClient(t, "default follow client should not handle playback streams")
			h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != tt.wantUpstreamURL {
					t.Fatalf("upstream request URL = %q, want %q", req.URL.String(), tt.wantUpstreamURL)
				}
				return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
					"Accept-Ranges":  []string{"bytes"},
					"Content-Length": []string{"4096"},
					"Content-Range":  []string{"bytes 0-4095/8192"},
					"Content-Type":   []string{"video/mp4"},
				}), nil
			})}

			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil)
			req.Header.Set("User-Agent", "actual-client")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusPartialContent {
				t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusPartialContent, rr.Body.String())
			}
			if rr.Body.String() != "video" {
				t.Fatalf("body = %q, want video", rr.Body.String())
			}

			ctx := context.Background()
			deadline := time.Now().Add(2 * time.Second)
			var seen bool
			var last storage.PlayStat
			for {
				stats, err := h.store.GetTodayStats(ctx)
				if err != nil {
					t.Fatalf("GetTodayStats() error = %v", err)
				}
				for _, row := range stats.Today {
					if row.Node == "node" && row.Client == "actual-client" {
						if row.Bytes != 10 || row.InboundBytes != 5 || row.OutboundBytes != 5 {
							seen = true
							last = row
							break
						}
						return
					}
				}
				if time.Now().After(deadline) {
					if seen {
						t.Fatalf("play_stats bytes = %d inbound = %d outbound = %d; want 10, 5, 5", last.Bytes, last.InboundBytes, last.OutboundBytes)
					}
					t.Fatalf("playback stat was not written")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestServeHTTPCountsPlaybackStartEvent(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.noRedirectClient = failRoundTripClient(t, "general no-redirect client should not handle playback start")
	h.defaultFollowClient = failRoundTripClient(t, "default follow client should not handle playback start")
	h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not handle playback start")
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", req.Method)
		}
		if req.URL.String() != "https://upstream.example/emby/Sessions/Playing" {
			t.Fatalf("upstream URL = %q", req.URL.String())
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read upstream body error = %v", err)
		}
		if string(raw) != `{"ItemId":"1","SessionId":"session-1","PlaySessionId":"play-session-1"}` {
			t.Fatalf("upstream body = %q", string(raw))
		}
		return textResponse(http.StatusNoContent, "", nil), nil
	})}

	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret/emby/Sessions/Playing", strings.NewReader(`{"ItemId":"1","SessionId":"session-1","PlaySessionId":"play-session-1"}`))
	req.Header.Set("User-Agent", "start-client")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		stats, err := h.store.GetTodayStats(context.Background())
		if err != nil {
			t.Fatalf("GetTodayStats() error = %v", err)
		}
		for _, row := range stats.Today {
			if row.Node == "node" && row.Client == "start-client" {
				if row.Plays != 1 || row.Sessions != 1 {
					t.Fatalf("play_stats = plays %d sessions %d; want 1, 1", row.Plays, row.Sessions)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("playback start stat was not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeHTTPDoesNotLogImageTrafficAsPlayback(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("image"), http.Header{"Content-Type": []string{"image/jpeg"}}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Items/1/Images/Primary", nil)
	req.Header.Set("User-Agent", "image-client")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		stats, err := h.store.GetTodayStats(context.Background())
		if err != nil {
			t.Fatalf("GetTodayStats() error = %v", err)
		}
		for _, row := range stats.Today {
			if row.Client == "image-client" {
				t.Fatalf("image request created playback stat: %+v", row)
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPlaybackRedirectModeClassifiesExternalLocations(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Videos/1/stream.mp4", nil)
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{name: "external absolute", location: "http://cdn.example/video.mp4", want: "direct"},
		{name: "proxy absolute", location: "https://proxy.example/node/secret/emby/Videos/1/stream.mp4", want: "proxy"},
		{name: "relative", location: "/node/secret/emby/Videos/1/stream.mp4", want: "proxy"},
		{name: "empty", location: "", want: "proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := textResponse(http.StatusFound, "", http.Header{"Location": []string{tt.location}})
			if got := playbackRedirectMode(req, res); got != tt.want {
				t.Fatalf("playbackRedirectMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleMediaProxyDoesNotCacheImageErrors(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusTooManyRequests, []byte("rate limited"), http.Header{
			"Cache-Control": []string{"public, max-age=60"},
			"Content-Type":  []string{"text/html; charset=UTF-8"},
		}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary", nil)
	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, targetURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestHandleMediaProxySkipsImageCacheWhenDisabled(t *testing.T) {
	store := newProxyTestStore(t)
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	upstreamCalls := 0
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		return bytesResponse(http.StatusOK, []byte("image"), http.Header{"Content-Type": []string{"image/jpeg"}}), nil
	})}

	var lastCtx context.Context
	for i := 0; i < 2; i++ {
		reqCtx := WithAccessLogFields(context.Background())
		lastCtx = reqCtx
		req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=disabled", nil).WithContext(reqCtx)
		targetURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=disabled")
		if err != nil {
			t.Fatal(err)
		}
		res, err := h.handleMediaProxy(reqCtx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, targetURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
		if err != nil {
			t.Fatalf("handleMediaProxy() error = %v", err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
	if upstreamCalls != 2 {
		t.Fatalf("upstream calls = %d, want 2", upstreamCalls)
	}
	if got := AccessLogFields(lastCtx)["imageCache"]; got != "disabled" {
		t.Fatalf("imageCache log field = %v, want disabled", got)
	}
}

func TestTrafficCaptureRecordsImageCacheWaitFailureTarget(t *testing.T) {
	cwd := t.TempDir()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures-test.jsonl"
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: cwd}, store, nil, logging.New("silent", false))
	h.imageFollowClient = failRoundTripClient(t, "upstream should not be called while an image fill is in progress")

	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=wait")
	if err != nil {
		t.Fatal(err)
	}
	imageCache := h.ensureImageCache(context.Background())
	fill, leader := imageCache.beginFill(imageCacheKey("node", targetURL))
	if !leader {
		t.Fatal("test image fill should be the leader")
	}
	defer imageCache.finishFill(fill)

	reqCtx, cancel := context.WithCancel(WithAccessLogFields(context.Background()))
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Items/1/Images/Primary?tag=wait", nil).WithContext(reqCtx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
	rr := httptest.NewRecorder()
	recorder.Middleware(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	records, err := capture.ReadJSONL(filepath.Join(cwd, sys.TrafficCaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if record.Stage != "image-cache-wait" {
		t.Fatalf("stage = %q, want image-cache-wait", record.Stage)
	}
	if record.TargetURL != targetURL.String() {
		t.Fatalf("targetUrl = %q, want %q", record.TargetURL, targetURL.String())
	}
	meta, ok := record.Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %T, want map", record.Meta)
	}
	if got := meta["errorClass"]; got != "context-canceled" {
		t.Fatalf("errorClass = %v, want context-canceled", got)
	}
	if got := meta["errorStage"]; got != "image-cache-wait" {
		t.Fatalf("errorStage = %v, want image-cache-wait", got)
	}
	if _, ok := meta["targetAttemptMs"]; !ok {
		t.Fatal("targetAttemptMs missing from meta")
	}
}

func TestHandleMediaProxyServesImageCacheHitBeforeLimiter(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.ImageProxyLimitEnabled = true
	sys.ImageProxyMaxConcurrent = 1
	sys.ImageProxyRequestIntervalMS = 0
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	upstreamCalls := 0
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		if upstreamCalls > 1 {
			return nil, errors.New("unexpected upstream request")
		}
		return bytesResponse(http.StatusOK, []byte("cached-image"), http.Header{
			"Content-Type": []string{"image/jpeg"},
			"ETag":         []string{`"image-v1"`},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=a", nil)
	targetURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=a")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, targetURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() first error = %v", err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "cached-image" {
		t.Fatalf("first body = %q", body)
	}
	if got := AccessLogFields(ctx)["imageCache"]; got != "miss" {
		t.Fatalf("first imageCache log field = %v, want miss", got)
	}
	release, err := h.acquireImageRequestSlot(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	hitBaseCtx := WithAccessLogFields(context.Background())
	hitCtx, cancel := context.WithTimeout(hitBaseCtx, 25*time.Millisecond)
	defer cancel()
	req = httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=a", nil).WithContext(hitCtx)
	targetURL, err = url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=a")
	if err != nil {
		t.Fatal(err)
	}
	res, err = h.handleMediaProxy(hitCtx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, targetURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() cache hit error = %v", err)
	}
	body, err = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "cached-image" {
		t.Fatalf("cache hit body = %q", body)
	}
	if got := AccessLogFields(hitCtx)["imageCache"]; got != "hit" {
		t.Fatalf("cache hit imageCache log field = %v, want hit", got)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
}

func TestHandleMediaProxyCoalescesConcurrentImageCacheMisses(t *testing.T) {
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	var upstreamMu sync.Mutex
	upstreamCalls := 0
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamMu.Lock()
		upstreamCalls++
		upstreamMu.Unlock()
		time.Sleep(100 * time.Millisecond)
		return bytesResponse(http.StatusOK, []byte("coalesced-image"), http.Header{
			"Content-Type": []string{"image/jpeg"},
			"ETag":         []string{`"coalesced-v1"`},
		}), nil
	})}

	const requestCount = 8
	start := make(chan struct{})
	errs := make(chan error, requestCount)
	var wg sync.WaitGroup
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reqCtx, cancel := context.WithTimeout(WithAccessLogFields(context.Background()), 2*time.Second)
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=coalesced", nil).WithContext(reqCtx)
			targetURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=coalesced")
			if err != nil {
				errs <- err
				return
			}
			res, err := h.handleMediaProxy(reqCtx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, targetURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if err != nil {
				errs <- err
				return
			}
			if string(body) != "coalesced-image" {
				errs <- fmt.Errorf("body = %q, want coalesced-image", body)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	upstreamMu.Lock()
	gotCalls := upstreamCalls
	upstreamMu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", gotCalls)
	}
}

func TestSetLastResponseClosesReplacedResponse(t *testing.T) {
	h := &Handler{}
	firstBody := newTrackedBody("first")
	secondBody := newTrackedBody("second")
	first := &http.Response{Body: firstBody}
	second := &http.Response{Body: secondBody}

	var last *http.Response
	h.setLastResponse(&last, first)
	if last != first {
		t.Fatal("first response was not stored")
	}
	if firstBody.closed {
		t.Fatal("stored response body was closed")
	}

	h.setLastResponse(&last, second)
	if last != second {
		t.Fatal("second response was not stored")
	}
	if !firstBody.closed {
		t.Fatal("replaced response body was not closed")
	}
	if secondBody.closed {
		t.Fatal("replacement response body was closed")
	}
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

var clientIPHeaderKeys = []string{
	"Remote-Host",
	"X-Forwarded-For",
	"CF-Connecting-IP",
	"X-Remote-Addr",
	"CloudFront-Viewer-Address",
	"X-Azure-ClientIP",
	"X-Envoy-External-Address",
	"X-Original-Forwarded-For",
	"Proxy-Client-IP",
	"Ali-Cdn-Real-IP",
	"Ali-Real-Client-IP",
	"Client-Real-IP",
	"X-Client-Real-IP",
}

func setClientIPHeaders(req *http.Request) {
	for _, key := range clientIPHeaderKeys {
		req.Header.Set(key, "203.0.113.10")
	}
}

func assertAccessLogRangeFields(t *testing.T, ctx context.Context, wantRange, wantContentRange string) {
	t.Helper()
	fields := AccessLogFields(ctx)
	if got := fields["range"]; got != wantRange {
		t.Fatalf("range access log field = %v, want %s", got, wantRange)
	}
	if got := fields["contentRange"]; got != wantContentRange {
		t.Fatalf("contentRange access log field = %v, want %s", got, wantContentRange)
	}
}

func assertHillsOutboundIdentityApplied(t *testing.T, ids *identity.Manager, req *http.Request, profile, token string) {
	t.Helper()
	if req == nil || req.URL == nil {
		t.Fatal("request URL is nil")
	}
	assertHillsOutboundQueryIdentityApplied(t, ids, req, profile, token)
	assertHillsOutboundHeaderIdentityApplied(t, ids, req, profile, token)
}

func assertHillsOutboundQueryIdentityApplied(t *testing.T, ids *identity.Manager, req *http.Request, profile, token string) {
	t.Helper()
	if req == nil || req.URL == nil {
		t.Fatal("request URL is nil")
	}
	snap := ids.Snapshot(profile)
	query := req.URL.Query()
	if got := query.Get("X-Emby-Language"); got != "zh-cn" {
		t.Fatalf("X-Emby-Language query = %q, want zh-cn; raw query: %s", got, req.URL.RawQuery)
	}
	if got := query.Get("X-Emby-Token"); got != token {
		t.Fatalf("X-Emby-Token query = %q, want %q; raw query: %s", got, token, req.URL.RawQuery)
	}
	if got := query.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="`+snap.ClientName+`"`) {
		t.Fatalf("X-Emby-Authorization query = %q, want Hills identity", got)
	}
	if query.Has("x_emby_device_id") || query.Has("X_Emby_Device_Id") || query.Has("X_MediaBrowser_Client") {
		t.Fatalf("legacy identity query was not removed: %s", req.URL.RawQuery)
	}
}

func assertHillsIdentityQueryAbsent(t *testing.T, req *http.Request) {
	t.Helper()
	if req == nil || req.URL == nil {
		t.Fatal("request URL is nil")
	}
	query := req.URL.Query()
	for _, key := range []string{
		"X-Emby-Authorization", "X-Emby-Client", "X-Emby-Client-Version",
		"X-Emby-Device-Name", "X-Emby-Device-Id", "X-Emby-Language", "X-Emby-Token",
		"x_emby_device_id", "X_Emby_Device_Id", "X_MediaBrowser_Client",
	} {
		if query.Has(key) {
			t.Fatalf("%s query = %q, want absent; raw query: %s", key, query.Get(key), req.URL.RawQuery)
		}
	}
}

func assertHillsOutboundHeaderIdentityApplied(t *testing.T, ids *identity.Manager, req *http.Request, profile, token string) {
	t.Helper()
	if req == nil {
		t.Fatal("request is nil")
	}
	snap := ids.Snapshot(profile)
	if got := req.Header.Get("User-Agent"); got != snap.UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, snap.UserAgent)
	}
	if got := req.Header.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="`+snap.ClientName+`"`) {
		t.Fatalf("X-Emby-Authorization header = %q, want Hills identity", got)
	}
	if got := req.Header.Get("X-Emby-Client"); got != snap.ClientName {
		t.Fatalf("X-Emby-Client header = %q, want %q", got, snap.ClientName)
	}
	if got := req.Header.Get("X-Emby-Token"); got != token {
		t.Fatalf("X-Emby-Token header = %q, want %q", got, token)
	}
	assertHeadersAbsent(t, req.Header,
		"Authorization", "X-Authorization",
		"X-MediaBrowser-Client",
	)
}

func assertHeadersAbsent(t *testing.T, headers http.Header, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s was forwarded as %q", key, got)
		}
	}
}
