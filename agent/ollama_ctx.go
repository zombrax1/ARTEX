package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Ollama's OpenAI-compatible endpoint (/v1/chat/completions) has no field for
// the context size: it runs every request with the model's own num_ctx, or the
// server default, which is 4096 tokens on a GPU under 24 GB. ARTEX prompts
// (system prompt, tool schemas, history) are far bigger than that, and Ollama
// drops the oldest messages to fit without reporting an error. The profile's
// "Context window" was used only for ARTEX's own compaction math, so a 32K
// profile on a 16 GB card really ran at 4K.
//
// A model's own num_ctx is the one setting the /v1 endpoint honours. So for an
// Ollama profile with an explicit context window, ARTEX asks Ollama once to
// create a light variant of the model with that num_ctx (POST /api/create with
// "from"; it reuses the base model's weights, nothing is copied), and sends the
// profile's requests to the variant. The variant shows in `ollama list` as
// "<model>:<tag>-artex-ctx<N>k" and can be removed with `ollama rm`.
//
// Only Ollama profiles with a context window set are affected. If the server
// refuses the create call (an older Ollama, or a gateway in front of it),
// requests go to the base model unchanged and ARTEX retries later.

// ollamaCtxRetryAfter is how long a failed variant create is remembered before
// the next request tries again.
const ollamaCtxRetryAfter = 5 * time.Minute

// ollamaCtxCreateTimeout bounds the create call. Creating from a local model
// only writes a small manifest, so this is generous.
const ollamaCtxCreateTimeout = 60 * time.Second

// ollamaNumCtx returns the num_ctx ARTEX asks Ollama for, in tokens. It never
// goes below the compaction floor: compaction assumes at least minWindowK, and
// a smaller real window would truncate before compaction ever runs.
func ollamaNumCtx(windowK int) int {
	if windowK < minWindowK {
		windowK = minWindowK
	}
	if windowK > maxWindowK {
		windowK = maxWindowK
	}
	return windowK * 1024
}

// ollamaContextVariant names the variant of model with the given num_ctx. The
// suffix goes on the tag ("qwen3:14b" -> "qwen3:14b-artex-ctx32k"; no tag means
// "latest"), so the variant sorts next to its base model in `ollama list`.
func ollamaContextVariant(model string, numCtx int) string {
	model = strings.TrimSpace(model)
	name, tag := model, "latest"
	if i := strings.LastIndex(model, ":"); i > strings.LastIndex(model, "/") {
		name, tag = model[:i], model[i+1:]
	}
	return fmt.Sprintf("%s:%s-artex-ctx%dk", name, tag, numCtx/1024)
}

// ollamaAPIRoot turns the profile's /v1 base URL into the server root that
// serves Ollama's native API. ok is false when the URL does not end in /v1,
// which means it is not a plain Ollama server.
func ollamaAPIRoot(baseURL string) (string, bool) {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if !strings.HasSuffix(b, "/v1") {
		return "", false
	}
	return strings.TrimSuffix(b, "/v1"), true
}

// ollamaVariantState remembers, per server and variant, whether the variant
// exists. It is process-wide so provider rebuilds (a profile save, a task
// start) do not create the variant again.
type ollamaVariantState struct {
	mu       sync.Mutex // held while creating, so concurrent first requests wait
	ready    bool
	failedAt time.Time
}

var (
	ollamaVariantsMu sync.Mutex
	ollamaVariants   = map[string]*ollamaVariantState{}
)

func ollamaVariantFor(key string) *ollamaVariantState {
	ollamaVariantsMu.Lock()
	defer ollamaVariantsMu.Unlock()
	st := ollamaVariants[key]
	if st == nil {
		st = &ollamaVariantState{}
		ollamaVariants[key] = st
	}
	return st
}

// ollamaContextTransport points chat requests for model at its num_ctx variant,
// creating the variant on first use.
type ollamaContextTransport struct {
	base    http.RoundTripper
	apiRoot string
	model   string
	variant string
	numCtx  int
	now     func() time.Time // tests
}

func newOllamaContextTransport(base http.RoundTripper, baseURL, model string, windowK int) (*ollamaContextTransport, bool) {
	if windowK <= 0 || strings.TrimSpace(model) == "" {
		return nil, false
	}
	root, ok := ollamaAPIRoot(baseURL)
	if !ok {
		return nil, false
	}
	n := ollamaNumCtx(windowK)
	return &ollamaContextTransport{
		base:    base,
		apiRoot: root,
		model:   strings.TrimSpace(model),
		variant: ollamaContextVariant(model, n),
		numCtx:  n,
		now:     time.Now,
	}, true
}

func (t *ollamaContextTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/chat/completions") || req.Body == nil {
		return t.base.RoundTrip(req)
	}
	if !t.ensureVariant(req.Context(), req.Header.Get("Authorization")) {
		return t.base.RoundTrip(req)
	}
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	out := req.Clone(req.Context())
	if rewritten, ok := rewriteRequestModel(body, t.model, t.variant); ok {
		body = rewritten
	}
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return t.base.RoundTrip(out)
}

// rewriteRequestModel swaps the top-level "model" of a JSON request body from
// `from` to `to`. Any other model name (or a body that is not a JSON object) is
// left alone.
func rewriteRequestModel(body []byte, from, to string) ([]byte, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, false
	}
	var model string
	if err := json.Unmarshal(m["model"], &model); err != nil || strings.TrimSpace(model) != from {
		return nil, false
	}
	enc, err := json.Marshal(to)
	if err != nil {
		return nil, false
	}
	m["model"] = enc
	out, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return out, true
}

// ensureVariant reports whether the variant exists, creating it if needed. A
// failure is remembered for ollamaCtxRetryAfter so a server that cannot create
// models is not asked on every request.
//
// auth is the Authorization header of the chat request that triggered it, so a
// server behind an authenticating proxy accepts the create call too.
func (t *ollamaContextTransport) ensureVariant(ctx context.Context, auth string) bool {
	st := ollamaVariantFor(t.apiRoot + "|" + t.variant)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.ready {
		return true
	}
	if !st.failedAt.IsZero() && t.now().Sub(st.failedAt) < ollamaCtxRetryAfter {
		return false
	}
	if err := t.createVariant(ctx, auth); err != nil {
		st.failedAt = t.now()
		log.Printf("[llm] ollama: could not create %q with num_ctx=%d, using %q at the server's default context (retry in %s): %v",
			t.variant, t.numCtx, t.model, ollamaCtxRetryAfter, err)
		return false
	}
	st.ready = true
	st.failedAt = time.Time{}
	log.Printf("[llm] ollama: using %q (%q with num_ctx=%d)", t.variant, t.model, t.numCtx)
	return true
}

func (t *ollamaContextTransport) createVariant(ctx context.Context, auth string) error {
	payload, err := json.Marshal(map[string]any{
		"model":      t.variant,
		"from":       t.model,
		"parameters": map[string]any{"num_ctx": t.numCtx},
		"stream":     false,
	})
	if err != nil {
		return err
	}
	// Detach from the triggering request's cancellation: the variant is shared,
	// and a create cut off halfway helps no one. The timeout still bounds it.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ollamaCtxCreateTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, t.apiRoot+"/api/create", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /api/create: HTTP %d: %s", resp.StatusCode, oneLine(string(msg)))
	}
	var r struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(msg, &r) == nil && r.Error != "" {
		return fmt.Errorf("POST /api/create: %s", oneLine(r.Error))
	}
	return nil
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(s))
}
