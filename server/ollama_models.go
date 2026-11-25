package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// OllamaModelInfo is what the model picker shows next to an Ollama model, read
// from the server's native API. Tools is nil when the server does not say (an
// Ollama too old to report capabilities and a template that gives no hint).
type OllamaModelInfo struct {
	Tools         *bool  `json:"tools,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	ParameterSize string `json:"parameter_size,omitempty"`
	Quantization  string `json:"quantization,omitempty"`
	ContextLength int    `json:"context_length,omitempty"` // the model's trained maximum
}

// ollamaShowLimit caps how many models get a per-model /api/show call, and
// ollamaShowParallel how many run at once against the local server.
const (
	ollamaShowLimit    = 200
	ollamaShowParallel = 4
)

// ollamaModelDetails enriches a model list from an Ollama server's native API:
// sizes and quantization from GET /api/tags, tool support and context length
// from POST /api/show. ARTEX agents work only through tool calls, so a model
// without tool support cannot run a task. Every failure is soft: a model the
// server says nothing about is simply absent from the map.
//
// root is the server root (the /v1 base without /v1). validate, when non-nil,
// checks each URL before it is fetched (the caller's SSRF guard).
func ollamaModelDetails(ctx context.Context, client *http.Client, root string, hdr http.Header, models []string, validate func(string) error) map[string]OllamaModelInfo {
	out := make(map[string]OllamaModelInfo, len(models))
	if len(models) == 0 {
		return out
	}
	want := make(map[string]bool, len(models))
	for _, m := range models {
		want[m] = true
	}
	var mu sync.Mutex
	set := func(name string, f func(*OllamaModelInfo)) {
		mu.Lock()
		defer mu.Unlock()
		info := out[name]
		f(&info)
		out[name] = info
	}

	tagsURL, showURL := root+"/api/tags", root+"/api/show"
	if validate != nil {
		if validate(tagsURL) != nil || validate(showURL) != nil {
			return out
		}
	}

	// Sizes for every model in one call.
	var tags struct {
		Models []struct {
			Name    string `json:"name"`
			Model   string `json:"model"`
			Size    int64  `json:"size"`
			Details struct {
				ParameterSize     string `json:"parameter_size"`
				QuantizationLevel string `json:"quantization_level"`
			} `json:"details"`
		} `json:"models"`
	}
	if body, ok := ollamaFetch(ctx, client, http.MethodGet, tagsURL, hdr, nil); ok && json.Unmarshal(body, &tags) == nil {
		for _, t := range tags.Models {
			name := t.Name
			if !want[name] && want[t.Model] {
				name = t.Model
			}
			if !want[name] {
				continue
			}
			set(name, func(i *OllamaModelInfo) {
				i.SizeBytes = t.Size
				i.ParameterSize = t.Details.ParameterSize
				i.Quantization = t.Details.QuantizationLevel
			})
		}
	}

	// Capabilities one model at a time, a few in parallel.
	list := models
	if len(list) > ollamaShowLimit {
		list = list[:ollamaShowLimit]
	}
	sem := make(chan struct{}, ollamaShowParallel)
	var wg sync.WaitGroup
	for _, name := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			payload, _ := json.Marshal(map[string]string{"model": name})
			body, ok := ollamaFetch(ctx, client, http.MethodPost, showURL, hdr, payload)
			if !ok {
				return
			}
			tools, ctxLen, ok := parseOllamaShow(body)
			if !ok || (tools == nil && ctxLen == 0) {
				return
			}
			set(name, func(i *OllamaModelInfo) {
				i.Tools = tools
				i.ContextLength = ctxLen
			})
		}(name)
	}
	wg.Wait()
	return out
}

// parseOllamaShow reads tool support and the trained context length from an
// /api/show response. Newer servers list "tools" in capabilities; for older ones
// a chat template that references .Tools is the same signal.
func parseOllamaShow(body []byte) (tools *bool, contextLength int, ok bool) {
	var show struct {
		Capabilities []string                   `json:"capabilities"`
		Template     string                     `json:"template"`
		ModelInfo    map[string]json.RawMessage `json:"model_info"`
	}
	if json.Unmarshal(body, &show) != nil {
		return nil, 0, false
	}
	switch {
	case len(show.Capabilities) > 0:
		v := false
		for _, c := range show.Capabilities {
			if c == "tools" {
				v = true
			}
		}
		tools = &v
	case show.Template != "":
		v := strings.Contains(show.Template, ".Tools")
		tools = &v
	}
	for k, raw := range show.ModelInfo {
		if strings.HasSuffix(k, ".context_length") {
			var n int
			if json.Unmarshal(raw, &n) == nil && n > 0 {
				contextLength = n
			}
		}
	}
	return tools, contextLength, true
}

func ollamaFetch(ctx context.Context, client *http.Client, method, u string, hdr http.Header, payload []byte) ([]byte, bool) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, false
	}
	req.Header = hdr.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, false
	}
	return data, true
}
