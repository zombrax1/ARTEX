// Package apidef imports API definitions (OpenAPI 3, Swagger 2 and Postman
// collections v2.x) into a flat list of operations, and matches observed requests
// against them so a task can show which operations were exercised.
package apidef

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits keep an import bounded: a definition is read into memory whole.
const (
	MaxBytes      = 10 << 20
	MaxOperations = 5000
	maxParams     = 100
)

// Formats.
const (
	FormatOpenAPI = "openapi"
	FormatSwagger = "swagger"
	FormatPostman = "postman"
)

// Param is one input of an operation.
type Param struct {
	Name     string `json:"name"`
	In       string `json:"in"` // path | query | header | cookie | body | form
	Required bool   `json:"required,omitempty"`
	Type     string `json:"type,omitempty"`
}

// Operation is one method on one path.
type Operation struct {
	Method      string  `json:"method"`
	Path        string  `json:"path"`     // template, e.g. /users/{id}
	BaseURL     string  `json:"base_url"` // scheme://host[/base], or "" when the definition has none
	OperationID string  `json:"operation_id,omitempty"`
	Summary     string  `json:"summary,omitempty"`
	Params      []Param `json:"params"`
	Auth        bool    `json:"auth"` // the definition requires authentication for it
}

// Definition is a parsed API definition.
type Definition struct {
	Format     string      `json:"format"`
	Title      string      `json:"title"`
	BaseURL    string      `json:"base_url"`
	Operations []Operation `json:"operations"`
}

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Parse detects the format of data (JSON or YAML) and parses it.
func Parse(data []byte) (*Definition, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("the definition is larger than %d MB", MaxBytes>>20)
	}
	doc, err := decode(data)
	if err != nil {
		return nil, err
	}
	var def *Definition
	switch {
	case str(doc["openapi"]) != "":
		def, err = parseOpenAPI(doc, false)
	case str(doc["swagger"]) != "":
		def, err = parseOpenAPI(doc, true)
	case isPostman(doc):
		def, err = parsePostman(doc)
	default:
		return nil, errors.New("not an OpenAPI 3, Swagger 2 or Postman v2 collection: no openapi, swagger or info.schema field")
	}
	if err != nil {
		return nil, err
	}
	if len(def.Operations) == 0 {
		return nil, errors.New("the definition contains no operations")
	}
	if len(def.Operations) > MaxOperations {
		return nil, fmt.Errorf("the definition has %d operations, more than the limit of %d", len(def.Operations), MaxOperations)
	}
	sort.SliceStable(def.Operations, func(i, j int) bool {
		a, b := def.Operations[i], def.Operations[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return methodRank(a.Method) < methodRank(b.Method)
	})
	return def, nil
}

func methodRank(m string) int {
	for i, x := range methods {
		if strings.EqualFold(x, m) {
			return i
		}
	}
	return len(methods)
}

func decode(data []byte) (map[string]any, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var doc map[string]any
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		return doc, nil
	}
	var y any
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, fmt.Errorf("neither JSON nor YAML: %w", err)
	}
	m, ok := normalizeYAML(y).(map[string]any)
	if !ok {
		return nil, errors.New("the document is not an object")
	}
	return m, nil
}

// normalizeYAML converts yaml.v3 output into JSON-shaped values.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalizeYAML(e)
		}
		return x
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[fmt.Sprint(k)] = normalizeYAML(e)
		}
		return m
	case []any:
		for i, e := range x {
			x[i] = normalizeYAML(e)
		}
		return x
	}
	return v
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64, int, bool:
		return fmt.Sprint(x)
	}
	return ""
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }

// ---------------- OpenAPI 3 / Swagger 2 ----------------

type oaParser struct {
	root    map[string]any
	swagger bool
	// budget is the schema nodes one top-level traversal may still visit: a
	// schema whose allOf lists itself several times branches exponentially
	// within the depth limit.
	budget int
	// path holds the $refs on the current traversal path; a reference back
	// to one of them is a cycle and is not followed again.
	path map[string]bool
}

// maxSchemaNodes bounds the work of one top-level schema traversal.
const maxSchemaNodes = 2000

// enter starts visiting a schema node: false when the work budget is spent
// or the node's $ref is already on the traversal path. leave undoes it.
func (p *oaParser) enter(s map[string]any) (ref string, ok bool) {
	p.budget--
	if p.budget < 0 {
		return "", false
	}
	ref = str(s["$ref"])
	if ref == "" {
		return "", true
	}
	if p.path[ref] {
		return "", false
	}
	if p.path == nil {
		p.path = map[string]bool{}
	}
	p.path[ref] = true
	return ref, true
}

func (p *oaParser) leave(ref string) {
	if ref != "" {
		delete(p.path, ref)
	}
}

// resolve follows a local $ref (#/a/b/c) up to a few levels.
func (p *oaParser) resolve(v map[string]any) map[string]any {
	for i := 0; i < 8 && v != nil; i++ {
		ref := str(v["$ref"])
		if ref == "" {
			return v
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil // external references are not followed
		}
		var cur any = p.root
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			cur = obj(cur)[part]
		}
		v = obj(cur)
	}
	return v
}

// maxSchemaDepth bounds schema traversal: a schema may reference itself
// (directly, through allOf or through items), and each step resolves its
// $ref afresh.
const maxSchemaDepth = 8

func (p *oaParser) schemaType(s map[string]any) string {
	p.budget, p.path = maxSchemaNodes, nil
	return p.schemaTypeAt(s, 0)
}

func (p *oaParser) schemaTypeAt(s map[string]any, depth int) string {
	ref, ok := p.enter(s)
	if !ok {
		return ""
	}
	defer p.leave(ref)
	s = p.resolve(s)
	if s == nil || depth > maxSchemaDepth {
		return ""
	}
	t := str(s["type"])
	if t == "" {
		if ts := arr(s["type"]); len(ts) > 0 {
			t = str(ts[0])
		}
	}
	if t == "array" {
		if it := p.schemaTypeAt(obj(s["items"]), depth+1); it != "" {
			return "array<" + it + ">"
		}
	}
	if f := str(s["format"]); f != "" && t != "" {
		return t + "(" + f + ")"
	}
	return t
}

// bodyParams lists the top-level properties of a request body schema.
func (p *oaParser) bodyParams(schema map[string]any, in string) []Param {
	p.budget, p.path = maxSchemaNodes, nil
	return p.bodyParamsAt(schema, in, 0)
}

func (p *oaParser) bodyParamsAt(schema map[string]any, in string, depth int) []Param {
	ref, ok := p.enter(schema)
	if !ok {
		return nil
	}
	defer p.leave(ref)
	schema = p.resolve(schema)
	if schema == nil || depth > maxSchemaDepth {
		return nil
	}
	var composed []Param
	all := arr(schema["allOf"])
	for _, s := range all {
		composed = append(composed, p.bodyParamsAt(obj(s), in, depth+1)...)
		if len(composed) > maxParams {
			return composed[:maxParams]
		}
	}
	props := obj(schema["properties"])
	if len(all) > 0 {
		// The schema's own properties and required list sit beside allOf.
		return p.mergeOwnParams(composed, schema, props, in, depth)
	}
	if len(props) == 0 {
		if t := p.schemaTypeAt(schema, depth+1); t != "" {
			return []Param{{Name: "(body)", In: in, Type: t}}
		}
		return nil
	}
	req := map[string]bool{}
	for _, r := range arr(schema["required"]) {
		req[str(r)] = true
	}
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]Param, 0, len(names))
	for _, k := range names {
		out = append(out, Param{Name: k, In: in, Required: req[k], Type: p.schemaTypeAt(obj(props[k]), depth+1)})
	}
	return out
}

// mergeOwnParams adds a schema's own properties to the parameters its allOf
// composed, and marks the fields its required list names.
func (p *oaParser) mergeOwnParams(out []Param, schema, props map[string]any, in string, depth int) []Param {
	req := map[string]bool{}
	for _, r := range arr(schema["required"]) {
		req[str(r)] = true
	}
	seen := map[string]int{}
	for i, prm := range out {
		seen[prm.Name] = i
		if req[prm.Name] {
			out[i].Required = true
		}
	}
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		prm := Param{Name: k, In: in, Required: req[k], Type: p.schemaTypeAt(obj(props[k]), depth+1)}
		if i, ok := seen[k]; ok {
			prm.Required = prm.Required || out[i].Required
			out[i] = prm
			continue
		}
		if len(out) >= maxParams {
			break
		}
		seen[k] = len(out)
		out = append(out, prm)
	}
	return out
}

func (p *oaParser) params(list []any) []Param {
	var out []Param
	for _, raw := range list {
		prm := p.resolve(obj(raw))
		if prm == nil {
			continue
		}
		in := str(prm["in"])
		switch in {
		case "body": // Swagger 2
			out = append(out, p.bodyParams(obj(prm["schema"]), "body")...)
			continue
		case "formData":
			in = "form"
		}
		t := str(prm["type"])
		if s := obj(prm["schema"]); s != nil {
			t = p.schemaType(s)
		}
		req, _ := prm["required"].(bool)
		out = append(out, Param{Name: str(prm["name"]), In: in, Required: req || in == "path", Type: t})
	}
	return out
}

func mergeParams(base, over []Param) []Param {
	key := func(x Param) string { return x.In + "\x00" + x.Name }
	idx := map[string]int{}
	out := append([]Param(nil), base...)
	for i, x := range out {
		idx[key(x)] = i
	}
	for _, x := range over {
		if i, ok := idx[key(x)]; ok {
			out[i] = x
			continue
		}
		idx[key(x)] = len(out)
		out = append(out, x)
	}
	if len(out) > maxParams {
		out = out[:maxParams]
	}
	return out
}

func (p *oaParser) baseURL() string {
	if p.swagger {
		host := str(p.root["host"])
		base := strings.TrimRight(str(p.root["basePath"]), "/")
		if host == "" {
			return base
		}
		scheme := "https"
		if ss := arr(p.root["schemes"]); len(ss) > 0 {
			scheme = str(ss[0])
			for _, s := range ss {
				if str(s) == "https" {
					scheme = "https"
				}
			}
		}
		return scheme + "://" + host + base
	}
	return serverURL(arr(p.root["servers"]))
}

// requiresAuth reports whether an OpenAPI security list demands credentials: it
// is not empty and has no {} entry, which allows anonymous access.
func requiresAuth(security []any) bool {
	for _, s := range security {
		if len(obj(s)) == 0 {
			return false
		}
	}
	return len(security) > 0
}

// serverURL is the first server of an OpenAPI servers list, with its variables
// set to their defaults, or "" for an empty list.
func serverURL(servers []any) string {
	if len(servers) == 0 {
		return ""
	}
	s := obj(servers[0])
	u := str(s["url"])
	for name, v := range obj(s["variables"]) {
		u = strings.ReplaceAll(u, "{"+name+"}", str(obj(v)["default"]))
	}
	return strings.TrimRight(u, "/")
}

func parseOpenAPI(root map[string]any, swagger bool) (*Definition, error) {
	p := &oaParser{root: root, swagger: swagger}
	def := &Definition{Format: FormatOpenAPI, Title: str(obj(root["info"])["title"]), BaseURL: p.baseURL()}
	if swagger {
		def.Format = FormatSwagger
	}
	globalAuth := requiresAuth(arr(root["security"]))
	paths := obj(root["paths"])
	if paths == nil {
		return nil, errors.New("the definition has no paths")
	}
	names := make([]string, 0, len(paths))
	for k := range paths {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, path := range names {
		item := p.resolve(obj(paths[path]))
		if item == nil {
			continue
		}
		shared := p.params(arr(item["parameters"]))
		// OpenAPI 3 servers: operation, then path item, then the root.
		itemBase := def.BaseURL
		if !swagger {
			if u := serverURL(arr(item["servers"])); u != "" {
				itemBase = u
			}
		}
		for _, m := range methods {
			op := obj(item[m])
			if op == nil {
				continue
			}
			params := mergeParams(shared, p.params(arr(op["parameters"])))
			if !swagger {
				if rb := p.resolve(obj(op["requestBody"])); rb != nil {
					content := obj(rb["content"])
					var chosen map[string]any
					in := "body"
					for _, ct := range []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"} {
						if c := obj(content[ct]); c != nil {
							chosen = c
							if ct != "application/json" {
								in = "form"
							}
							break
						}
					}
					if chosen == nil {
						for _, c := range content {
							chosen = obj(c)
							break
						}
					}
					if chosen != nil {
						params = mergeParams(params, p.bodyParams(obj(chosen["schema"]), in))
					}
				}
			}
			auth := globalAuth
			if sec, ok := op["security"]; ok {
				auth = requiresAuth(arr(sec))
			}
			if params == nil {
				params = []Param{}
			}
			base := itemBase
			if !swagger {
				if u := serverURL(arr(op["servers"])); u != "" {
					base = u
				}
			}
			def.Operations = append(def.Operations, Operation{
				Method: strings.ToUpper(m), Path: path, BaseURL: base,
				OperationID: str(op["operationId"]), Summary: firstLine(str(op["summary"]), str(op["description"])),
				Params: params, Auth: auth,
			})
			if len(def.Operations) > MaxOperations {
				return def, nil
			}
		}
	}
	return def, nil
}

func firstLine(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if i := strings.IndexByte(v, '\n'); i >= 0 {
			v = v[:i]
		}
		if len(v) > 200 {
			v = v[:200]
		}
		return v
	}
	return ""
}

// ---------------- Postman ----------------

func isPostman(doc map[string]any) bool {
	schema := str(obj(doc["info"])["schema"])
	return strings.Contains(schema, "schema.getpostman.com") || (obj(doc["info"])["_postman_id"] != nil && doc["item"] != nil)
}

var postmanVar = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

func parsePostman(doc map[string]any) (*Definition, error) {
	def := &Definition{Format: FormatPostman, Title: str(obj(doc["info"])["name"])}
	vars := map[string]string{}
	for _, v := range arr(doc["variable"]) {
		vars[str(obj(v)["key"])] = str(obj(v)["value"])
	}
	expand := func(s string) string {
		return postmanVar.ReplaceAllStringFunc(s, func(m string) string {
			name := postmanVar.FindStringSubmatch(m)[1]
			if v, ok := vars[name]; ok && v != "" && !strings.Contains(v, "{{") {
				return v
			}
			return m
		})
	}
	collectionAuth := doc["auth"] != nil && str(obj(doc["auth"])["type"]) != "noauth"
	var walk func(items []any, inheritedAuth bool)
	walk = func(items []any, inheritedAuth bool) {
		for _, raw := range items {
			it := obj(raw)
			if it == nil || len(def.Operations) > MaxOperations {
				continue
			}
			auth := inheritedAuth
			if a, ok := it["auth"]; ok {
				auth = a != nil && str(obj(a)["type"]) != "noauth"
			}
			if sub := arr(it["item"]); sub != nil {
				walk(sub, auth)
				continue
			}
			req := obj(it["request"])
			if req == nil {
				if s := str(it["request"]); s != "" {
					req = map[string]any{"url": s, "method": "GET"}
				} else {
					continue
				}
			}
			if a, ok := req["auth"]; ok {
				auth = a != nil && str(obj(a)["type"]) != "noauth"
			}
			op := postmanOperation(req, expand)
			if op == nil {
				continue
			}
			op.Summary = firstLine(str(it["name"]))
			op.Auth = auth
			def.Operations = append(def.Operations, *op)
		}
	}
	walk(arr(doc["item"]), collectionAuth)
	// A collection has no base URL of its own: use the one most operations share.
	count := map[string]int{}
	for _, op := range def.Operations {
		count[op.BaseURL]++
	}
	best := 0
	for b, n := range count {
		if n > best || (n == best && b < def.BaseURL) {
			def.BaseURL, best = b, n
		}
	}
	return def, nil
}

func postmanOperation(req map[string]any, expand func(string) string) *Operation {
	method := strings.ToUpper(str(req["method"]))
	if method == "" {
		method = "GET"
	}
	var raw string
	var params []Param
	var pathSegs []string
	var base string
	switch u := req["url"].(type) {
	case string:
		raw = u
	case map[string]any:
		raw = str(u["raw"])
		if hs := arr(u["host"]); len(hs) > 0 {
			parts := make([]string, 0, len(hs))
			for _, h := range hs {
				parts = append(parts, str(h))
			}
			host := strings.Join(parts, ".")
			if pr := str(u["protocol"]); pr != "" && !strings.Contains(host, "://") {
				host = pr + "://" + host
			}
			if port := str(u["port"]); port != "" {
				host += ":" + port
			}
			base = host
		}
		if ps, ok := u["path"]; ok {
			switch x := ps.(type) {
			case string:
				pathSegs = strings.Split(strings.Trim(x, "/"), "/")
			case []any:
				for _, s := range x {
					if seg := str(s); seg != "" {
						pathSegs = append(pathSegs, seg)
					} else if m := obj(s); m != nil {
						pathSegs = append(pathSegs, str(m["value"]))
					}
				}
			}
		}
		for _, q := range arr(u["query"]) {
			if qm := obj(q); qm != nil && qm["disabled"] != true {
				params = append(params, Param{Name: str(qm["key"]), In: "query"})
			}
		}
	default:
		return nil
	}
	if base == "" || pathSegs == nil {
		b, segs, qs := splitRawURL(raw)
		if base == "" {
			base = b
		}
		if pathSegs == nil {
			pathSegs = segs
		}
		if len(params) == 0 {
			for _, q := range qs {
				params = append(params, Param{Name: q, In: "query"})
			}
		}
	}
	base = strings.TrimRight(expand(base), "/")
	if base != "" && !strings.Contains(base, "://") && !strings.HasPrefix(base, "{{") {
		base = "https://" + base
	}
	// Path segments: ":id" and "{{id}}" are variables.
	var b strings.Builder
	for _, seg := range pathSegs {
		if seg == "" {
			continue
		}
		seg = expand(seg)
		switch {
		case strings.HasPrefix(seg, ":") && len(seg) > 1:
			name := seg[1:]
			params = append([]Param{{Name: name, In: "path", Required: true}}, params...)
			seg = "{" + name + "}"
		case postmanVar.MatchString(seg) && postmanVar.FindString(seg) == seg:
			name := postmanVar.FindStringSubmatch(seg)[1]
			params = append([]Param{{Name: name, In: "path", Required: true}}, params...)
			seg = "{" + name + "}"
		}
		b.WriteString("/")
		b.WriteString(seg)
	}
	path := b.String()
	if path == "" {
		path = "/"
	}
	for _, h := range arr(req["header"]) {
		if hm := obj(h); hm != nil && hm["disabled"] != true {
			name := str(hm["key"])
			if name != "" && !strings.EqualFold(name, "content-type") && !strings.EqualFold(name, "accept") {
				params = append(params, Param{Name: name, In: "header"})
			}
		}
	}
	if body := obj(req["body"]); body != nil {
		switch str(body["mode"]) {
		case "urlencoded", "formdata":
			for _, f := range arr(body[str(body["mode"])]) {
				if fm := obj(f); fm != nil && fm["disabled"] != true {
					params = append(params, Param{Name: str(fm["key"]), In: "form"})
				}
			}
		case "raw":
			var m map[string]any
			if json.Unmarshal([]byte(str(body["raw"])), &m) == nil {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					params = append(params, Param{Name: k, In: "body"})
				}
			}
		case "graphql":
			params = append(params, Param{Name: "query", In: "body"}, Param{Name: "variables", In: "body"})
		}
	}
	if len(params) > maxParams {
		params = params[:maxParams]
	}
	if params == nil {
		params = []Param{}
	}
	return &Operation{Method: method, Path: path, BaseURL: base, Params: params}
}

// splitRawURL splits a Postman raw URL into base, path segments and query names.
func splitRawURL(raw string) (base string, segs []string, query []string) {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		for _, kv := range strings.Split(raw[i+1:], "&") {
			if k, _, _ := strings.Cut(kv, "="); k != "" {
				query = append(query, k)
			}
		}
		raw = raw[:i]
	}
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		base = rest[:i+3]
		rest = rest[i+3:]
	}
	host, path, _ := strings.Cut(rest, "/")
	base += host
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return base, segs, query
}

// ---------------- matching ----------------

var templateVar = regexp.MustCompile(`\{[^}]*\}`)

// Matcher matches an observed request against one operation.
type Matcher struct {
	Method string
	Host   string // lower-case host[:port] from the base URL, or "" when unknown
	re     *regexp.Regexp
}

// NewMatcher compiles op's base path and path template.
func NewMatcher(op Operation) Matcher {
	host, basePath := "", ""
	if u, err := url.Parse(op.BaseURL); err == nil {
		host = strings.ToLower(u.Host)
		basePath = strings.TrimRight(u.Path, "/")
	} else if strings.HasPrefix(op.BaseURL, "/") {
		basePath = strings.TrimRight(op.BaseURL, "/")
	}
	if strings.Contains(host, "{{") {
		host = ""
	}
	full := basePath + op.Path
	var b strings.Builder
	b.WriteString("^")
	for _, seg := range strings.Split(full, "/") {
		if seg == "" {
			continue
		}
		b.WriteString("/")
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && strings.Count(seg, "{") == 1 {
			b.WriteString("[^/]+")
			continue
		}
		// a template piece inside a segment, e.g. file.{ext}
		parts := templateVar.Split(seg, -1)
		for i, part := range parts {
			if i > 0 {
				b.WriteString("[^/]+")
			}
			b.WriteString(regexp.QuoteMeta(part))
		}
	}
	b.WriteString("/?$")
	return Matcher{Method: strings.ToUpper(op.Method), Host: host, re: regexp.MustCompile(b.String())}
}

// Match reports whether a request (method, host, path without query) is op.
// Hosts compare without a default port; an operation with no known host matches
// any host.
func (m Matcher) Match(method, host, path string) bool {
	if !strings.EqualFold(method, m.Method) {
		return false
	}
	if m.Host != "" && stripDefaultPort(strings.ToLower(host)) != stripDefaultPort(m.Host) {
		return false
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		path = "/"
	}
	return m.re.MatchString(path)
}

func stripDefaultPort(h string) string {
	return strings.TrimSuffix(strings.TrimSuffix(h, ":443"), ":80")
}
