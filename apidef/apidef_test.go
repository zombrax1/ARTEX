package apidef

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const openapiYAML = `
openapi: 3.0.3
info: {title: Shop}
servers:
  - url: https://{env}.shop.example/api/v1
    variables: {env: {default: api}}
security: [{bearer: []}]
components:
  parameters:
    Id: {name: id, in: path, required: true, schema: {type: integer, format: int64}}
  schemas:
    User:
      type: object
      required: [email]
      properties:
        email: {type: string}
        role: {type: string}
paths:
  /users/{id}:
    parameters: [{$ref: '#/components/parameters/Id'}]
    get:
      operationId: getUser
      summary: Get a user
    put:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/User'}
  /health:
    get:
      security: [{}]
      parameters: [{name: verbose, in: query, schema: {type: boolean}}]
`

func TestParseOpenAPI3YAML(t *testing.T) {
	d, err := Parse([]byte(openapiYAML))
	if err != nil {
		t.Fatal(err)
	}
	if d.Format != FormatOpenAPI || d.Title != "Shop" || d.BaseURL != "https://api.shop.example/api/v1" || len(d.Operations) != 3 {
		t.Fatalf("def = %+v", d)
	}
	h := d.Operations[0]
	if h.Path != "/health" || h.Auth || len(h.Params) != 1 || h.Params[0].In != "query" {
		t.Fatalf("health = %+v", h)
	}
	get := d.Operations[1]
	if get.Method != "GET" || get.OperationID != "getUser" || !get.Auth || get.Params[0].Type != "integer(int64)" || !get.Params[0].Required {
		t.Fatalf("get = %+v", get)
	}
	put := d.Operations[2]
	if put.Method != "PUT" || len(put.Params) != 3 || put.Params[1].Name != "email" || !put.Params[1].Required || put.Params[1].In != "body" {
		t.Fatalf("put = %+v", put)
	}
}

func TestParseSwagger2(t *testing.T) {
	d, err := Parse([]byte(`{"swagger":"2.0","info":{"title":"Pets"},"host":"pets.example","basePath":"/v2","schemes":["http","https"],
	 "paths":{"/pet":{"post":{"parameters":[{"in":"body","name":"body","schema":{"properties":{"name":{"type":"string"}}}}]}},
	          "/pet/{petId}/upload":{"post":{"parameters":[{"in":"path","name":"petId","type":"integer"},{"in":"formData","name":"file","type":"file"}]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Format != FormatSwagger || d.BaseURL != "https://pets.example/v2" || len(d.Operations) != 2 {
		t.Fatalf("def = %+v", d)
	}
	if p := d.Operations[0].Params; len(p) != 1 || p[0].In != "body" || p[0].Name != "name" {
		t.Fatalf("body params = %+v", p)
	}
	if p := d.Operations[1].Params; len(p) != 2 || p[1].In != "form" || !p[0].Required {
		t.Fatalf("upload params = %+v", p)
	}
}

func TestParsePostman(t *testing.T) {
	d, err := Parse([]byte(`{"info":{"name":"Admin API","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	 "variable":[{"key":"base","value":"https://admin.example"}],
	 "auth":{"type":"bearer"},
	 "item":[{"name":"Users","item":[
	   {"name":"Get user","request":{"method":"GET","url":{"raw":"{{base}}/users/:id?expand=1","host":["{{base}}"],"path":["users",":id"],"query":[{"key":"expand","value":"1"}]}}},
	   {"name":"Login","request":{"method":"POST","auth":{"type":"noauth"},"header":[{"key":"X-Tenant","value":"a"}],
	     "body":{"mode":"raw","raw":"{\"user\":\"a\",\"pass\":\"b\"}"},"url":"{{base}}/login"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Format != FormatPostman || d.BaseURL != "https://admin.example" || len(d.Operations) != 2 {
		t.Fatalf("def = %+v", d)
	}
	login, get := d.Operations[0], d.Operations[1]
	if login.Path != "/login" || login.Auth || len(login.Params) != 3 {
		t.Fatalf("login = %+v", login)
	}
	if get.Path != "/users/{id}" || !get.Auth || get.Params[0].Name != "id" || get.Params[0].In != "path" || get.Params[1].Name != "expand" {
		t.Fatalf("get = %+v", get)
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{`{"foo":1}`, `[1,2]`, `{"openapi":"3.0.0","paths":{}}`, "::"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
	if _, err := Parse([]byte(strings.Repeat(" ", MaxBytes+1))); err == nil {
		t.Error("oversized input parsed")
	}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher(Operation{Method: "GET", Path: "/users/{id}", BaseURL: "https://api.shop.example:443/api/v1"})
	cases := []struct {
		method, host, path string
		want               bool
	}{
		{"GET", "api.shop.example", "/api/v1/users/42", true},
		{"get", "API.shop.example:443", "/api/v1/users/42/?x=1", true},
		{"POST", "api.shop.example", "/api/v1/users/42", false},
		{"GET", "other.example", "/api/v1/users/42", false},
		{"GET", "api.shop.example", "/api/v1/users/42/orders", false},
		{"GET", "api.shop.example", "/users/42", false},
	}
	for _, c := range cases {
		if got := m.Match(c.method, c.host, c.path); got != c.want {
			t.Errorf("%s %s%s = %v, want %v", c.method, c.host, c.path, got, c.want)
		}
	}
	anyHost := NewMatcher(Operation{Method: "GET", Path: "/files/{name}.{ext}"})
	if !anyHost.Match("GET", "x.example", "/files/a.pdf") || anyHost.Match("GET", "x.example", "/files/a") {
		t.Error("in-segment template mismatch")
	}
}

func TestParseSelfReferencingSchema(t *testing.T) {
	doc := `{"openapi":"3.0.0","info":{"title":"loop"},"paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}}}}},
	  "components":{"schemas":{"A":{"allOf":[{"$ref":"#/components/schemas/A"},{"properties":{"x":{"$ref":"#/components/schemas/B"}}}]},
	  "B":{"type":"array","items":{"$ref":"#/components/schemas/B"}}}}}`
	def, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(def.Operations) != 1 {
		t.Fatalf("operations = %+v", def.Operations)
	}
}

func TestParseOperationServers(t *testing.T) {
	doc := `{"openapi":"3.0.0","info":{"title":"s"},"servers":[{"url":"https://example.com/v1"}],"paths":{
	  "/a":{"get":{}},
	  "/b":{"servers":[{"url":"https://{env}.example.com/v2","variables":{"env":{"default":"api"}}}],"get":{},"post":{"servers":[{"url":"https://example.com/v3/"}]}}}}`
	def, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, op := range def.Operations {
		got[op.Method+" "+op.Path] = op.BaseURL
	}
	want := map[string]string{"GET /a": "https://example.com/v1", "GET /b": "https://api.example.com/v2", "POST /b": "https://example.com/v3"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s base = %q, want %q", k, got[k], v)
		}
	}
	for _, op := range def.Operations {
		if op.Method == "POST" && op.Path == "/b" && !NewMatcher(op).Match("POST", "example.com", "/v3/b") {
			t.Error("the operation-level server does not match its own traffic")
		}
	}
}

func TestParseBranchingSelfReference(t *testing.T) {
	refs := make([]string, 20)
	for i := range refs {
		refs[i] = `{"$ref":"#/components/schemas/A"}`
	}
	doc := `{"openapi":"3.0.0","info":{"title":"fan"},"paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}}}}},
	  "components":{"schemas":{"A":{"allOf":[` + strings.Join(refs, ",") + `,{"properties":{"x":{"type":"string"}}}]}}}}`
	done := make(chan error, 1)
	go func() {
		def, err := Parse([]byte(doc))
		if err == nil && (len(def.Operations) != 1 || len(def.Operations[0].Params) != 1) {
			err = fmt.Errorf("operations = %+v", def.Operations)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parsing a schema whose allOf references itself 20 times did not finish")
	}
}

func TestParseAnonymousRootSecurity(t *testing.T) {
	for _, sec := range []string{`[{}]`, `[{"bearer":[]},{}]`} {
		doc := `{"openapi":"3.0.0","info":{"title":"s"},"security":` + sec + `,"paths":{"/a":{"get":{}},"/b":{"get":{"security":[{"bearer":[]}]}}}}`
		def, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if len(def.Operations) != 2 {
			t.Fatalf("operations = %+v", def.Operations)
		}
		for _, op := range def.Operations {
			if want := op.Path == "/b"; op.Auth != want {
				t.Errorf("security %s: %s auth = %v, want %v", sec, op.Path, op.Auth, want)
			}
		}
	}
}

func TestParseAllOfWithSiblingProperties(t *testing.T) {
	doc := `{"openapi":"3.0.0","info":{"title":"s"},"paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{
	  "allOf":[{"properties":{"base":{"type":"string"}}}],
	  "properties":{"extra":{"type":"integer"}},"required":["extra","base"]}}}}}}}}`
	def, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Param{}
	for _, prm := range def.Operations[0].Params {
		got[prm.Name] = prm
	}
	if !got["base"].Required || !got["extra"].Required || got["extra"].Type != "integer" || len(got) != 2 {
		t.Fatalf("params = %+v", def.Operations[0].Params)
	}
}

func TestParsePostmanCollectionNoAuth(t *testing.T) {
	doc := `{"info":{"name":"c","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	  "auth":{"type":"noauth"},
	  "item":[{"name":"a","request":{"method":"GET","url":"https://example.com/a"}},
	    {"name":"b","request":{"method":"GET","url":"https://example.com/b","auth":{"type":"bearer"}}}]}`
	def, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(def.Operations) != 2 {
		t.Fatalf("operations = %+v", def.Operations)
	}
	for _, op := range def.Operations {
		if want := op.Path == "/b"; op.Auth != want {
			t.Errorf("%s auth = %v, want %v", op.Path, op.Auth, want)
		}
	}
}

func TestParseAllOfDuplicateRequired(t *testing.T) {
	doc := `{"openapi":"3.0.0","info":{"title":"s"},"paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{
	  "allOf":[{"properties":{"email":{"type":"string"}},"required":["email"]},{"properties":{"email":{"type":"string","format":"email"}}}]}}}}}}}}`
	def, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	ps := def.Operations[0].Params
	if len(ps) != 1 || !ps[0].Required || ps[0].Type != "string(email)" {
		t.Fatalf("params = %+v", ps)
	}
}

func TestParsePostmanNullAuthInherits(t *testing.T) {
	doc := `{"info":{"name":"c","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	  "auth":{"type":"bearer"},
	  "item":[{"name":"f","auth":null,"item":[{"name":"a","request":{"method":"GET","url":"https://example.com/a","auth":null}}]},
	    {"name":"b","request":{"method":"GET","url":"https://example.com/b","auth":{"type":"noauth"}}}]}`
	def, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(def.Operations) != 2 {
		t.Fatalf("operations = %+v", def.Operations)
	}
	for _, op := range def.Operations {
		if want := op.Path == "/a"; op.Auth != want {
			t.Errorf("%s auth = %v, want %v", op.Path, op.Auth, want)
		}
	}
}

func TestMatcherEscapedBasePath(t *testing.T) {
	m := NewMatcher(Operation{Method: "GET", Path: "/users", BaseURL: "https://example.com/api%20v1"})
	if !m.Match("GET", "example.com", "/api%20v1/users") {
		t.Error("the escaped base path does not match the captured escaped path")
	}
}
