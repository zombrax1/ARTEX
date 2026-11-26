package server

import (
	"encoding/json"
	"fmt"
	actool "github.com/Autumn-27/norma/tool"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestAPIDefinitionImportAndCoverage(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	t.Cleanup(func() { agent.SetAPICoverageSource(agent.APICoverageSource{}) })
	tasks := s.m.List()
	if len(tasks) == 0 {
		t.Fatal("no task")
	}
	var taskID string
	for _, tk := range tasks {
		if tk.Description == "traffic evidence API" {
			taskID = tk.ID
		}
	}
	base := "/api/tasks/" + taskID
	spec := `{"openapi":"3.0.0","info":{"title":"Lab"},"servers":[{"url":"https://lab.example/api"}],
	  "paths":{"/users/{id}":{"get":{},"delete":{}},"/admin":{"post":{}}}}`
	body, _ := json.Marshal(map[string]string{"content": spec})
	if w := request("POST", base+"/api-definitions", string(body)); w.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	if w := request("POST", base+"/api-definitions", `{"content":"{\"foo\":1}"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad import: %d", w.Code)
	}

	// One captured request after the import matches GET /users/{id}.
	now := time.Now().Unix() + 1
	if _, err := s.m.Traffic().DB().Exec(`INSERT INTO exchanges (id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
		VALUES ('ex-api-1',?,'lab.example','GET','/api/users/{n}','https://lab.example/api/users/5',200,'',0,0,'/api/users/5')`, now); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Definitions []db.APIDefinition      `json:"definitions"`
		Operations  []db.APIOperationStatus `json:"operations"`
		Summary     apiCoverageSummary      `json:"summary"`
	}
	read := func() {
		t.Helper()
		w := request("GET", base+"/api-definitions", "")
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
	}
	read()
	if len(got.Definitions) != 1 || got.Definitions[0].Name != "Lab" || got.Summary != (apiCoverageSummary{Total: 3, Tested: 1, Untested: 2}) {
		t.Fatalf("after import: %+v %+v", got.Definitions, got.Summary)
	}
	byKey := map[string]db.APIOperationStatus{}
	for _, o := range got.Operations {
		byKey[o.Method+" "+o.Path] = o
	}
	if o := byKey["GET /users/{id}"]; o.Status != "tested" || o.LastExchange != "ex-api-1" {
		t.Fatalf("GET op = %+v", o)
	}
	// Counted captures stay counted: later passes read only newer traffic,
	// a page at a time, and never count a capture twice.
	defer func(size, pages int) { apiCoveragePageSize, apiCoveragePages = size, pages }(apiCoveragePageSize, apiCoveragePages)
	apiCoveragePageSize, apiCoveragePages = 1, 1
	for i := 2; i <= 4; i++ {
		if _, err := s.m.Traffic().DB().Exec(`INSERT INTO exchanges (id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
			VALUES (?,?,'lab.example','GET','/api/users/{n}','https://lab.example/api/users/5',200,'',0,0,'/api/users/5')`, fmt.Sprintf("ex-api-%d", i), now+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Stored later but sorting first by ts and id (a wrapped id sequence), with
	// the host in upper case: still counted.
	if _, err := s.m.Traffic().DB().Exec(`INSERT INTO exchanges (id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
		VALUES ('0000-late',?,'LAB.example','GET','/api/users/{n}','https://LAB.example/api/users/5',200,'',0,0,'/api/users/5')`, now); err != nil {
		t.Fatal(err)
	}
	for pass, want := range []int{2, 3, 4, 5, 5} {
		read()
		for _, o := range got.Operations {
			if o.Method == "GET" && o.Requests != want {
				t.Fatalf("pass %d: GET requests = %d, want %d", pass, o.Requests, want)
			}
		}
	}
	// Clearing the traffic store does not put new captures behind the cursor.
	if _, _, err := s.m.Traffic().DeleteAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.Traffic().DB().Exec(`INSERT INTO exchanges (id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
		VALUES ('ex-api-9',?,'lab.example','GET','/api/users/{n}','https://lab.example/api/users/5',200,'',0,0,'/api/users/5')`, now); err != nil {
		t.Fatal(err)
	}
	read()
	for _, o := range got.Operations {
		if o.Method == "GET" && o.Requests != 6 {
			t.Fatalf("after clearing traffic: GET requests = %d, want 6", o.Requests)
		}
	}
	apiCoveragePageSize, apiCoveragePages = 20000, 5
	del := byKey["DELETE /users/{id}"]
	if w := request("PUT", fmt.Sprintf("%s/api-operations/%d", base, del.ID), `{"mark":"skipped"}`); w.Code != 400 {
		t.Fatalf("skip without reason: %d", w.Code)
	}
	if w := request("PUT", fmt.Sprintf("%s/api-operations/%d", base, del.ID), `{"mark":"skipped","note":"destructive"}`); w.Code != 200 {
		t.Fatalf("skip: %d %s", w.Code, w.Body.String())
	}
	// The agent path marks through the installed source.
	tid := got.Definitions[0].TaskID
	admin := byKey["POST /admin"]
	ts := agent.NewToolSet(nil, "worker-1")
	ts.SetTaskID(tid)
	res, err := toolByName(t, ts, "mark_api_operation").Call(t.Context(), json.RawMessage(fmt.Sprintf(`{"id":%d,"mark":"tested","note":"curl, capture off"}`, admin.ID)), nil)
	if err != nil || res.IsError {
		t.Fatalf("agent mark: %v %s", err, res.Flatten())
	}
	res, _ = toolByName(t, ts, "list_api_operations").Call(t.Context(), json.RawMessage(`{"status":"all"}`), nil)
	if !strings.Contains(res.Flatten(), `"tested":2`) || !strings.Contains(res.Flatten(), `"skipped":1`) {
		t.Fatalf("agent list: %s", res.Flatten())
	}
	read()
	if got.Summary != (apiCoverageSummary{Total: 3, Tested: 2, Skipped: 1}) {
		t.Fatalf("after marks: %+v", got.Summary)
	}
	if w := request("DELETE", fmt.Sprintf("%s/api-definitions/%d", base, got.Definitions[0].ID), ""); w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	read()
	if len(got.Definitions) != 0 || got.Summary.Total != 0 {
		t.Fatalf("after delete: %+v", got)
	}
}

func toolByName(t *testing.T, ts *agent.ToolSet, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range ts.WorkerTools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("worker tool %s not found", name)
	return nil
}
