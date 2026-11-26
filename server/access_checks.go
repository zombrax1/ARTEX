package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
)

// Multiple-account testing: one request replayed as each test account (with the
// session headers saved on the credential) and once without a session, compared
// by db.AnalyzeAccess. The agent tool is compare_access; the UI lists the stored
// comparisons on the task's credentials tab.

const (
	maxAccessAccounts   = 12
	maxAccessBody       = 2 << 20
	accessSnippetLength = 240
	accessTimeout       = 20 * time.Second
)

func (s *Server) installAccessChecks() {
	agent.SetAccessCheckSource(agent.AccessCheckSource{Run: s.runAccessCheck})
}

// accessAccount is one replay: a credential, or anonymous when cred is nil.
type accessAccount struct {
	cred    *db.TaskCredential
	headers [][2]string
}

// credentialHost is the host a credential's domain names, lower-case, without
// a scheme, port or path ("https://App.example.com:8443/x" -> "app.example.com").
func credentialHost(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	return strings.Trim(strings.TrimPrefix(d, "*."), "[].")
}

// credentialCovers reports whether a credential for domain may be sent to host:
// the same host, or a subdomain of the credential's domain (a session for
// example.com is sent to api.example.com, not the other way round).
func credentialCovers(domain, host string) bool {
	d, h := credentialHost(domain), strings.ToLower(strings.Trim(host, "[]."))
	return d != "" && (h == d || strings.HasSuffix(h, "."+d))
}

// selectAccessAccounts picks the credentials to replay as. Without ids, every
// account with session headers whose domain covers the destination host takes
// part. A named account for another domain, or without session headers, is an
// error: its session must not be sent to another site, and replaying it
// without one would only repeat the anonymous request.
func selectAccessAccounts(creds []db.TaskCredential, ids []int64, owner int64, host string) ([]accessAccount, error) {
	byID := make(map[int64]int, len(creds))
	for i, c := range creds {
		byID[c.ID] = i
	}
	want := ids
	if len(want) == 0 {
		for _, c := range creds {
			if c.AuthHeaders != "" && credentialCovers(c.Domain, host) {
				want = append(want, c.ID)
			}
		}
	}
	if owner > 0 {
		found := false
		for _, id := range want {
			if id == owner {
				found = true
				break
			}
		}
		if !found {
			want = append([]int64{owner}, want...)
		}
	}
	seen := map[int64]bool{}
	var out []accessAccount
	for _, id := range want {
		if seen[id] {
			continue
		}
		seen[id] = true
		i, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("credential %d is not a test account of this task", id)
		}
		c := creds[i]
		if !credentialCovers(c.Domain, host) {
			return nil, fmt.Errorf("credential %d (%s) belongs to %s, not %s; its session is not sent to another host", id, c.Username, c.Domain, host)
		}
		if c.AuthHeaders == "" {
			return nil, fmt.Errorf("credential %d (%s) has no session headers saved; log in as it and save them with save_task_credential auth_headers", id, c.Username)
		}
		h, err := db.ParseAuthHeaders(c.AuthHeaders)
		if err != nil {
			return nil, fmt.Errorf("credential %d: %v", id, err)
		}
		out = append(out, accessAccount{cred: &c, headers: h})
	}
	if len(out) > maxAccessAccounts {
		return nil, fmt.Errorf("at most %d accounts per comparison", maxAccessAccounts)
	}
	return out, nil
}

// runAccessCheck replays the request as each selected account and stores the
// comparison. The URL goes through the target gate, every replay goes through
// the recording proxy when traffic capture is on (so the responses are evidence
// in the traffic view), and through the egress governor.
func (s *Server) runAccessCheck(ctx context.Context, toolName string, taskID int64, req agent.AccessCheckRequest) (db.AccessCheck, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	if agent.StateChangingMethod(method) && !req.AllowStateChange {
		return db.AccessCheck{}, fmt.Errorf("%s is sent once per account; set allow_state_change=true if that is safe", method)
	}
	rawURL := strings.TrimSpace(req.URL)
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return db.AccessCheck{}, errors.New("url must be an absolute http(s) URL")
	}
	if res := intercept.GateRenderedURL(ctx, toolName, rawURL); res.Code != "" {
		return db.AccessCheck{}, errors.New(guard.TargetBlockMessage(res))
	}
	creds, err := s.m.PG().TaskCredentials(taskID)
	if err != nil {
		return db.AccessCheck{}, err
	}
	accounts, err := selectAccessAccounts(creds, req.Accounts, req.Owner, u.Hostname())
	if err != nil {
		return db.AccessCheck{}, err
	}
	if req.Anonymous() {
		accounts = append(accounts, accessAccount{})
	}
	if len(accounts) < 2 {
		return db.AccessCheck{}, errors.New("nothing to compare: save session headers on at least one test account (or two, without the anonymous request)")
	}
	// Session header names of any account are stripped from the shared headers,
	// so the anonymous request carries no session, and no account carries
	// another's.
	session := map[string]bool{"cookie": true, "authorization": true}
	for _, a := range accounts {
		for _, h := range a.headers {
			session[strings.ToLower(h[0])] = true
		}
	}
	results := make([]db.AccessResult, 0, len(accounts))
	ownerIdx := -1
	for i, a := range accounts {
		r := s.replayAs(ctx, toolName, method, rawURL, req, session, a)
		if a.cred != nil && a.cred.ID == req.Owner {
			ownerIdx = i
		}
		results = append(results, r)
	}
	check := db.AccessCheck{
		TaskID: taskID, Method: method, URL: rawURL, Results: results,
		Flags: db.AnalyzeAccess(results, ownerIdx), CheckedBy: req.CheckedBy,
	}
	if req.Owner > 0 {
		owner := req.Owner
		check.OwnerID = &owner
	}
	if err := s.m.PG().CreateAccessCheck(&check); err != nil {
		return check, err
	}
	return check, nil
}

func (s *Server) replayAs(ctx context.Context, toolName, method, rawURL string, in agent.AccessCheckRequest, session map[string]bool, a accessAccount) db.AccessResult {
	res := db.AccessResult{Account: "anonymous"}
	if a.cred != nil {
		id := a.cred.ID
		res.CredentialID, res.Account, res.Role, res.Org = &id, a.cred.Username, a.cred.Role, a.cred.Org
	}
	runCtx, cancel := context.WithTimeout(ctx, accessTimeout)
	defer cancel()
	var body io.Reader
	if in.Body != "" {
		body = strings.NewReader(in.Body)
	}
	req, err := http.NewRequestWithContext(runCtx, method, rawURL, body)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	for k, v := range in.Headers {
		if !session[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}
	for _, h := range a.headers {
		req.Header.Set(h[0], h[1])
	}
	intercept.ApplyAssessmentUserAgent(req)
	client := &http.Client{
		Timeout: accessTimeout,
		// A redirect (often to a login page) is part of the answer: keep it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var base http.RoundTripper = http.DefaultTransport
	if tr := s.httpToolTransport(ctx, toolName, httpExec{UseRecordingProxy: true}); tr != nil {
		base = tr
	}
	client.Transport = egress.Current().Transport(toolName, base)
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAccessBody))
	if err != nil {
		// A truncated or stalled body is not evidence: keep the status, mark
		// the result failed so the comparison skips it.
		res.Status, res.Length = resp.StatusCode, len(data)
		res.Error = "reading the response body failed: " + err.Error()
		return res
	}
	sum := sha256.Sum256(data)
	res.Status, res.Length, res.BodyHash = resp.StatusCode, len(data), hex.EncodeToString(sum[:])
	snippet := data
	if len(snippet) > accessSnippetLength {
		snippet = snippet[:accessSnippetLength]
	}
	res.Snippet = strings.ToValidUTF8(string(snippet), "")
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		res.Snippet = "→ " + loc
	}
	return res
}

// GET /api/tasks/{id}/access-checks
func (s *Server) listAccessChecks(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.m.PG().AccessChecks(id, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}
