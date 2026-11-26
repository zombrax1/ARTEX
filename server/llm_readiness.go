package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// Model readiness results (agent.RunReadiness) are kept per LLM profile in one
// settings row, so the profile cards and the task dialog can show the last
// measured result next to what the provider advertises. A result is tied to the
// model it was measured on: when the profile's model changes it is reported as
// stale rather than silently reused.
const settingLLMReadiness = "llm_readiness"

var readinessMu sync.Mutex

func loadReadiness(pg *db.DB) map[string]agent.ReadinessReport {
	out := map[string]agent.ReadinessReport{}
	if pg == nil {
		return out
	}
	if raw, ok, err := pg.GetSetting(settingLLMReadiness); err == nil && ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func saveReadiness(pg *db.DB, id int64, r agent.ReadinessReport) error {
	readinessMu.Lock()
	defer readinessMu.Unlock()
	all := loadReadiness(pg)
	all[strconv.FormatInt(id, 10)] = r
	raw, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return pg.SetSetting(settingLLMReadiness, string(raw))
}

// readinessEntry is one profile's last result as the API returns it.
type readinessEntry struct {
	agent.ReadinessReport
	// Stale is true when the profile now uses a different model than the one tested.
	Stale bool `json:"stale"`
}

// llmReadiness returns the last readiness result of every existing profile
// (GET /api/llm/readiness), keyed by profile id. Untested profiles are absent.
func (s *Server) llmReadiness(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	profiles, err := pg.ListProfiles()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	all := loadReadiness(pg)
	out := map[string]readinessEntry{}
	for _, p := range profiles {
		key := strconv.FormatInt(p.ID, 10)
		if rep, ok := all[key]; ok {
			out[key] = readinessEntry{ReadinessReport: rep, Stale: rep.Model != p.Model}
		}
	}
	writeJSON(w, 200, out)
}

// runLLMReadiness runs the readiness test on a stored profile
// (POST /api/llm/profiles/{id}/readiness). It uses the profile's shared
// provider, so the profile's concurrency cap and rate limits apply and the test
// queues behind running agents instead of overloading a local model.
func (s *Server) runLLMReadiness(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid profile id")
		return
	}
	p, err := pg.ProfileByID(id)
	if err != nil || p == nil {
		writeErr(w, 404, "profile not found")
		return
	}
	prov, cfg, ok := s.providerForProfile(id)
	if !ok {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "this profile cannot be used: check its API key and settings"})
		return
	}
	rep := agent.RunReadiness(r.Context(), prov, cfg)
	if r.Context().Err() != nil {
		return // the client went away; a cut-short run is not a measurement
	}
	log.Printf("[llm] readiness test of profile %d (%s / %s): %s in %dms", id, p.Name, cfg.Model, rep.Verdict, rep.LatencyMS)
	if err := saveReadiness(pg, id, rep); err != nil {
		log.Printf("[llm] saving the readiness result of profile %d failed: %v", id, err)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "report": readinessEntry{ReadinessReport: rep, Stale: rep.Model != p.Model}})
}
