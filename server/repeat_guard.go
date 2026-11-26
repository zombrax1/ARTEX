package server

import (
	"encoding/json"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// settingRepeatGuard stores the repeated-failure detection limits as JSON
// (agent.RepeatGuardLimits). Unset = agent.DefaultRepeatGuardLimits.
const settingRepeatGuard = "repeat_guard"

// repeatGuardLimits reads the stored limits, falling back to the defaults when
// the setting is unset or unreadable.
func repeatGuardLimits(pg *db.DB) agent.RepeatGuardLimits {
	if pg == nil {
		return agent.DefaultRepeatGuardLimits()
	}
	raw, ok, err := pg.GetSetting(settingRepeatGuard)
	if err != nil || !ok || raw == "" {
		return agent.DefaultRepeatGuardLimits()
	}
	l := agent.DefaultRepeatGuardLimits()
	if json.Unmarshal([]byte(raw), &l) != nil {
		return agent.DefaultRepeatGuardLimits()
	}
	return l.Clamped()
}

// setRepeatGuardLimits merges a partial update into the stored limits.
func setRepeatGuardLimits(pg *db.DB, patch json.RawMessage) (agent.RepeatGuardLimits, error) {
	l := repeatGuardLimits(pg)
	if err := json.Unmarshal(patch, &l); err != nil {
		return l, err
	}
	l = l.Clamped()
	raw, _ := json.Marshal(l)
	return l, pg.SetSetting(settingRepeatGuard, string(raw))
}

// installRepeatGuard makes every new agent run read the stored limits, so a
// change applies to runs started afterwards without a restart.
func (s *Server) installRepeatGuard() {
	pg := s.m.pg
	agent.SetRepeatGuardSource(func() agent.RepeatGuardLimits { return repeatGuardLimits(pg) })
}
