// Package llmgate caps how many LLM requests run at once against one profile.
//
// Many agents (planner, workers, reporters, side questions…) across many tasks
// share one provider per profile. A hosted API copes with that; a local model
// server on one GPU (Ollama, llama.cpp, vLLM on a 16 GB card) does not: every
// parallel request needs its own KV cache, VRAM runs out, layers spill to CPU and
// everything slows to a crawl or times out. A Gate admits at most N requests at a
// time and makes the rest wait, first come first served, so the GPU works through
// a steady queue instead of thrashing.
//
// The rate limits on a profile (requests per second/minute) don't solve this:
// they space out request starts, but long generations still pile up in parallel.
package llmgate

import (
	"context"
	"iter"
	"sync"

	"github.com/Autumn-27/norma/llm"
)

// Gate is a FIFO counting semaphore whose limit can change at runtime. A limit
// of 0 or less means unlimited. The zero value is not usable; use New.
type Gate struct {
	mu      sync.Mutex
	limit   int
	inUse   int
	waiters []chan struct{} // FIFO; a closed channel means "slot handed to you"
}

// New returns a Gate admitting at most limit concurrent holders (<=0 = unlimited).
func New(limit int) *Gate { return &Gate{limit: limit} }

// SetLimit changes the cap. Raising it (or lifting it with <=0) admits waiters
// immediately; lowering it lets in-flight requests finish and only holds back
// new ones until the count drops below the new cap.
func (g *Gate) SetLimit(limit int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.limit = limit
	g.admitLocked()
}

// Limit returns the current cap (<=0 = unlimited).
func (g *Gate) Limit() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit
}

// Stats returns how many requests hold a slot and how many are queued.
func (g *Gate) Stats() (inFlight, queued int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inUse, len(g.waiters)
}

func (g *Gate) hasRoomLocked() bool { return g.limit <= 0 || g.inUse < g.limit }

// admitLocked hands free slots to the oldest waiters.
func (g *Gate) admitLocked() {
	for len(g.waiters) > 0 && g.hasRoomLocked() {
		ch := g.waiters[0]
		g.waiters = g.waiters[1:]
		g.inUse++
		close(ch)
	}
}

// Acquire waits for a slot. It returns ctx.Err() if ctx ends first, in which case
// no slot is held. On success the caller must call Release exactly once.
func (g *Gate) Acquire(ctx context.Context) error {
	g.mu.Lock()
	if len(g.waiters) == 0 && g.hasRoomLocked() {
		g.inUse++
		g.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	g.waiters = append(g.waiters, ch)
	g.mu.Unlock()

	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		g.mu.Lock()
		defer g.mu.Unlock()
		select {
		case <-ch:
			// Granted while we were giving up: pass the slot on.
			g.inUse--
			g.admitLocked()
		default:
			for i, w := range g.waiters {
				if w == ch {
					g.waiters = append(g.waiters[:i], g.waiters[i+1:]...)
					break
				}
			}
		}
		return ctx.Err()
	}
}

// Release frees a slot taken by a successful Acquire.
func (g *Gate) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inUse > 0 {
		g.inUse--
	}
	g.admitLocked()
}

// Wrap returns a provider that holds a slot of g for the whole duration of each
// call: a Complete until it returns, a Stream until the caller stops iterating
// (end of stream, error, or early exit). A nil gate returns inner unchanged.
func Wrap(inner llm.Provider, g *Gate) llm.Provider {
	if g == nil {
		return inner
	}
	return &provider{inner: inner, gate: g}
}

type provider struct {
	inner llm.Provider
	gate  *Gate
}

func (p *provider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if err := p.gate.Acquire(ctx); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		defer p.gate.Release()
		for ev, err := range p.inner.Stream(ctx, req) {
			if !yield(ev, err) {
				return
			}
		}
	}
}

func (p *provider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := p.gate.Acquire(ctx); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	defer p.gate.Release()
	return p.inner.Complete(ctx, req)
}
