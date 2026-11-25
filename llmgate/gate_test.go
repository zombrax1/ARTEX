package llmgate

import (
	"context"
	"errors"
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// slowProv records the peak number of concurrent calls.
type slowProv struct {
	cur, peak atomic.Int32
	hold      time.Duration
}

func (p *slowProv) enter() {
	n := p.cur.Add(1)
	for {
		old := p.peak.Load()
		if n <= old || p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	time.Sleep(p.hold)
}

func (p *slowProv) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.enter()
		defer p.cur.Add(-1)
		for i := 0; i < 3; i++ {
			if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "x"}, nil) {
				return
			}
		}
	}
}

func (p *slowProv) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.enter()
	defer p.cur.Add(-1)
	return llm.Message{}, "end_turn", llm.Usage{}, nil
}

func TestWrapCapsConcurrency(t *testing.T) {
	for _, limit := range []int{1, 2, 3} {
		inner := &slowProv{hold: 20 * time.Millisecond}
		p := Wrap(inner, New(limit))
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
					if err != nil {
						t.Error(err)
					}
				}
			}()
			go func() {
				defer wg.Done()
				if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if got := inner.peak.Load(); got > int32(limit) || got < 1 {
			t.Fatalf("limit %d: peak concurrency %d", limit, got)
		}
	}
}

func TestStreamEarlyExitReleases(t *testing.T) {
	g := New(1)
	p := Wrap(&slowProv{}, g)
	for range p.Stream(context.Background(), llm.CompletionRequest{}) {
		break // caller stops after the first event
	}
	if in, q := g.Stats(); in != 0 || q != 0 {
		t.Fatalf("slot leaked: inFlight=%d queued=%d", in, q)
	}
}

func TestAcquireCancelWhileQueued(t *testing.T) {
	g := New(1)
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if in, q := g.Stats(); in != 1 || q != 0 {
		t.Fatalf("after cancel: inFlight=%d queued=%d", in, q)
	}
	g.Release()
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.Release()
}

func TestFIFOAndSetLimit(t *testing.T) {
	g := New(1)
	_ = g.Acquire(context.Background())
	order := make(chan int, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_ = g.Acquire(context.Background())
			order <- i
		}()
		// make sure waiter i is queued before i+1
		for {
			if _, q := g.Stats(); q == i+1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	g.Release() // hands the slot to waiter 0
	if got := <-order; got != 0 {
		t.Fatalf("first admitted = %d, want 0", got)
	}
	g.SetLimit(0) // unlimited: everyone else gets in at once
	for range 2 {
		select {
		case <-order:
		case <-time.After(time.Second):
			t.Fatal("SetLimit(0) did not admit waiters")
		}
	}
	if in, q := g.Stats(); in != 3 || q != 0 {
		t.Fatalf("inFlight=%d queued=%d, want 3/0", in, q)
	}
}

func TestNilGateIsPassthrough(t *testing.T) {
	inner := &slowProv{}
	if Wrap(inner, nil) != llm.Provider(inner) {
		t.Fatal("nil gate should return inner unchanged")
	}
}
