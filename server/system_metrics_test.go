package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestParseNvidiaSMI(t *testing.T) {
	out := "0, NVIDIA GeForce RTX 4080, 6144, 16376, 37\n1, Tesla T4, 100, 15360, [N/A]\n2, Broken, [N/A], [N/A], 5\n\n"
	g := parseNvidiaSMI(out)
	if len(g) != 2 {
		t.Fatalf("got %d GPUs, want 2: %+v", len(g), g)
	}
	if g[0].Name != "NVIDIA GeForce RTX 4080" || g[0].MemUsed != 6144*mib || g[0].MemTotal != 16376*mib {
		t.Fatalf("first GPU: %+v", g[0])
	}
	if g[0].UtilPercent == nil || *g[0].UtilPercent != 37 {
		t.Fatalf("first GPU utilization: %+v", g[0].UtilPercent)
	}
	if g[1].UtilPercent != nil {
		t.Fatalf("[N/A] utilization must be left out, got %v", *g[1].UtilPercent)
	}
	if g[1].Index != 1 || g[1].MemPercent <= 0 || g[1].MemPercent >= 1 {
		t.Fatalf("second GPU: %+v", g[1])
	}
}

func TestParseROCmSMI(t *testing.T) {
	out := []byte(`{
	  "card1": {"Card series": "Radeon RX 6800", "VRAM Total Memory (B)": "17163091968", "VRAM Total Used Memory (B)": "1073741824", "GPU use (%)": "12"},
	  "card0": {"Card SKU": "D41205", "VRAM Total Memory (B)": "8573157376", "VRAM Total Used Memory (B)": "8573157376"},
	  "system": {"Driver version": "6.7"}
	}`)
	g := parseROCmSMI(out)
	if len(g) != 2 {
		t.Fatalf("got %d GPUs, want 2: %+v", len(g), g)
	}
	if g[0].Index != 0 || g[0].MemPercent != 100 || g[0].UtilPercent != nil || g[0].Name != "D41205" {
		t.Fatalf("card0: %+v", g[0])
	}
	if g[1].Index != 1 || g[1].Name != "Radeon RX 6800" || g[1].MemUsed != 1073741824 || g[1].UtilPercent == nil || *g[1].UtilPercent != 12 {
		t.Fatalf("card1: %+v", g[1])
	}
	if parseROCmSMI([]byte("not json")) != nil {
		t.Fatal("bad JSON must give no GPUs")
	}
}

func fakeCollector(t *testing.T, tools map[string]string) (*systemMetricsCollector, *int) {
	t.Helper()
	calls := 0
	c := newSystemMetricsCollector(filepath.Join(t.TempDir(), "not-created-yet"))
	c.lookPath = func(name string) (string, error) {
		if _, ok := tools[name]; ok {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	c.run = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		calls++
		out, ok := tools[filepath.Base(name)]
		if !ok || out == "FAIL" {
			return nil, errors.New("exit status 9")
		}
		return []byte(out), nil
	}
	return c, &calls
}

func TestSystemMetricsWithoutGPUTool(t *testing.T) {
	c, calls := fakeCollector(t, nil)
	got := c.snapshot(context.Background())
	if len(got.GPUs) != 0 || got.GPUSource != "" || *calls != 0 {
		t.Fatalf("no GPU tool: gpus=%+v source=%q calls=%d", got.GPUs, got.GPUSource, *calls)
	}
	if got.Disk == nil || got.Disk.TotalBytes == 0 {
		t.Fatalf("disk of the nearest existing parent of the data dir is missing: %+v", got.Disk)
	}
	if got.Memory == nil || got.Memory.TotalBytes == 0 {
		t.Fatalf("memory missing: %+v", got.Memory)
	}
}

func TestSystemMetricsFallsBackToROCmWhenNvidiaFails(t *testing.T) {
	c, _ := fakeCollector(t, map[string]string{
		"nvidia-smi": "FAIL",
		"rocm-smi":   `{"card0": {"Card series": "RX", "VRAM Total Memory (B)": "100", "VRAM Total Used Memory (B)": "25"}}`,
	})
	got := c.snapshot(context.Background())
	if got.GPUSource != "rocm-smi" || len(got.GPUs) != 1 || got.GPUs[0].MemPercent != 25 {
		t.Fatalf("got %+v from %q", got.GPUs, got.GPUSource)
	}
}

func TestSystemMetricsCachesSnapshots(t *testing.T) {
	c, calls := fakeCollector(t, map[string]string{"nvidia-smi": "0, GPU, 1, 2, 3"})
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.snapshot(context.Background())
	c.snapshot(context.Background())
	if *calls != 1 {
		t.Fatalf("a second poll inside the TTL ran the GPU tool again: %d calls", *calls)
	}
	now = now.Add(systemMetricsTTL)
	c.snapshot(context.Background())
	if *calls != 1 {
		t.Fatalf("the GPU reading is reused until its own TTL: %d calls", *calls)
	}
	now = now.Add(gpuMetricsTTL)
	c.snapshot(context.Background())
	if *calls != 2 {
		t.Fatalf("GPU tool should run again after its TTL: %d calls", *calls)
	}
}

func TestSystemMetricsGPUOff(t *testing.T) {
	t.Setenv("ARTEX_GPU_METRICS", "off")
	c, calls := fakeCollector(t, map[string]string{"nvidia-smi": "0, GPU, 1, 2, 3"})
	if got := c.snapshot(context.Background()); len(got.GPUs) != 0 || *calls != 0 {
		t.Fatalf("ARTEX_GPU_METRICS=off still read GPUs: %+v calls=%d", got.GPUs, *calls)
	}
}

func TestSystemMetricsHandler(t *testing.T) {
	c, _ := fakeCollector(t, nil)
	s := &Server{sysMetrics: c}
	w := httptest.NewRecorder()
	s.systemMetrics(w, httptest.NewRequest("GET", "/api/system/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if gpus, ok := body["gpus"].([]any); !ok || len(gpus) != 0 {
		t.Fatalf("gpus must be an empty list, not null: %v", body["gpus"])
	}
}
