package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// GET /api/system/metrics reports how busy the machine running ARTEX is: CPU,
// memory, the disk that holds the data directory, and the memory of each GPU
// when a vendor tool can report it. Every part is optional: a value the host
// cannot report is left out (null) instead of failing the call, so the same
// endpoint works on Linux, macOS and Windows, in a container or natively, with
// an NVIDIA GPU, an AMD GPU or none.
//
// GPUs are read with nvidia-smi or rocm-smi when one is on PATH. Set
// ARTEX_GPU_METRICS=off to never run either.

type metricValue struct {
	UsedBytes  uint64  `json:"used_bytes,omitempty"`
	TotalBytes uint64  `json:"total_bytes,omitempty"`
	Percent    float64 `json:"percent"`
}

type gpuMetric struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	MemUsed     uint64   `json:"memory_used_bytes"`
	MemTotal    uint64   `json:"memory_total_bytes"`
	MemPercent  float64  `json:"memory_percent"`
	UtilPercent *float64 `json:"util_percent,omitempty"`
}

type systemMetricsResponse struct {
	Timestamp time.Time    `json:"timestamp"`
	CPU       *metricValue `json:"cpu"`
	Memory    *metricValue `json:"memory"`
	Disk      *metricValue `json:"disk"`
	DiskPath  string       `json:"disk_path,omitempty"`
	GPUs      []gpuMetric  `json:"gpus"`
	GPUSource string       `json:"gpu_source,omitempty"` // "nvidia-smi", "rocm-smi" or empty when no GPU was read
}

const (
	systemMetricsTTL = 2 * time.Second // several open tabs share one sample
	gpuMetricsTTL    = 5 * time.Second // vendor tools are slow to start
	gpuQueryTimeout  = 3 * time.Second
)

// systemMetricsCollector caches the last snapshot so polling from several
// browser tabs neither spawns a GPU tool per request nor skews the CPU delta.
type systemMetricsCollector struct {
	dir string

	mu     sync.Mutex
	at     time.Time
	last   systemMetricsResponse
	gpuAt  time.Time
	gpus   []gpuMetric
	gpuSrc string

	// replaced in tests
	lookPath func(string) (string, error)
	run      func(ctx context.Context, name string, args ...string) ([]byte, error)
	now      func() time.Time
}

func newSystemMetricsCollector(dataDir string) *systemMetricsCollector {
	return &systemMetricsCollector{
		dir:      dataDir,
		lookPath: exec.LookPath,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
		now: time.Now,
	}
}

func (s *Server) systemMetrics(w http.ResponseWriter, r *http.Request) {
	if s.sysMetrics == nil {
		writeJSON(w, 200, systemMetricsResponse{Timestamp: time.Now().UTC(), GPUs: []gpuMetric{}})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, s.sysMetrics.snapshot(r.Context()))
}

func (c *systemMetricsCollector) snapshot(ctx context.Context) systemMetricsResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.at.IsZero() && now.Sub(c.at) < systemMetricsTTL {
		return c.last
	}
	out := systemMetricsResponse{Timestamp: now.UTC(), GPUs: []gpuMetric{}}

	// Percent with interval 0 compares against the previous call (the first call
	// against process start), so it never blocks the request.
	if p, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(p) == 1 {
		out.CPU = &metricValue{Percent: clampPercent(p[0])}
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm.Total > 0 {
		out.Memory = &metricValue{UsedBytes: vm.Used, TotalBytes: vm.Total, Percent: clampPercent(vm.UsedPercent)}
	}
	if dir := c.diskDir(); dir != "" {
		if du, err := disk.UsageWithContext(ctx, dir); err == nil && du.Total > 0 {
			out.Disk = &metricValue{UsedBytes: du.Used, TotalBytes: du.Total, Percent: clampPercent(du.UsedPercent)}
			out.DiskPath = dir
		}
	}
	if c.gpuAt.IsZero() || now.Sub(c.gpuAt) >= gpuMetricsTTL {
		c.gpus, c.gpuSrc = c.readGPUs(ctx)
		c.gpuAt = now
	}
	if len(c.gpus) > 0 {
		out.GPUs = c.gpus
		out.GPUSource = c.gpuSrc
	}
	c.at, c.last = now, out
	return out
}

// diskDir is the data directory, or the nearest existing parent when it has not
// been created yet.
func (c *systemMetricsCollector) diskDir() string {
	if c.dir == "" {
		return ""
	}
	d, err := filepath.Abs(c.dir)
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(d); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

func gpuMetricsDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_GPU_METRICS"))) {
	case "off", "0", "false", "no", "disabled":
		return true
	}
	return false
}

// readGPUs asks nvidia-smi, then rocm-smi. A missing tool, a failing tool or
// output it cannot parse all mean "no GPU data", never an error.
func (c *systemMetricsCollector) readGPUs(ctx context.Context) ([]gpuMetric, string) {
	if gpuMetricsDisabled() {
		return nil, ""
	}
	if p, err := c.lookPath("nvidia-smi"); err == nil {
		qctx, cancel := context.WithTimeout(ctx, gpuQueryTimeout)
		b, err := c.run(qctx, p, "--query-gpu=index,name,memory.used,memory.total,utilization.gpu", "--format=csv,noheader,nounits")
		cancel()
		if err == nil {
			if g := parseNvidiaSMI(string(b)); len(g) > 0 {
				return g, "nvidia-smi"
			}
		}
	}
	if p, err := c.lookPath("rocm-smi"); err == nil {
		qctx, cancel := context.WithTimeout(ctx, gpuQueryTimeout)
		b, err := c.run(qctx, p, "--showproductname", "--showmeminfo", "vram", "--showuse", "--json")
		cancel()
		if err == nil {
			if g := parseROCmSMI(b); len(g) > 0 {
				return g, "rocm-smi"
			}
		}
	}
	return nil, ""
}

const mib = 1024 * 1024

// parseNvidiaSMI reads `index, name, memory.used, memory.total, utilization.gpu`
// lines (MiB and percent, no units). A field nvidia-smi cannot read on a given
// card comes back as "[N/A]" or "[Not Supported]": the memory pair is required,
// utilization is optional.
func parseNvidiaSMI(out string) []gpuMetric {
	var gpus []gpuMetric
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, ",")
		if len(f) < 4 {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		idx, err1 := strconv.Atoi(f[0])
		used, err2 := strconv.ParseFloat(f[2], 64)
		total, err3 := strconv.ParseFloat(f[3], 64)
		if err1 != nil || err2 != nil || err3 != nil || total <= 0 || used < 0 {
			continue
		}
		g := gpuMetric{Index: idx, Name: f[1], MemUsed: uint64(used * mib), MemTotal: uint64(total * mib)}
		g.MemPercent = clampPercent(used / total * 100)
		if len(f) >= 5 {
			if u, err := strconv.ParseFloat(f[4], 64); err == nil {
				u = clampPercent(u)
				g.UtilPercent = &u
			}
		}
		gpus = append(gpus, g)
	}
	return gpus
}

// parseROCmSMI reads `rocm-smi --showproductname --showmeminfo vram --showuse
// --json`: an object keyed by card ("card0") whose values are strings. Key
// names differ slightly between ROCm releases, so they are matched loosely.
func parseROCmSMI(out []byte) []gpuMetric {
	var cards map[string]map[string]any
	if err := json.Unmarshal(out, &cards); err != nil {
		return nil
	}
	keys := make([]string, 0, len(cards))
	for k := range cards {
		if strings.HasPrefix(strings.ToLower(k), "card") {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return cardIndex(keys[i]) < cardIndex(keys[j]) })
	var gpus []gpuMetric
	for _, k := range keys {
		var used, total float64
		var name string
		var util *float64
		for field, raw := range cards[k] {
			v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(toString(raw)), "%"))
			lf := strings.ToLower(field)
			switch {
			case strings.Contains(lf, "vram total used memory"):
				used, _ = strconv.ParseFloat(v, 64)
			case strings.Contains(lf, "vram total memory"):
				total, _ = strconv.ParseFloat(v, 64)
			case strings.Contains(lf, "gpu use"):
				if u, err := strconv.ParseFloat(v, 64); err == nil {
					u = clampPercent(u)
					util = &u
				}
			case lf == "card series" || lf == "card model" || lf == "card sku":
				if name == "" || lf == "card series" {
					name = v
				}
			}
		}
		if total <= 0 || used < 0 {
			continue
		}
		if name == "" {
			name = "AMD GPU"
		}
		gpus = append(gpus, gpuMetric{Index: cardIndex(k), Name: name, MemUsed: uint64(used), MemTotal: uint64(total),
			MemPercent: clampPercent(used / total * 100), UtilPercent: util})
	}
	return gpus
}

func cardIndex(k string) int {
	n, err := strconv.Atoi(strings.TrimLeft(strings.ToLower(k), "card"))
	if err != nil {
		return 1 << 20
	}
	return n
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func clampPercent(v float64) float64 {
	if v != v || v < 0 { // NaN or negative
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
