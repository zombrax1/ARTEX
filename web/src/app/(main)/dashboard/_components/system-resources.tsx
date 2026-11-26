"use client";

import * as React from "react";

import { CpuIcon, GaugeIcon, HardDriveIcon, MemoryStickIcon, MonitorIcon } from "lucide-react";

import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import { setVisibleInterval } from "@/lib/polling";
import type { SystemMetrics, SystemMetricValue } from "@/lib/types";
import { cn } from "@/lib/utils";

// fmtGB renders a byte count in GB (or MB below 1 GB) for the resource rows.
function fmtGB(bytes: number): string {
  if (bytes >= 1024 ** 3) {
    const v = bytes / 1024 ** 3;
    return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} GB`;
  }
  return `${Math.round(bytes / 1024 ** 2)} MB`;
}

function barColor(percent: number): string {
  if (percent >= 90) return "[&>div]:bg-red-500";
  if (percent >= 75) return "[&>div]:bg-amber-500";
  return "";
}

function ResourceRow({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: React.ElementType;
  label: string;
  value: SystemMetricValue;
  detail?: string;
}) {
  const sizes =
    value.total_bytes && value.total_bytes > 0
      ? t("{used} of {total}", { used: fmtGB(value.used_bytes ?? 0), total: fmtGB(value.total_bytes) })
      : "";
  return (
    <div className="flex flex-col gap-1" title={detail}>
      <div className="flex items-center justify-between gap-2 text-[11px]">
        <span className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
          <Icon className="size-3 shrink-0" />
          <span className="truncate">{label}</span>
        </span>
        <span className="shrink-0 tabular-nums">
          {sizes && <span className="mr-1.5 text-muted-foreground">{sizes}</span>}
          {value.percent.toFixed(0)}%
        </span>
      </div>
      <Progress value={value.percent} className={cn("h-1.5", barColor(value.percent))} />
    </div>
  );
}

// SystemResources shows how loaded the machine running ARTEX is: CPU, memory,
// the disk holding the data directory, and each GPU's memory when the host has
// nvidia-smi or rocm-smi. Rows the host cannot report are left out.
export function SystemResources() {
  const [metrics, setMetrics] = React.useState<SystemMetrics | null>(null);
  const [failed, setFailed] = React.useState(false);

  React.useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const next = await api.systemMetrics();
        if (!alive) return;
        setMetrics(next);
        setFailed(false);
      } catch {
        if (alive) setFailed(true);
      }
    };
    void load();
    const stop = setVisibleInterval(load, 5000);
    return () => {
      alive = false;
      stop();
    };
  }, []);

  if (!metrics) return null;
  const gpus = metrics.gpus ?? [];
  const nothing = !metrics.cpu && !metrics.memory && !metrics.disk && gpus.length === 0;
  if (nothing) return null;

  return (
    <Card className="gap-2">
      <CardHeader className="pb-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 font-semibold text-xs">
            <GaugeIcon className="size-3.5 text-muted-foreground" />
            {t("This machine")}
          </div>
          {failed && <span className="text-[10px] text-amber-500">{t("Not updating")}</span>}
        </div>
      </CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {metrics.cpu && <ResourceRow icon={CpuIcon} label={t("CPU")} value={metrics.cpu} />}
        {metrics.memory && <ResourceRow icon={MemoryStickIcon} label={t("Memory")} value={metrics.memory} />}
        {metrics.disk && (
          <ResourceRow icon={HardDriveIcon} label={t("Data disk")} value={metrics.disk} detail={metrics.disk_path} />
        )}
        {gpus.map((g) => (
          <ResourceRow
            key={g.index}
            icon={MonitorIcon}
            label={t("GPU {index} memory · {name}", { index: g.index, name: g.name })}
            value={{ used_bytes: g.memory_used_bytes, total_bytes: g.memory_total_bytes, percent: g.memory_percent }}
            detail={
              g.util_percent !== undefined
                ? `${g.name} · ${t("GPU {index} busy {percent}%", { index: g.index, percent: g.util_percent.toFixed(0) })}`
                : g.name
            }
          />
        ))}
        {gpus.length === 0 && (
          <div className="flex items-center gap-1.5 self-end text-[11px] text-muted-foreground">
            <MonitorIcon className="size-3 shrink-0" />
            {t("No GPU reported (needs nvidia-smi or rocm-smi)")}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
