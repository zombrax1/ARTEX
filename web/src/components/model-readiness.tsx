"use client";

import * as React from "react";

import { CheckCircle2Icon, FlaskConicalIcon, TriangleAlertIcon, XCircleIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Spinner } from "@/components/ui/spinner";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { LLMProfile, ReadinessReport, ReadinessVerdict } from "@/lib/types";
import { cn } from "@/lib/utils";

const verdictLabel: Record<ReadinessVerdict, string> = {
  ready: t("Tools: ready"),
  limited: t("Tools: limited"),
  not_ready: t("Tools: not ready"),
};

const verdictClass: Record<ReadinessVerdict, string> = {
  ready: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400",
  limited: "border-amber-500/50 text-amber-600 dark:text-amber-400",
  not_ready: "border-destructive/50 text-destructive",
};

const checkLabel: Record<string, string> = {
  tool_call: t("Single tool call with typed arguments"),
  task: t("Short multi-step task (fetch, read the result, report)"),
};

// useReadiness loads the last readiness result of every profile.
export function useReadiness() {
  const [results, setResults] = React.useState<Record<string, ReadinessReport>>({});
  const reload = React.useCallback(() => {
    api
      .llmReadiness()
      .then((r) => setResults(r ?? {}))
      .catch(() => setResults({}));
  }, []);
  React.useEffect(() => {
    reload();
  }, [reload]);
  return { results, reload };
}

// isStale reports whether a result was measured on a different model than the
// profile now uses. The server says so too, but a profile edited on this page
// changes before the stored results are fetched again.
export function isStale(report: ReadinessReport, model?: string) {
  return report.stale || (model !== undefined && report.model !== model);
}

// ReadinessBadge shows a profile's last measured tool readiness.
export function ReadinessBadge({ report, model }: { report?: ReadinessReport; model?: string }) {
  if (!report) {
    return (
      <Badge variant="outline" className="text-muted-foreground" title={t("The model readiness test has not been run")}>
        {t("Tools: untested")}
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className={cn(report.stale ? "text-muted-foreground" : verdictClass[report.verdict])}
      title={
        report.stale
          ? t("Tested on {model}; the profile now uses another model", { model: report.model })
          : report.summary
      }
    >
      {report.stale ? t("Tools: retest") : verdictLabel[report.verdict]}
    </Badge>
  );
}

type Advertised = { state: "loading" } | { state: "known"; tools: boolean } | { state: "unknown"; note: string };

// ReadinessDialog runs the readiness test on one profile and shows the measured
// result next to what the provider advertises.
export function ReadinessDialog({
  profile,
  report,
  open,
  onOpenChange,
  onTested,
}: {
  profile: LLMProfile | null;
  report?: ReadinessReport;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onTested: () => void;
}) {
  const [running, setRunning] = React.useState(false);
  const [current, setCurrent] = React.useState<ReadinessReport | undefined>(report);
  const [advertised, setAdvertised] = React.useState<Advertised>({ state: "loading" });

  React.useEffect(() => {
    if (open) setCurrent(report);
  }, [open, report]);

  React.useEffect(() => {
    if (!open || !profile) return;
    if (profile.format !== "ollama") {
      setAdvertised({ state: "unknown", note: t("This provider does not report tool support per model.") });
      return;
    }
    setAdvertised({ state: "loading" });
    api
      .fetchLLMModels(profile.format, profile.base_url ?? "", "", "", Number(profile.id))
      .then((r) => {
        const tools = r.details?.[profile.model]?.tools;
        setAdvertised(
          tools === undefined
            ? { state: "unknown", note: t("The server did not report tool support for this model.") }
            : { state: "known", tools },
        );
      })
      .catch(() => setAdvertised({ state: "unknown", note: t("The model list could not be read.") }));
  }, [open, profile]);

  const run = () => {
    if (!profile) return;
    setRunning(true);
    api
      .runLLMReadiness(profile.id)
      .then((r) => {
        if (!r.ok || !r.report) {
          toast.error(t("Readiness test failed: {error}", { error: r.error ?? "?" }));
          return;
        }
        setCurrent(r.report);
        onTested();
      })
      .catch((e) => toast.error(t("Readiness test failed: {error}", { error: (e as Error).message })))
      .finally(() => setRunning(false));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FlaskConicalIcon className="size-4" />
            {t("Model readiness")}
          </DialogTitle>
          <DialogDescription>
            {t(
              "Sends two short prompts to {model} with stub tools and checks what it actually does: whether it calls the tool, with valid arguments, and whether it can finish a short multi-step task. No command is run. The test uses this profile's concurrency limit, so on a busy local model it waits its turn.",
              { model: profile?.model ?? "" },
            )}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 text-sm">
          <div className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2">
            <span className="text-muted-foreground">{t("Advertised")}</span>
            <span>
              {advertised.state === "loading" && <Spinner className="inline size-3" />}
              {advertised.state === "known" &&
                (advertised.tools ? t("Tool support reported") : t("No tool support reported"))}
              {advertised.state === "unknown" && <span className="text-muted-foreground">{advertised.note}</span>}
            </span>
            <span className="text-muted-foreground">{t("Measured")}</span>
            <span>
              {current ? (
                <>
                  <ReadinessBadge report={current} model={profile?.model} /> <span className="text-muted-foreground">{current.summary}</span>
                  <span className="block text-muted-foreground text-xs">
                    {t("{model} · tested {time} · {seconds}s", {
                      model: current.model,
                      time: new Date(current.tested_at).toLocaleString(),
                      seconds: Math.round(current.latency_ms / 100) / 10,
                    })}
                  </span>
                </>
              ) : (
                <span className="text-muted-foreground">{t("Not tested yet.")}</span>
              )}
            </span>
          </div>
          {current?.checks.map((c) => (
            <div key={c.id} className="grid gap-1 rounded-md border p-3">
              <div className="flex items-center gap-2 font-medium">
                {c.passed ? (
                  <CheckCircle2Icon className="size-4 text-emerald-600" />
                ) : (
                  <XCircleIcon className="size-4 text-destructive" />
                )}
                {checkLabel[c.id] ?? c.id}
                <span className="ml-auto text-muted-foreground text-xs">{Math.round(c.latency_ms / 100) / 10}s</span>
              </div>
              {c.problems?.map((p) => (
                <p key={p} className="flex gap-1 text-xs">
                  <TriangleAlertIcon className="mt-0.5 size-3 shrink-0 text-amber-600" />
                  {p}
                </p>
              ))}
              {c.calls && c.calls.length > 0 && (
                <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 font-mono text-xs">
                  {c.calls.join("\n")}
                </pre>
              )}
              {!c.passed && c.reply && (
                <p className="break-words text-muted-foreground text-xs">{t("Reply: {reply}", { reply: c.reply })}</p>
              )}
            </div>
          ))}
        </div>
        <DialogFooter>
          <Button onClick={run} disabled={running || !profile}>
            {running ? <Spinner /> : <FlaskConicalIcon />}
            {running ? t("Testing…") : current ? t("Run again") : t("Run test")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ReadinessWarning lists the chosen profiles whose model failed, partly failed or
// was never put through the readiness test, before a task is started on them.
export function ReadinessWarning({ profiles, ids }: { profiles: LLMProfile[]; ids: string[] }) {
  const { results } = useReadiness();
  const chosen = ids.length > 0 ? profiles.filter((p) => ids.includes(p.id)) : profiles.filter((p) => p.is_default);
  const flagged = chosen.filter((p) => {
    const r = results[p.id];
    return !r || isStale(r, p.model) || r.verdict !== "ready";
  });
  if (flagged.length === 0) return null;
  const failing = flagged.filter(
    (p) => results[p.id] && !isStale(results[p.id], p.model) && results[p.id].verdict === "not_ready",
  );
  return (
    <p
      className={cn(
        "rounded-md border px-3 py-2 text-xs",
        failing.length > 0
          ? "border-destructive/30 bg-destructive/10 text-destructive"
          : "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
      )}
    >
      {failing.length > 0
        ? t("Failed the model readiness test: {names}. Agents on this model cannot call tools reliably.", {
            names: failing.map((p) => p.name).join(", "),
          })
        : t("Not confirmed by the model readiness test: {names}. Run it under System → LLM before a long task.", {
            names: flagged.map((p) => p.name).join(", "),
          })}
    </p>
  );
}
