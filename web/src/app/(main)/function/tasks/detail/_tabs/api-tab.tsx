"use client";

import * as React from "react";

import { FileUpIcon, TrashIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import { setVisibleInterval } from "@/lib/polling";
import type { APICoverage, APIOperation, APIOperationStatusName } from "@/lib/types";
import { cn } from "@/lib/utils";

const statusLabel: Record<APIOperationStatusName, string> = {
  tested: t("Tested"),
  skipped: t("Skipped"),
  untested: t("Untested"),
};

const statusClass: Record<APIOperationStatusName, string> = {
  tested: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400",
  skipped: "border-amber-500/50 text-amber-600 dark:text-amber-400",
  untested: "text-muted-foreground",
};

const MAX_FILE_BYTES = 10 * 1024 * 1024;

// ApiTab imports OpenAPI, Swagger or Postman definitions into the task and shows
// which operations were exercised (matched in captured traffic or marked),
// skipped with a reason, or not touched yet.
export function ApiTab({ taskId }: { taskId: string }) {
  const [data, setData] = React.useState<APICoverage | null>(null);
  const [error, setError] = React.useState("");
  const [paste, setPaste] = React.useState("");
  const [importing, setImporting] = React.useState(false);
  const [filter, setFilter] = React.useState<"all" | APIOperationStatusName>("all");
  const [search, setSearch] = React.useState("");
  const fileRef = React.useRef<HTMLInputElement>(null);
  const [skipping, setSkipping] = React.useState<number | null>(null);
  const [skipNote, setSkipNote] = React.useState("");

  const load = React.useCallback(() => {
    api
      .taskAPICoverage(taskId)
      .then((r) => {
        setData(r);
        setError("");
      })
      .catch((e) => setError((e as Error).message));
  }, [taskId]);

  React.useEffect(() => {
    load();
    // Coverage moves as workers send requests; a light poll keeps it current.
    return setVisibleInterval(load, 15000);
  }, [load]);

  async function importContent(content: string, name = "") {
    setImporting(true);
    try {
      const def = await api.importAPIDefinition(taskId, content, name);
      toast.success(t("Imported {name}: {count} operations", { name: def.name || def.format, count: def.operations }));
      setPaste("");
      load();
    } catch (e) {
      toast.error(t("Import failed: {error}", { error: (e as Error).message }));
    } finally {
      setImporting(false);
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    if (f.size > MAX_FILE_BYTES) {
      toast.error(t("The file is larger than 10 MB"));
      return;
    }
    await importContent(await f.text());
  }

  async function removeDefinition(id: number) {
    try {
      await api.deleteAPIDefinition(taskId, id);
      load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function mark(op: APIOperation, value: "" | "tested" | "skipped", note = "") {
    try {
      await api.markAPIOperation(taskId, op.id, value, note);
      setSkipping(null);
      setSkipNote("");
      load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  const ops = (data?.operations ?? []).filter(
    (o) =>
      (filter === "all" || o.status === filter) &&
      (!search || `${o.method} ${o.path} ${o.summary ?? ""}`.toLowerCase().includes(search.toLowerCase())),
  );
  const sum = data?.summary;

  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("API definitions")}</CardTitle>
          <CardDescription>
            {t(
              "Import an OpenAPI 3, Swagger 2 (JSON or YAML) or Postman v2 collection. Agents see the operations and their parameters, and an operation counts as tested when a matching request is captured after the import, or when an agent or you mark it.",
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          {error && <p className="text-destructive text-sm">{error}</p>}
          {data && !data.traffic_capture && (
            <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-amber-600 text-xs dark:text-amber-400">
              {t("Traffic capture is off, so operations are only counted as tested when an agent or you mark them.")}
            </p>
          )}
          {data?.definitions.map((d) => (
            <div key={d.id} className="flex items-center gap-2 text-sm">
              <Badge variant="outline">{d.format}</Badge>
              <span className="font-medium">{d.name || t("(unnamed)")}</span>
              <span className="truncate font-mono text-muted-foreground text-xs">{d.base_url}</span>
              <span className="ml-auto text-muted-foreground text-xs">
                {t("{count} operations", { count: d.operations })}
              </span>
              <Button
                size="icon"
                variant="ghost"
                aria-label={t("Remove definition")}
                onClick={() => void removeDefinition(d.id)}
              >
                <TrashIcon />
              </Button>
            </div>
          ))}
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".json,.yaml,.yml,application/json"
              className="hidden"
              onChange={(e) => void onFile(e)}
            />
            <Button size="sm" variant="outline" disabled={importing} onClick={() => fileRef.current?.click()}>
              <FileUpIcon /> {t("Import file")}
            </Button>
            <span className="text-muted-foreground text-xs">{t("or paste the definition below")}</span>
          </div>
          <Textarea
            rows={4}
            className="font-mono text-xs"
            placeholder={t("Paste OpenAPI, Swagger or Postman JSON/YAML")}
            value={paste}
            onChange={(e) => setPaste(e.target.value)}
          />
          <div className="flex justify-end">
            <Button size="sm" disabled={importing || !paste.trim()} onClick={() => void importContent(paste)}>
              {t("Import")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {data && data.operations.length > 0 && sum && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t("Operations: {tested} tested, {skipped} skipped, {untested} untested of {total}", {
                tested: sum.tested,
                skipped: sum.skipped,
                untested: sum.untested,
                total: sum.total,
              })}
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="flex flex-wrap gap-2">
              <Select value={filter} onValueChange={(v) => setFilter(v as typeof filter)}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("All")}</SelectItem>
                  <SelectItem value="untested">{statusLabel.untested}</SelectItem>
                  <SelectItem value="tested">{statusLabel.tested}</SelectItem>
                  <SelectItem value="skipped">{statusLabel.skipped}</SelectItem>
                </SelectContent>
              </Select>
              <Input
                className="w-64"
                placeholder={t("Filter by path")}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">{t("Method")}</TableHead>
                  <TableHead>{t("Path")}</TableHead>
                  <TableHead>{t("Parameters")}</TableHead>
                  <TableHead className="w-28">{t("Status")}</TableHead>
                  <TableHead className="w-44" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {ops.map((o) => (
                  <TableRow key={o.id}>
                    <TableCell className="font-mono text-xs">{o.method}</TableCell>
                    <TableCell>
                      <div className="font-mono text-xs">{o.path}</div>
                      {o.summary && <div className="text-muted-foreground text-xs">{o.summary}</div>}
                      {o.auth && (
                        <Badge variant="outline" className="mt-1 text-[10px]">
                          {t("auth")}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="max-w-64 text-muted-foreground text-xs">
                      {o.params.map((p) => `${p.name}${p.required ? "*" : ""} (${p.in})`).join(", ") || "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn(statusClass[o.status])} title={o.mark_note || undefined}>
                        {statusLabel[o.status]}
                      </Badge>
                      {o.requests > 0 && (
                        <div className="text-muted-foreground text-xs">
                          {t("{count} requests", { count: o.requests })}
                        </div>
                      )}
                      {o.mark_note && (
                        <div className="max-w-40 truncate text-muted-foreground text-xs">{o.mark_note}</div>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {skipping === o.id ? (
                        <div className="flex gap-1">
                          <Input
                            autoFocus
                            className="h-8 text-xs"
                            placeholder={t("Why is this operation skipped?")}
                            value={skipNote}
                            onChange={(e) => setSkipNote(e.target.value)}
                          />
                          <Button
                            size="sm"
                            disabled={!skipNote.trim()}
                            onClick={() => void mark(o, "skipped", skipNote.trim())}
                          >
                            {t("Skip")}
                          </Button>
                        </div>
                      ) : o.mark ? (
                        <Button size="sm" variant="ghost" onClick={() => void mark(o, "")}>
                          {t("Clear mark")}
                        </Button>
                      ) : (
                        <>
                          <Button size="sm" variant="ghost" onClick={() => void mark(o, "tested")}>
                            {t("Mark tested")}
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => setSkipping(o.id)}>
                            {t("Skip")}
                          </Button>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      {data && data.operations.length === 0 && (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>{t("No API definition imported")}</EmptyTitle>
            <EmptyDescription>
              {t("Import a definition to give agents a list of operations to cover and to track what was tested.")}
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      )}
    </div>
  );
}
