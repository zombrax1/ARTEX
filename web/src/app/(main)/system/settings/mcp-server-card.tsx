"use client";

import * as React from "react";

import { CopyIcon, PlugZapIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { intlLocale, t } from "@/i18n";
import { api } from "@/lib/api";
import type { MCPServerAuditEntry, MCPServerScope, MCPServerSettings, MCPServerToken } from "@/lib/types";
import { copyText } from "@/lib/utils";

const scopeInfo: Record<MCPServerScope, { label: string; hint: string }> = {
  read: { label: t("Read"), hint: t("List tasks and LLM profiles, read findings, graphs and worker traces") },
  "task:create": { label: t("Create tasks"), hint: t("Start new tasks") },
  "task:control": { label: t("Control tasks"), hint: t("Pause and resume tasks, add hints") },
};

const expiryOptions = [
  { value: "30", label: t("30 days") },
  { value: "90", label: t("90 days") },
  { value: "365", label: t("1 year") },
  { value: "0", label: t("Never") },
];

function fmtTime(ts?: string): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(intlLocale);
}

function tokenState(tok: MCPServerToken): { label: string; variant: "secondary" | "destructive" | "outline" } {
  if (tok.revoked_at) return { label: t("Revoked"), variant: "destructive" };
  if (tok.expires_at && new Date(tok.expires_at).getTime() <= Date.now())
    return { label: t("Expired"), variant: "outline" };
  return { label: t("Active"), variant: "secondary" };
}

// McpServerCard turns ARTEX's own MCP endpoint on or off, manages the access
// tokens outside MCP clients use, and shows the latest tool calls they made.
export function McpServerCard() {
  const [cfg, setCfg] = React.useState<MCPServerSettings | null>(null);
  const [audit, setAudit] = React.useState<MCPServerAuditEntry[]>([]);
  const [saving, setSaving] = React.useState(false);
  const [name, setName] = React.useState("");
  const [scopes, setScopes] = React.useState<MCPServerScope[]>(["read"]);
  const [expiry, setExpiry] = React.useState("90");
  const [created, setCreated] = React.useState<string | null>(null);

  const refresh = React.useCallback(() => {
    api
      .mcpServer()
      .then(setCfg)
      .catch((e) => toast.error(t("Failed to load the MCP server settings: {error}", { error: (e as Error).message })));
    api
      .mcpServerAudit(20)
      .then((r) => setAudit(r.entries))
      .catch(() => setAudit([]));
  }, []);
  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const endpoint =
    typeof window === "undefined" ? (cfg?.path ?? "/mcp") : `${window.location.origin}${cfg?.path ?? "/mcp"}`;

  const toggle = (on: boolean) => {
    setSaving(true);
    api
      .setMCPServerEnabled(on)
      .then((next) => {
        setCfg(next);
        toast.success(on ? t("MCP server enabled") : t("MCP server disabled"));
      })
      .catch((e) => toast.error(t("Save failed: {error}", { error: (e as Error).message })))
      .finally(() => setSaving(false));
  };

  const create = () => {
    setSaving(true);
    api
      .createMCPServerToken({ name: name.trim(), scopes, expires_in_days: Number(expiry) })
      .then((r) => {
        setCreated(r.token);
        setName("");
        refresh();
      })
      .catch((e) => toast.error(t("Could not create the token: {error}", { error: (e as Error).message })))
      .finally(() => setSaving(false));
  };

  const act = (fn: () => Promise<unknown>, done: string) => {
    fn()
      .then(() => {
        toast.success(done);
        refresh();
      })
      .catch((e) => toast.error((e as Error).message));
  };

  const copy = async (text: string) => {
    if (await copyText(text)) toast.success(t("Copied"));
    else toast.error(t("Copy failed, select the text and copy it by hand"));
  };

  const claudeCmd = created
    ? `claude mcp add --transport http artex ${endpoint} --header "Authorization: Bearer ${created}"`
    : "";

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <PlugZapIcon className="size-4" />
          {t("ARTEX as an MCP server")}
        </CardTitle>
        <CardDescription>
          {t(
            "Lets an outside agent or MCP client (Claude Code, Claude Desktop, another agent) list tasks, read findings, start tasks and pause or resume them over MCP. Each client needs an access token, and each token can only use the tools its scopes allow. Settings, tools, skills and LLM profiles cannot be changed this way. Every call is logged below. Off by default.",
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex items-center justify-between gap-4">
          <Label htmlFor="mcp-server-enabled" className="font-normal text-sm">
            {t("Accept MCP clients at {endpoint}", { endpoint })}
          </Label>
          <Switch id="mcp-server-enabled" checked={!!cfg?.enabled} disabled={!cfg || saving} onCheckedChange={toggle} />
        </div>

        <div className="flex flex-col gap-3 rounded-md border p-3">
          <span className="font-medium text-sm">{t("New access token")}</span>
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex min-w-48 flex-1 flex-col gap-1">
              <Label htmlFor="mcp-token-name" className="text-muted-foreground text-xs">
                {t("Name")}
              </Label>
              <Input
                id="mcp-token-name"
                value={name}
                maxLength={80}
                placeholder={t("e.g. laptop Claude Code")}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="mcp-token-expiry" className="text-muted-foreground text-xs">
                {t("Expires after")}
              </Label>
              <Select value={expiry} onValueChange={setExpiry}>
                <SelectTrigger id="mcp-token-expiry" className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {expiryOptions.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={create} disabled={saving || !name.trim() || scopes.length === 0}>
              {t("Create token")}
            </Button>
          </div>
          <div className="flex flex-wrap gap-4">
            {(cfg?.scopes ?? (Object.keys(scopeInfo) as MCPServerScope[])).map((sc) => (
              <Label key={sc} className="flex items-start gap-2 font-normal text-sm" title={scopeInfo[sc]?.hint}>
                <Checkbox
                  checked={scopes.includes(sc)}
                  onCheckedChange={(on) =>
                    setScopes((cur) => (on ? [...cur.filter((x) => x !== sc), sc] : cur.filter((x) => x !== sc)))
                  }
                />
                <span className="flex flex-col">
                  <span>{scopeInfo[sc]?.label ?? sc}</span>
                  <span className="text-muted-foreground text-xs">{scopeInfo[sc]?.hint}</span>
                </span>
              </Label>
            ))}
          </div>
          {created && (
            <div className="flex flex-col gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
              <span className="font-medium">{t("Copy the token now. It is not shown again.")}</span>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded bg-background px-2 py-1 font-mono">{created}</code>
                <Button variant="outline" size="sm" onClick={() => copy(created)}>
                  <CopyIcon data-icon="inline-start" />
                  {t("Copy")}
                </Button>
              </div>
              <span className="text-muted-foreground">{t("Add it to Claude Code:")}</span>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded bg-background px-2 py-1 font-mono">{claudeCmd}</code>
                <Button variant="outline" size="sm" onClick={() => copy(claudeCmd)}>
                  <CopyIcon data-icon="inline-start" />
                  {t("Copy")}
                </Button>
              </div>
              <Button variant="ghost" size="sm" className="self-end" onClick={() => setCreated(null)}>
                {t("Done")}
              </Button>
            </div>
          )}
        </div>

        {cfg?.tokens.length ? (
          <Table aria-label={t("MCP access tokens")}>
            <TableHeader>
              <TableRow>
                <TableHead>{t("Name")}</TableHead>
                <TableHead>{t("Scopes")}</TableHead>
                <TableHead>{t("Last used")}</TableHead>
                <TableHead className="text-right">{t("Actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {cfg.tokens.map((tok) => {
                const st = tokenState(tok);
                return (
                  <TableRow key={tok.id}>
                    <TableCell className="max-w-44">
                      <div className="truncate" title={tok.name}>
                        {tok.name} <span className="font-mono text-muted-foreground text-xs">…{tok.hint}</span>
                      </div>
                      <div className="mt-0.5 flex items-center gap-1.5 text-muted-foreground text-xs">
                        <Badge variant={st.variant}>{st.label}</Badge>
                        <span>
                          {tok.expires_at ? t("Expires {date}", { date: fmtTime(tok.expires_at) }) : t("Never expires")}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs">
                      {tok.scopes.map((sc) => scopeInfo[sc]?.label ?? sc).join(", ")}
                    </TableCell>
                    <TableCell className="text-xs">{fmtTime(tok.last_used_at)}</TableCell>
                    <TableCell className="text-right">
                      {/* Revoke first; a revoked token can then be deleted, so one click never removes a working token. */}
                      {tok.revoked_at ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => act(() => api.deleteMCPServerToken(tok.id), t("Token deleted"))}
                        >
                          {t("Delete")}
                        </Button>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => act(() => api.revokeMCPServerToken(tok.id), t("Token revoked"))}
                        >
                          {t("Revoke")}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        ) : (
          <p className="text-muted-foreground text-xs">{t("No access tokens yet.")}</p>
        )}

        <div className="flex items-center justify-between gap-4">
          <span className="font-medium text-sm">{t("Recent MCP calls")}</span>
          <Button variant="outline" size="sm" onClick={refresh}>
            <RefreshCwIcon data-icon="inline-start" />
            {t("Refresh")}
          </Button>
        </div>
        {audit.length ? (
          <Table aria-label={t("Recent MCP calls")}>
            <TableHeader>
              <TableRow>
                <TableHead>{t("Time")}</TableHead>
                <TableHead>{t("Token")}</TableHead>
                <TableHead>{t("Tool")}</TableHead>
                <TableHead>{t("Result")}</TableHead>
                <TableHead className="text-right">{t("Duration")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audit.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="text-xs">{fmtTime(a.ts)}</TableCell>
                  <TableCell className="max-w-32 truncate text-xs" title={a.remote_addr}>
                    {a.token_name}
                  </TableCell>
                  <TableCell className="font-mono text-xs" title={a.args}>
                    {a.tool}
                  </TableCell>
                  <TableCell className="max-w-64 truncate text-xs" title={a.result}>
                    {a.ok ? (
                      <span className="text-emerald-600 dark:text-emerald-400">{t("OK")}</span>
                    ) : (
                      <span className="text-red-600 dark:text-red-400">{a.result || t("Error")}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right text-xs">{a.duration_ms} ms</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <p className="text-muted-foreground text-xs">{t("No MCP calls yet.")}</p>
        )}
      </CardContent>
    </Card>
  );
}
