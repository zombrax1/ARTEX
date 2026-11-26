"use client";

import * as React from "react";

import { KeyRoundIcon, PlusIcon, TrashIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { TaskCredential } from "@/lib/types";
import { setVisibleInterval } from "@/lib/polling";

import { AccessChecksCard } from "./access-checks";

// Credentials tab (#3): the task's test accounts — user-declared (program alias
// accounts) and agent-recorded (accounts the workers registered themselves).
// Passwords are masked server-side and never sent to the browser.
export function CredentialsTab({ taskId }: { taskId: string }) {
  const [items, setItems] = React.useState<TaskCredential[] | null>(null);
  const [error, setError] = React.useState("");
  const [domain, setDomain] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [note, setNote] = React.useState("");
  const [role, setRole] = React.useState("");
  const [org, setOrg] = React.useState("");
  const [headers, setHeaders] = React.useState("");
  // Session editor: the credential whose headers are being replaced, and the draft.
  const [sessionFor, setSessionFor] = React.useState<number | null>(null);
  const [sessionDraft, setSessionDraft] = React.useState("");
  const [adding, setAdding] = React.useState(false);

  const load = React.useCallback(() => {
    api
      .taskCredentials(taskId)
      .then((r) => {
        setItems(r);
        setError("");
      })
      .catch((e) => setError((e as Error).message));
  }, [taskId]);

  React.useEffect(() => {
    load();
    // Agent runs can record credentials mid-task; a light poll keeps the tab current.
    const stopPolling = setVisibleInterval(load, 15000);
    return stopPolling;
  }, [load]);

  async function add() {
    if (!domain.trim() || !username.trim()) return;
    setAdding(true);
    try {
      await api.addTaskCredential(taskId, {
        domain: domain.trim(),
        username: username.trim(),
        password, // empty = "agent generates and records it"
        note: note.trim(),
        role: role.trim(),
        org: org.trim(),
        auth_headers: headers.trim(),
      });
      setDomain("");
      setUsername("");
      setPassword("");
      setNote("");
      setRole("");
      setOrg("");
      setHeaders("");
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  }

  async function saveSession(id: number, value: string) {
    try {
      await api.setTaskCredentialSession(taskId, id, value.trim());
      setSessionFor(null);
      setSessionDraft("");
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function remove(id: number) {
    try {
      await api.deleteTaskCredential(taskId, id);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("Test accounts")}</CardTitle>
          <CardDescription>
            {t("Test accounts for this task. Entries with an empty password mean the agent registers that account and records it. Agent-recorded accounts appear here automatically.")}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {error ? <p className="text-destructive text-sm">{error}</p> : null}
          {items === null ? (
            <Skeleton className="h-24 w-full" />
          ) : items.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>{t("No test accounts")}</EmptyTitle>
                <EmptyDescription>
                  {t("Add one below, or declare them when creating the task — the agent reuses them for authenticated testing.")}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="flex flex-col divide-y">
              {items.map((c) => (
                <div key={c.id} className="flex flex-wrap items-center gap-2 py-2.5">
                  <code className="text-sm font-medium">{c.domain}</code>
                  <span className="text-muted-foreground text-sm">{c.username}</span>
                  <Badge variant={c.source === "agent" ? "secondary" : "outline"}>
                    {c.source === "agent" ? t("agent-recorded") : t("declared")}
                  </Badge>
                  {c.role ? <Badge variant="outline">{c.role}</Badge> : null}
                  {c.org ? <Badge variant="outline">{c.org}</Badge> : null}
                  {c.auth_headers_set ? <Badge variant="secondary">{t("session saved")}</Badge> : null}
                  <div className="ml-auto flex items-center gap-1">
                    <code className="max-w-40 truncate rounded bg-muted px-2 py-0.5 text-sm">
                      {c.password === "" ? t("— agent generates —") : t("stored, hidden")}
                    </code>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7"
                      aria-label={t("Session headers")}
                      title={t("Session headers")}
                      onClick={() => {
                        setSessionFor(sessionFor === c.id ? null : c.id);
                        setSessionDraft("");
                      }}
                    >
                      <KeyRoundIcon />
                    </Button>
                    <Button size="icon" variant="ghost" className="size-7" aria-label={t("Delete credential")} onClick={() => remove(c.id)}>
                      <TrashIcon />
                    </Button>
                  </div>
                  {c.note ? <p className="text-muted-foreground w-full text-xs">{c.note}</p> : null}
                  {sessionFor === c.id ? (
                    <div className="flex w-full flex-col gap-2">
                      <Textarea
                        rows={3}
                        className="font-mono text-xs"
                        placeholder={t("Cookie: session=... (one header per line)")}
                        value={sessionDraft}
                        onChange={(e) => setSessionDraft(e.target.value)}
                      />
                      <div className="flex gap-2">
                        <Button size="sm" disabled={!sessionDraft.trim()} onClick={() => saveSession(c.id, sessionDraft)}>
                          {t("Save session")}
                        </Button>
                        {c.auth_headers_set ? (
                          <Button size="sm" variant="outline" onClick={() => saveSession(c.id, "")}>
                            {t("Clear session")}
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          )}
          <div className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]">
            <Input placeholder={t("domain (e.g. target.example.com)")} value={domain} onChange={(e) => setDomain(e.target.value)} />
            <Input placeholder={t("email or username")} value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input
              placeholder={t("password (empty = agent generates)")}
              type="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button variant="outline" disabled={adding || !domain.trim() || !username.trim()} onClick={add}>
              <PlusIcon /> {t("Add")}
            </Button>
            <Input placeholder={t("role (optional, e.g. admin)")} value={role} onChange={(e) => setRole(e.target.value)} />
            <Input placeholder={t("organisation (optional)")} value={org} onChange={(e) => setOrg(e.target.value)} />
            <Input className="sm:col-span-2" placeholder={t("note (optional, e.g. program alias account)")} value={note} onChange={(e) => setNote(e.target.value)} />
            <Textarea
              rows={2}
              className="font-mono text-xs sm:col-span-4"
              placeholder={t("session headers (optional), one per line, e.g. Cookie: session=...")}
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
            />
          </div>
          <p className="text-muted-foreground text-xs">
            {t(
              "Role, organisation and session headers let the agent replay a request as each account and flag broken access control. Session headers are stored encrypted, never shown here again, and left out of the account list the agent reads.",
            )}
          </p>
        </CardContent>
      </Card>
      <AccessChecksCard taskId={taskId} />
    </div>
  );
}
