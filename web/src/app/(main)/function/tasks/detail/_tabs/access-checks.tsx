"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import { setVisibleInterval } from "@/lib/polling";
import type { AccessCheck, AccessFlag, AccessFlagKind } from "@/lib/types";

function flagLabel(kind: AccessFlagKind): string {
  switch (kind) {
    case "unauthenticated_access":
      return t("No session");
    case "cross_org_access":
      return t("Other organisation");
    case "cross_role_access":
      return t("Other role");
    case "cross_user_access":
      return t("Other user");
  }
}

function statusVariant(status: number): "secondary" | "outline" | "destructive" {
  if (status >= 200 && status < 300) return "secondary";
  if (status === 0) return "destructive";
  return "outline";
}

// AccessChecksCard lists the compare_access results of a task: one request
// replayed as each test account and without a session, with the accounts that
// got the owner's response flagged.
export function AccessChecksCard({ taskId }: { taskId: string }) {
  const [items, setItems] = React.useState<AccessCheck[] | null>(null);
  const [error, setError] = React.useState("");

  const load = React.useCallback(() => {
    api
      .taskAccessChecks(taskId)
      .then((r) => {
        setItems(r);
        setError("");
      })
      .catch((e) => setError((e as Error).message));
  }, [taskId]);

  React.useEffect(() => {
    load();
    return setVisibleInterval(load, 15000);
  }, [load]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("Access comparisons")}</CardTitle>
        <CardDescription>
          {t(
            "Requests replayed as each test account with saved session headers, and once without a session. A flagged account got the owner's response although its role or organisation differs. A flag is a lead to confirm, not a finding.",
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <AccessCheckList items={items} />
      </CardContent>
    </Card>
  );
}

function AccessCheckList({ items }: { items: AccessCheck[] | null }) {
  if (items === null) return <Skeleton className="h-24 w-full" />;
  if (items.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyTitle>{t("No comparisons yet")}</EmptyTitle>
          <EmptyDescription>
            {t(
              "Save session headers on two or more test accounts. The agent then compares what each account can reach with the compare_access tool.",
            )}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }
  return items.map((c) => <AccessCheckRow key={c.id} check={c} />);
}

function AccessCheckRow({ check }: { check: AccessCheck }) {
  const flagged = new Map<string, AccessFlag>();
  for (const f of check.flags) flagged.set(f.account, f);
  return (
    <div className="flex flex-col gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">{check.method}</Badge>
        <code className="min-w-0 flex-1 truncate text-sm" title={check.url}>
          {check.url}
        </code>
        {check.flags.length > 0 ? (
          <Badge variant="destructive">
            {check.flags.length} {t("flagged")}
          </Badge>
        ) : (
          <Badge variant="secondary">{t("no flags")}</Badge>
        )}
        <span className="text-xs text-muted-foreground">{new Date(check.created_at).toLocaleString()}</span>
      </div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("Account")}</TableHead>
              <TableHead>{t("Role")}</TableHead>
              <TableHead>{t("Organisation")}</TableHead>
              <TableHead>{t("Status")}</TableHead>
              <TableHead>{t("Size")}</TableHead>
              <TableHead>{t("Result")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {check.results.map((r) => {
              const isOwner = r.credential_id != null && r.credential_id === check.owner_id;
              const flag = flagged.get(r.account);
              return (
                <TableRow key={r.credential_id ?? "anonymous"} className={flag ? "bg-destructive/5" : undefined}>
                  <TableCell className="font-medium">
                    {r.credential_id == null ? t("anonymous") : r.account}
                    {isOwner ? (
                      <Badge variant="outline" className="ml-2">
                        {t("owner")}
                      </Badge>
                    ) : null}
                  </TableCell>
                  <TableCell>{r.role || "-"}</TableCell>
                  <TableCell>{r.org || "-"}</TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(r.status)}>{r.status || t("error")}</Badge>
                  </TableCell>
                  <TableCell className="tabular-nums">{r.error ? "-" : r.length}</TableCell>
                  <TableCell className="max-w-80 text-xs">
                    {flag ? (
                      <span className="text-destructive" title={flag.detail}>
                        {flagLabel(flag.kind)} ({flag.match === "identical" ? t("identical") : t("similar")})
                      </span>
                    ) : (
                      <span className="block truncate text-muted-foreground" title={r.error || r.snippet}>
                        {r.error || r.snippet || ""}
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {check.flags.map((f) => (
        <p key={`${f.kind}-${f.account}`} className="text-xs text-destructive">
          {f.detail}
        </p>
      ))}
    </div>
  );
}
