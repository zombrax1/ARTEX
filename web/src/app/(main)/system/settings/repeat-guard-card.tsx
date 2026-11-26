"use client";

import * as React from "react";

import { RepeatIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { RepeatGuardLimits } from "@/lib/types";

type NumberField = Exclude<keyof RepeatGuardLimits, "enabled">;

const fields: { key: NumberField; label: string; hint: string }[] = [
  {
    key: "fail_repeats",
    label: t("Identical failures"),
    hint: t("After this many failures of the exact same call, the next identical call is refused."),
  },
  {
    key: "identical_repeats",
    label: t("Identical successes"),
    hint: t("After this many identical successful calls in a row, the next one is refused."),
  },
  {
    key: "failure_streak",
    label: t("Failures in a row"),
    hint: t("After this many failed calls in a row, of any kind, the agent must change direction."),
  },
  {
    key: "stop_after",
    label: t("Stop after refusals"),
    hint: t("After this many refusals the run records what failed and ends."),
  },
];

// RepeatGuardCard edits the repeated-failure detection limits. 0 turns a check off.
export function RepeatGuardCard() {
  const [limits, setLimits] = React.useState<RepeatGuardLimits | null>(null);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    api
      .settings()
      .then((s) => setLimits(s.repeat_guard ?? null))
      .catch((e) => toast.error(t("Failed to load settings: {error}", { error: (e as Error).message })));
  }, []);

  const save = (next: RepeatGuardLimits) => {
    setSaving(true);
    api
      .setSettings({ repeat_guard: next })
      .then((s) => {
        if (s.repeat_guard) setLimits(s.repeat_guard);
        toast.success(t("Repeated-failure detection saved"));
      })
      .catch((e) => toast.error(t("Save failed: {error}", { error: (e as Error).message })))
      .finally(() => setSaving(false));
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <RepeatIcon className="size-4" />
          {t("Repeated-failure detection")}
        </CardTitle>
        <CardDescription>
          {t(
            "Stops worker and chat agents from repeating failing commands or identical requests. A refused call is not run; the agent gets a summary of the earlier failure and must change approach. Set a limit to 0 to turn that check off. Applies to runs started afterwards.",
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex items-center justify-between gap-4">
          <Label htmlFor="repeat-guard-enabled" className="text-sm font-normal text-muted-foreground">
            {t("Enabled")}
          </Label>
          <Switch
            id="repeat-guard-enabled"
            checked={limits?.enabled ?? false}
            disabled={!limits || saving}
            onCheckedChange={(on) => limits && save({ ...limits, enabled: on })}
          />
        </div>
        {fields.map((f) => (
          <div key={f.key} className="flex items-start justify-between gap-4">
            <div className="flex flex-col gap-1">
              <Label htmlFor={`repeat-guard-${f.key}`} className="text-sm font-normal">
                {f.label}
              </Label>
              <p className="text-muted-foreground text-xs">{f.hint}</p>
            </div>
            <Input
              id={`repeat-guard-${f.key}`}
              type="number"
              min={0}
              max={100}
              className="w-24 shrink-0"
              disabled={!limits || saving}
              value={limits ? String(limits[f.key]) : ""}
              onChange={(e) =>
                limits && setLimits({ ...limits, [f.key]: Math.max(0, Math.min(100, Number(e.target.value) || 0)) })
              }
            />
          </div>
        ))}
        <div className="flex justify-end">
          <Button size="sm" disabled={!limits || saving} onClick={() => limits && save(limits)}>
            {t("Save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
