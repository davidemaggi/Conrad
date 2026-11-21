import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { LockKeyhole } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { PasswordInput } from "@/components/ui/input";
import { Dialog, DialogContent, DialogFooter, DialogHeader } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { ErrorAlert } from "@/components/common";

export function CALockedBanner() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState("");
  const m = useMutation({
    mutationFn: () => api.post("/ca/unlock", { secret }),
    onSuccess: async () => {
      setOpen(false);
      setSecret("");
      toast.success(t("unlock.done"));
      await qc.invalidateQueries();
    },
  });
  return (
    <div role="status" className="border-b border-warning-fill/40 bg-warning-fill/12">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-2.5 text-sm sm:px-6 lg:px-8">
        <LockKeyhole className="size-4 shrink-0 text-warning" aria-hidden />
        <p className="flex-1 text-warning">
          <strong className="font-semibold">{t("unlock.bannerTitle")}</strong> {t("unlock.bannerText")}
        </p>
        <Button size="sm" variant="outline" onClick={() => setOpen(true)}>{t("unlock.action")}</Button>
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader title={t("unlock.title")} description={t("unlock.description")} />
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              m.mutate();
            }}
          >
            <Field label={t("unlock.secret")} required>
              <PasswordInput value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="current-password" autoFocus />
            </Field>
            <ErrorAlert error={m.error} />
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
              <Button type="submit" loading={m.isPending} disabled={!secret}>{t("unlock.action")}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
