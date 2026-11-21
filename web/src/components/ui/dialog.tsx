import type { ComponentProps, ReactNode } from "react";
import { Dialog as D } from "radix-ui";
import { X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";

export const Dialog = D.Root;
export const DialogTrigger = D.Trigger;
export const DialogClose = D.Close;

export function DialogContent({
  className,
  children,
  wide,
  ...props
}: ComponentProps<typeof D.Content> & { wide?: boolean }) {
  const { t } = useTranslation();
  return (
    <D.Portal>
      <D.Overlay className="anim-fade fixed inset-0 z-50 bg-black/50" />
      <D.Content
        className={cn(
          "anim-pop fixed left-1/2 top-1/2 z-50 grid max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-xl border bg-popover p-6 text-popover-foreground shadow-2xl",
          wide ? "max-w-2xl" : "max-w-lg",
          className,
        )}
        {...props}
      >
        {children}
        <D.Close
          className="absolute right-3 top-3 flex size-9 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
          aria-label={t("common.close")}
        >
          <X className="size-4" aria-hidden />
        </D.Close>
      </D.Content>
    </D.Portal>
  );
}

export function DialogHeader({ title, description }: { title: ReactNode; description?: ReactNode }) {
  return (
    <div className="grid gap-1.5 pr-8">
      <D.Title className="text-lg font-semibold leading-tight">{title}</D.Title>
      {description ? (
        <D.Description className="text-sm text-muted-foreground">{description}</D.Description>
      ) : (
        <D.Description className="sr-only">{title}</D.Description>
      )}
    </div>
  );
}

export function DialogFooter({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex flex-col-reverse gap-2 pt-2 sm:flex-row sm:justify-end", className)} {...p} />;
}
