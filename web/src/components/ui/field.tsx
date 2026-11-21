import { cloneElement, isValidElement, useId, type ReactElement, type ReactNode } from "react";
import { Label } from "radix-ui";
import { cn } from "@/lib/utils";

/** Label + control + helper/error, wired with aria-describedby. */
export function Field({
  label,
  hint,
  error,
  required,
  className,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  className?: string;
  children: ReactElement<Record<string, unknown>>;
}) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errId = error ? `${id}-err` : undefined;
  const control = isValidElement(children)
    ? cloneElement(children, {
        id: (children.props.id as string) ?? id,
        "aria-describedby": [errId, hintId].filter(Boolean).join(" ") || undefined,
        "aria-invalid": error ? true : undefined,
        required: required || (children.props.required as boolean | undefined),
      })
    : children;
  return (
    <div className={cn("grid gap-1.5", className)}>
      <FieldLabel htmlFor={(children.props.id as string) ?? id}>
        {label}
        {required && <span className="text-destructive" aria-hidden> *</span>}
      </FieldLabel>
      {control}
      {error ? (
        <p id={errId} role="alert" className="text-sm text-destructive">{error}</p>
      ) : hint ? (
        <p id={hintId} className="text-[13px] leading-snug text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );
}

export function FieldLabel({ className, ...props }: React.ComponentProps<typeof Label.Root>) {
  return <Label.Root className={cn("text-sm font-medium leading-none", className)} {...props} />;
}
