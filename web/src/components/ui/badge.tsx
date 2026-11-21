import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap [&_svg]:size-3",
  {
    variants: {
      variant: {
        default: "border-transparent bg-secondary text-secondary-foreground",
        success: "border-success/30 bg-success/10 text-success",
        warning: "border-warning-fill/40 bg-warning-fill/12 text-warning",
        danger: "border-destructive/30 bg-destructive/10 text-destructive",
        info: "border-info-fill/40 bg-info-fill/12 text-info",
        outline: "border-border text-muted-foreground",
        stamp: "border-[1.5px] border-current bg-transparent uppercase tracking-[0.12em] text-[10px] font-bold",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export function Badge({ className, variant, ...p }: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...p} />;
}
