import type { ComponentProps, HTMLAttributes } from "react";
import { Switch as Sw, Checkbox as Cb, Tabs as T, Tooltip as Tt, Separator as Sep, DropdownMenu as DM } from "radix-ui";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

export function Switch({ className, ...p }: ComponentProps<typeof Sw.Root>) {
  return (
    <Sw.Root
      className={cn(
        "peer relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border-2 border-transparent bg-input transition-colors data-[state=checked]:bg-primary disabled:opacity-50",
        className,
      )}
      {...p}
    >
      <Sw.Thumb className="block size-5 rounded-full bg-card shadow transition-transform data-[state=checked]:translate-x-5" />
    </Sw.Root>
  );
}

export function Checkbox({ className, ...p }: ComponentProps<typeof Cb.Root>) {
  return (
    <Cb.Root
      className={cn(
        "flex size-5 shrink-0 items-center justify-center rounded border border-input bg-card data-[state=checked]:border-primary data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground disabled:opacity-50",
        className,
      )}
      {...p}
    >
      <Cb.Indicator><Check className="size-3.5" strokeWidth={3} aria-hidden /></Cb.Indicator>
    </Cb.Root>
  );
}

export const Tabs = T.Root;
export function TabsList({ className, ...p }: ComponentProps<typeof T.List>) {
  return (
    <T.List
      className={cn("flex w-full gap-1 overflow-x-auto border-b [scrollbar-width:none]", className)}
      {...p}
    />
  );
}
export function TabsTrigger({ className, ...p }: ComponentProps<typeof T.Trigger>) {
  return (
    <T.Trigger
      className={cn(
        "-mb-px inline-flex h-10 shrink-0 items-center gap-2 border-b-2 border-transparent px-3 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground data-[state=active]:border-primary data-[state=active]:text-foreground [&_svg]:size-4",
        className,
      )}
      {...p}
    />
  );
}
export function TabsContent({ className, ...p }: ComponentProps<typeof T.Content>) {
  return <T.Content className={cn("pt-5 focus-visible:outline-none", className)} {...p} />;
}

export function Tooltip({ content, children }: { content: React.ReactNode; children: React.ReactNode }) {
  return (
    <Tt.Root delayDuration={300}>
      <Tt.Trigger asChild>{children}</Tt.Trigger>
      <Tt.Portal>
        <Tt.Content sideOffset={6} className="anim-fade z-50 max-w-xs rounded-md bg-foreground px-2.5 py-1.5 text-xs text-background shadow-md">
          {content}
        </Tt.Content>
      </Tt.Portal>
    </Tt.Root>
  );
}
export const TooltipProvider = Tt.Provider;

export function Separator({ className, ...p }: ComponentProps<typeof Sep.Root>) {
  return <Sep.Root className={cn("shrink-0 bg-border data-[orientation=horizontal]:h-px data-[orientation=horizontal]:w-full data-[orientation=vertical]:w-px data-[orientation=vertical]:h-full", className)} {...p} />;
}

export function Skeleton({ className, ...p }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("animate-pulse rounded-md bg-muted", className)} aria-hidden {...p} />;
}

export const DropdownMenu = DM.Root;
export const DropdownMenuTrigger = DM.Trigger;
export function DropdownMenuContent({ className, ...p }: ComponentProps<typeof DM.Content>) {
  return (
    <DM.Portal>
      <DM.Content
        sideOffset={6}
        className={cn("anim-down z-50 min-w-48 overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-lg", className)}
        {...p}
      />
    </DM.Portal>
  );
}
export function DropdownMenuItem({ className, ...p }: ComponentProps<typeof DM.Item>) {
  return (
    <DM.Item
      className={cn(
        "flex min-h-9 cursor-pointer select-none items-center gap-2 rounded-sm px-2 text-sm outline-none data-[highlighted]:bg-accent data-[disabled]:opacity-50 [&_svg]:size-4 [&_svg]:text-muted-foreground",
        className,
      )}
      {...p}
    />
  );
}
export const DropdownMenuLabel = ({ className, ...p }: ComponentProps<typeof DM.Label>) => (
  <DM.Label className={cn("px-2 py-1.5 text-xs text-muted-foreground", className)} {...p} />
);
export const DropdownMenuSeparator = ({ className, ...p }: ComponentProps<typeof DM.Separator>) => (
  <DM.Separator className={cn("-mx-1 my-1 h-px bg-border", className)} {...p} />
);
export const DropdownMenuRadioGroup = DM.RadioGroup;
export function DropdownMenuRadioItem({ className, children, ...p }: ComponentProps<typeof DM.RadioItem>) {
  return (
    <DM.RadioItem
      className={cn("relative flex min-h-9 cursor-pointer select-none items-center gap-2 rounded-sm pl-8 pr-2 text-sm outline-none data-[highlighted]:bg-accent [&_svg]:size-4", className)}
      {...p}
    >
      <span className="absolute left-2 flex items-center"><DM.ItemIndicator><Check className="size-4" aria-hidden /></DM.ItemIndicator></span>
      {children}
    </DM.RadioItem>
  );
}
