"use client";

import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef } from "react";
import { cn } from "@/lib/cn";

const button = cva(
  "inline-flex items-center justify-center font-medium tracking-tight transition-colors disabled:opacity-40 disabled:pointer-events-none",
  {
    variants: {
      variant: {
        default: "bg-[var(--color-fg)] text-[var(--color-bg)] hover:bg-[var(--color-fg-muted)]",
        ghost:
          "text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] hover:bg-[var(--color-bg-muted)]",
        outline:
          "border border-[var(--color-line)] text-[var(--color-fg)] hover:border-[var(--color-line-strong)] hover:bg-[var(--color-bg-muted)]",
      },
      size: {
        default: "h-8 px-3 text-[13px] rounded-[6px]",
        sm: "h-7 px-2.5 text-[12px] rounded-[6px]",
        icon: "h-8 w-8 rounded-[6px]",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(button({ variant, size }), className)} {...props} />;
  },
);
Button.displayName = "Button";
