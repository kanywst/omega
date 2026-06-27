"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/cn";

/**
 * Inline mono span for SPIFFE IDs, kids, hashes — never truncated.
 */
export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn("font-mono text-[12.5px] text-[var(--color-fg)] tracking-tight", className)}
    >
      {children}
    </span>
  );
}

export function CodeBlock({
  value,
  copyable = true,
  className,
}: {
  value: string;
  copyable?: boolean;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className={cn(
        "group relative rounded-[6px] border border-[var(--color-line)] bg-[var(--color-bg-raised)]",
        className,
      )}
    >
      <pre className="overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed text-[var(--color-fg)]">
        {value}
      </pre>
      {copyable && (
        <button
          type="button"
          onClick={() => {
            navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
          className="absolute top-2 right-2 grid h-6 w-6 place-items-center rounded text-[var(--color-fg-subtle)] opacity-0 transition-colors hover:text-[var(--color-fg)] group-hover:opacity-100 focus-visible:opacity-100"
          aria-label="Copy"
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
        </button>
      )}
    </div>
  );
}
