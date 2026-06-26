"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { Command } from "cmdk";
import { useRouter } from "next/navigation";
import { Kbd } from "@/components/ui/kbd";
import { NAV } from "./nav-items";

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px] data-[state=open]:animate-in data-[state=open]:fade-in" />
        <Dialog.Content
          className="-translate-x-1/2 fixed top-[20vh] left-1/2 z-50 w-full max-w-lg overflow-hidden rounded-[8px] border border-[var(--color-line-strong)] bg-[var(--color-bg-raised)] shadow-[0_20px_60px_rgba(0,0,0,0.5)] data-[state=open]:animate-in data-[state=open]:fade-in data-[state=open]:zoom-in-[0.98]"
          aria-describedby={undefined}
        >
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <Command label="Command palette" loop>
            <Command.Input
              placeholder="Search domains, audit, policy…"
              className="h-11 w-full border-[var(--color-line)] border-b bg-transparent px-4 text-[14px] text-[var(--color-fg)] outline-none placeholder:text-[var(--color-fg-subtle)]"
            />
            <Command.List className="max-h-[320px] overflow-y-auto p-1">
              <Command.Empty className="px-3 py-6 text-center font-mono text-[12px] text-[var(--color-fg-subtle)]">
                No matches. Try a SPIFFE ID, kind, or page name.
              </Command.Empty>
              <Command.Group
                heading="Navigate"
                className="px-1 py-1 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:text-[10.5px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-[var(--color-fg-subtle)]"
              >
                {NAV.map((item) => (
                  <Command.Item
                    key={item.href}
                    value={`go ${item.label} ${item.desc}`}
                    onSelect={() => {
                      router.push(item.href);
                      onOpenChange(false);
                    }}
                    className="flex h-8 cursor-pointer items-center gap-2 rounded-[5px] px-2 text-[13px] text-[var(--color-fg)] data-[selected=true]:bg-[var(--color-bg-muted)]"
                  >
                    <item.icon
                      size={13}
                      strokeWidth={1.75}
                      className="text-[var(--color-fg-subtle)]"
                    />
                    <span>{item.label}</span>
                    <span className="text-[var(--color-fg-subtle)]">— {item.desc}</span>
                    <Kbd className="ml-auto">{item.shortcut}</Kbd>
                  </Command.Item>
                ))}
              </Command.Group>
            </Command.List>
            <div className="flex items-center justify-between border-[var(--color-line)] border-t px-3 py-1.5 font-mono text-[10.5px] text-[var(--color-fg-subtle)]">
              <span>↑↓ select · ↵ go · esc close</span>
              <span>pre-alpha</span>
            </div>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
