import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata } from "next";
import { AppShell } from "@/components/shell/app-shell";
import { Providers } from "./providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Omega",
  description: "Workload identity, authorization, federation. One control plane.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
