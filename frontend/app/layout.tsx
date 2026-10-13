import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RepoGuard · Repository readiness",
  description: "Evidence-backed readiness. Controlled remediation.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
