import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LogProof | Trust assurance console",
  description: "A local-first log provenance, drift, and parser replay demonstration.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
