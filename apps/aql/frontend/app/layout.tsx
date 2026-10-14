import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AQL-1 — Agent Operating Layer",
  description: "Autonomous AI agent operating layer — control plane for agents.",
};

/**
 * Applies the persisted theme before first paint so there is no light/dark
 * flash on load. Kept inline and tiny on purpose — it must run synchronously.
 */
const THEME_INIT = `(function(){try{var m=localStorage.getItem('aql1-theme')||'system';var d=m==='dark'||(m==='system'&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);}catch(e){}})();`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
