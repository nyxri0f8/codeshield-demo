import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CodeShield AI - AI Vulnerability Detection & Secure Code Review",
  description: "Identify vulnerabilities, map threat models, generate secure fixes, and run automated security audits powered by Google Gemini AI & RAG.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full dark antialiased">
      <body className="min-h-full flex flex-col bg-gray-950 text-gray-100 font-sans">
        {children}
      </body>
    </html>
  );
}
