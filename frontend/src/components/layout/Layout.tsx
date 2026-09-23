"use client";

import Sidebar from "./Sidebar";
import Header from "./Header";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-950">
      <Sidebar />
      <Header />
      <main className="ml-64 pt-16 min-h-screen">{children}</main>
    </div>
  );
}

