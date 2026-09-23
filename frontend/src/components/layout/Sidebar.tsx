"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Crosshair,
  Shield,
  FileSearch,
  FileText,
  Share2,
  Bot,
  Search,
  BarChart3,
  Activity,
} from "lucide-react";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/missions", label: "Missions", icon: Crosshair },
  { href: "/assets", label: "Assets", icon: Shield },
  { href: "/findings", label: "Findings", icon: FileSearch },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/graph", label: "Knowledge Graph", icon: Share2 },
  { href: "/copilot", label: "AI Analyst", icon: Bot },
  { href: "/search", label: "Search", icon: Search },
  { href: "/benchmark", label: "Benchmarks", icon: BarChart3 },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 bg-slate-900 border-r border-slate-800">
      <div className="flex items-center gap-2 px-6 py-5 border-b border-slate-800">
        <Activity className="h-6 w-6 text-emerald-400" />
        <span className="text-lg font-bold text-white">ORACLE</span>
        <span className="text-xs text-slate-500 ml-auto">v0.2</span>
      </div>

      <nav className="px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname?.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800"
              }`}
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="absolute bottom-0 left-0 right-0 px-4 py-4 border-t border-slate-800">
        <div className="flex items-center gap-3 text-xs text-slate-500">
          <div className="h-2 w-2 rounded-full bg-emerald-400" />
          <span>System Online</span>
        </div>
      </div>
    </aside>
  );
}

