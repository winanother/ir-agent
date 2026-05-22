"use client";

import { useEffect, useState } from "react";
import { getHealth } from "@/lib/api";

const navItems = [
  { label: "概览", href: "#overview" },
  { label: "上传分析", href: "#upload" },
  { label: "任务列表", href: "#tasks" },
  { label: "配置管理", href: "#config" },
];

export default function Navbar() {
  const [status, setStatus] = useState("连接中...");
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const health = await getHealth();
        setEnabled(health.llm_enabled);
        setStatus(health.llm_enabled ? "LLM 已启用" : "仅本地分析");
      } catch {
        setEnabled(false);
        setStatus("连接失败");
      }
    }

    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-neon-blue/20 bg-black/35 backdrop-blur-xl">
      <div className="mx-auto flex h-20 max-w-7xl items-center justify-between px-6 lg:px-10">
        <div className="flex items-center gap-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-neon-blue/40 bg-neon-blue/10 text-xl text-neon-blue shadow-[0_0_25px_rgba(0,240,255,0.25)]">
            🛡
          </div>
          <div>
            <p className="font-display text-lg tracking-[0.35em] text-neon-blue">IR-CORE</p>
            <p className="font-body text-xs uppercase tracking-[0.28em] text-gray-400">应急响应智能体</p>
          </div>
        </div>

        <nav className="hidden items-center gap-8 md:flex">
          {navItems.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="group relative font-display text-sm uppercase tracking-[0.24em] text-gray-300 transition-colors hover:text-neon-blue"
            >
              {item.label}
              <span className="absolute -bottom-2 left-0 h-px w-0 bg-neon-blue shadow-[0_0_12px_rgba(0,240,255,0.8)] transition-all duration-300 group-hover:w-full" />
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-3 rounded-full border border-neon-blue/20 bg-white/5 px-4 py-2 text-xs text-gray-300">
          <span className={`h-2.5 w-2.5 rounded-full ${enabled ? "bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.9)]" : "bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.9)]"}`} />
          <span className="font-body tracking-[0.12em] uppercase">{status}</span>
        </div>
      </div>
    </header>
  );
}
