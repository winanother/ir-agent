"use client";

import { useEffect, useState } from "react";
import GlowCard from "@/components/GlowCard";
import { getConfig, getHealth, getTasks } from "@/lib/api";

export default function HeroOverview() {
  const [stats, setStats] = useState({ total: 0, completed: 0, analyzing: 0, failed: 0 });
  const [config, setConfig] = useState({ proto: "-", model: "-", llm: "-", time: "-" });

  useEffect(() => {
    async function load() {
      try {
        const [health, tasksData, cfg] = await Promise.all([getHealth(), getTasks(), getConfig()]);
        const list = tasksData.tasks || [];
        setStats({
          total: list.length,
          completed: list.filter((t) => t.status === "completed").length,
          analyzing: list.filter((t) => t.status === "analyzing" || t.status === "queued").length,
          failed: list.filter((t) => t.status === "failed").length,
        });
        setConfig({
          proto: cfg.llm_protocol || "-",
          model: cfg.llm_model || "-",
          llm: health.llm_enabled ? "已启用" : "未启用",
          time: health.server_time ? health.server_time.slice(11, 19) : "-",
        });
      } catch {
        // noop
      }
    }

    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <section id="overview" className="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col justify-center px-6 pt-28 pb-20 lg:px-10">
      <div className="stagger-1 mb-14 max-w-4xl">
        <p className="mb-4 font-display text-sm uppercase tracking-[0.5em] text-neon-blue/80">Threat Command Center</p>
        <h1 className="font-display text-5xl leading-none text-white drop-shadow-[0_0_22px_rgba(0,240,255,0.18)] sm:text-6xl lg:text-8xl">
          INCIDENT
          <span className="block text-neon-blue">RESPONSE</span>
        </h1>
        <p className="mt-6 max-w-2xl font-body text-lg leading-8 text-gray-300">
          威胁检测、攻击链还原与智能决策汇聚于同一作战界面，用赛博指挥中心的方式感知、分析并处置异常事件。
        </p>
      </div>

      <div className="stagger-2 mb-6 flex items-center gap-3">
        <span className="h-px w-12 bg-neon-blue/60" />
        <span className="font-display text-xs uppercase tracking-[0.4em] text-neon-blue/80">Service Status</span>
      </div>
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "总任务数", value: stats.total, color: "blue" as const },
          { label: "已完成", value: stats.completed, color: "purple" as const },
          { label: "分析中", value: stats.analyzing, color: "blue" as const },
          { label: "失败", value: stats.failed, color: "pink" as const },
        ].map((item, index) => (
          <GlowCard key={item.label} color={item.color} className={`stagger-${Math.min(index + 2, 6)}`}>
            <p className="font-body text-xs uppercase tracking-[0.35em] text-gray-400">{item.label}</p>
            <p className="mt-4 font-display text-4xl text-white">{item.value}</p>
          </GlowCard>
        ))}
      </div>

      <div className="stagger-4 mt-14 mb-6 flex items-center gap-3">
        <span className="h-px w-12 bg-neon-purple/60" />
        <span className="font-display text-xs uppercase tracking-[0.4em] text-neon-purple/80">Current Configuration</span>
      </div>
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "LLM 协议", value: config.proto },
          { label: "模型", value: config.model },
          { label: "LLM 状态", value: config.llm },
          { label: "服务器时间", value: config.time },
        ].map((item, index) => (
          <GlowCard key={item.label} color="purple" className={`stagger-${Math.min(index + 3, 6)}`}>
            <p className="font-body text-xs uppercase tracking-[0.35em] text-gray-400">{item.label}</p>
            <p className="mt-4 break-all font-display text-xl text-white">{item.value}</p>
          </GlowCard>
        ))}
      </div>
    </section>
  );
}
