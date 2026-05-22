"use client";

import { useEffect, useRef, useState } from "react";
import GlowCard from "@/components/GlowCard";
import { getTaskProgress, getTasks, Task, API_BASE, Threat } from "@/lib/api";

const statusCn: Record<string, string> = { completed: "已完成", analyzing: "分析中", queued: "排队中", failed: "失败" };
const statusStyle: Record<string, string> = {
  completed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 shadow-[0_0_10px_rgba(52,211,153,0.2)]",
  analyzing: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30 animate-pulse",
  queued: "bg-neon-purple/15 text-neon-purple border-neon-purple/30",
  failed: "bg-rose-500/15 text-rose-400 border-rose-500/30",
};

export default function TaskCarousel() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedOverview, setSelectedOverview] = useState<{
    status: string;
    hostname: string;
    threatTitles: string[];
    reportReady: boolean;
  } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await getTasks();
        setTasks(data.tasks || []);
      } catch {
        /* noop */
      }
    }

    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  const handleSelectTask = async (taskId: string) => {
    if (selected === taskId) {
      setSelected(null);
      setSelectedOverview(null);
      return;
    }
    setSelected(taskId);
    setSelectedOverview(null);

    try {
      const detail = await getTaskProgress(taskId);
      const threats: Threat[] = detail.analysis?.threats || [];
      setSelectedOverview({
        status: detail.status,
        hostname: detail.hostname,
        threatTitles: threats.slice(0, 5).map((t) => t.title || "未知威胁"),
        reportReady: detail.status === "completed" && !!detail.report_md,
      });
    } catch {
      setSelectedOverview({
        status: "unknown",
        hostname: "-",
        threatTitles: [],
        reportReady: false,
      });
    }
  };

  return (
    <section id="tasks" className="mx-auto w-full max-w-7xl px-6 py-20 lg:px-10">
      <div className="stagger-4 mb-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="h-px w-12 bg-neon-blue/60" />
          <span className="font-display text-xs uppercase tracking-[0.4em] text-neon-blue/80">Task Stream</span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => scrollRef.current?.scrollBy({ left: -300, behavior: "smooth" })}
            className="flex h-10 w-10 items-center justify-center rounded-lg border border-gray-700 text-gray-400 transition-all hover:border-neon-blue/50 hover:text-neon-blue"
          >
            ←
          </button>
          <button
            onClick={() => scrollRef.current?.scrollBy({ left: 300, behavior: "smooth" })}
            className="flex h-10 w-10 items-center justify-center rounded-lg border border-gray-700 text-gray-400 transition-all hover:border-neon-blue/50 hover:text-neon-blue"
          >
            →
          </button>
        </div>
      </div>

      {tasks.length === 0 ? (
        <p className="text-center font-body text-sm text-gray-400">暂无任务</p>
      ) : (
        <div ref={scrollRef} className="flex snap-x snap-mandatory gap-6 overflow-x-auto overflow-y-visible py-4 px-6 scrollbar-thin">
          {tasks.map((task) => (
            <div
              key={task.task_id}
              className="w-72 flex-shrink-0 snap-start cursor-pointer relative z-0 hover:z-50"
              onClick={() => handleSelectTask(task.task_id)}
            >
              <GlowCard color={selected === task.task_id ? "blue" : "purple"} className="origin-center transition-transform duration-300 hover:scale-105">
                <div className="flex items-center justify-between">
                  <code className="font-display text-sm text-neon-blue">{task.task_id}</code>
                  <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs ${statusStyle[task.status] || ""}`}>
                    {statusCn[task.status] || task.status}
                  </span>
                </div>
                <p className="mt-4 font-body text-sm text-gray-200">{task.hostname}</p>
                <p className="mt-1 font-body text-xs text-gray-500">{task.submitted_at?.replace("T", " ").slice(0, 19)}</p>
                {task.status === "completed" && (
                  <a
                    href={`${API_BASE}/api/v1/reports/${task.task_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-4 inline-flex items-center gap-1 font-body text-xs text-neon-blue transition-colors hover:text-white"
                    onClick={(e) => e.stopPropagation()}
                  >
                    下载报告 →
                  </a>
                )}
              </GlowCard>
            </div>
          ))}
        </div>
      )}

      {selected && (
        <div className="mt-8 animate-fade-in-up">
          <GlowCard color="blue">
            <div className="flex items-center justify-between">
              <h3 className="font-display text-sm uppercase tracking-[0.2em] text-neon-blue">
                报告概览 · {selected}
              </h3>
              {tasks.find((t) => t.task_id === selected)?.status === "completed" && (
                <a
                  href={`${API_BASE}/api/v1/reports/${selected}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-body text-xs text-neon-blue transition-colors hover:text-white"
                >
                  下载完整报告 →
                </a>
              )}
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <div className="rounded-lg border border-gray-700 bg-white/3 p-4">
                <p className="font-body text-xs uppercase tracking-wider text-gray-500">主机</p>
                <p className="mt-1 font-body text-sm text-white">{selectedOverview?.hostname || tasks.find((t) => t.task_id === selected)?.hostname || "-"}</p>
              </div>
              <div className="rounded-lg border border-gray-700 bg-white/3 p-4">
                <p className="font-body text-xs uppercase tracking-wider text-gray-500">状态</p>
                <p className="mt-1 font-body text-sm text-white">{statusCn[selectedOverview?.status || ""] || selectedOverview?.status || "加载中..."}</p>
              </div>
              <div className="rounded-lg border border-gray-700 bg-white/3 p-4">
                <p className="font-body text-xs uppercase tracking-wider text-gray-500">提交时间</p>
                <p className="mt-1 font-body text-sm text-white">{tasks.find((t) => t.task_id === selected)?.submitted_at?.replace("T", " ").slice(0, 19) || "-"}</p>
              </div>
            </div>

            <div className="mt-6">
              <div className="flex items-center gap-3 mb-4">
                <span className="h-px w-8 bg-neon-pink/60" />
                <span className="font-display text-xs uppercase tracking-[0.3em] text-neon-pink/80">Threat Summary</span>
              </div>

              {!selectedOverview ? (
                <p className="font-body text-sm text-gray-500 animate-pulse">正在加载报告概览...</p>
              ) : selectedOverview.status !== "completed" ? (
                <p className="font-body text-sm text-gray-500">分析尚未完成，暂无报告概览</p>
              ) : selectedOverview.threatTitles.length === 0 ? (
                <p className="font-body text-sm text-emerald-400">未发现威胁</p>
              ) : (
                <div className="space-y-2">
                  {selectedOverview.threatTitles.map((title, i) => (
                    <div key={i} className="flex items-start gap-3 rounded-lg border border-neon-pink/20 bg-neon-pink/5 px-4 py-3">
                      <span className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full border border-neon-pink/40 font-display text-[10px] text-neon-pink">
                        {i + 1}
                      </span>
                      <span className="font-body text-sm text-gray-200">{title}</span>
                    </div>
                  ))}
                  {selectedOverview.threatTitles.length >= 5 && (
                    <p className="font-body text-xs text-gray-500 pl-8">...更多威胁详见完整报告</p>
                  )}
                </div>
              )}
            </div>
          </GlowCard>
        </div>
      )}
    </section>
  );
}
