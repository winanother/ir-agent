"use client";

import { useCallback, useRef, useState } from "react";
import GlowCard from "@/components/GlowCard";
import { getTaskProgress, submitAnalysis, AnalysisResult, Threat, AttackPhase } from "@/lib/api";

const ANALYSIS_STEPS = [
  { key: "initializing", label: "初始化分析引擎" },
  { key: "detect_shadow_accounts", label: "检测影子账户" },
  { key: "detect_processes", label: "检测可疑进程" },
  { key: "detect_cron", label: "检测恶意计划任务" },
  { key: "detect_network", label: "检测可疑网络连接" },
  { key: "detect_auth", label: "分析认证日志" },
  { key: "detect_files", label: "检测文件系统指标" },
  { key: "detect_windows", label: "检测 Windows 威胁" },
  { key: "build_chain", label: "构建攻击链" },
  { key: "build_profile", label: "生成攻击者画像" },
  { key: "llm_threats", label: "LLM 分析威胁数据" },
  { key: "llm_process", label: "LLM 分析可疑进程" },
  { key: "llm_cron", label: "LLM 分析计划任务" },
  { key: "llm_login", label: "LLM 分析登录活动" },
  { key: "llm_chain", label: "LLM 攻击链深度还原" },
  { key: "report_generation", label: "生成分析报告" },
  { key: "done", label: "分析完成" },
];

type ResultTab = "threats" | "chain" | "profile" | "report";

export default function UploadAnalysis() {
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [progress, setProgress] = useState<{ step: string; detail: string; percent: number } | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [reportMd, setReportMd] = useState("");
  const [activeTab, setActiveTab] = useState<ResultTab>("threats");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const handleFile = useCallback((f: File) => {
    if (!f.name.endsWith(".json")) return;
    setFile(f);
  }, []);

  const clearUpload = useCallback(() => {
    setFile(null);
    setResult(null);
    setReportMd("");
    setProgress(null);
    setSubmitting(false);
    if (pollRef.current) clearInterval(pollRef.current);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const startAnalysis = useCallback(async () => {
    if (!file) return;
    setSubmitting(true);
    setProgress({ step: "initializing", detail: "正在上传证据文件...", percent: 2 });
    setResult(null);
    setReportMd("");
    try {
      const text = await file.text();
      const evidence = JSON.parse(text);
      setProgress({ step: "initializing", detail: "正在提交到分析引擎...", percent: 5 });
      const data = await submitAnalysis(evidence);
      const taskId = data.task_id;
      pollRef.current = setInterval(async () => {
        try {
          const t = await getTaskProgress(taskId);
          if (t.progress) setProgress(t.progress);
          if (t.status === "completed") {
            clearInterval(pollRef.current!);
            pollRef.current = null;
            setResult(t.analysis ?? null);
            setReportMd(t.report_md || "");
            setProgress({ step: "done", detail: "分析完成", percent: 100 });
            setSubmitting(false);
          } else if (t.status === "failed") {
            clearInterval(pollRef.current!);
            pollRef.current = null;
            setProgress({ step: "failed", detail: t.error || "分析失败", percent: 0 });
            setSubmitting(false);
          }
        } catch {
          /* ignore */
        }
      }, 800);
    } catch (e: unknown) {
      const errorMessage = e instanceof Error ? e.message : "提交失败";
      setProgress({ step: "failed", detail: errorMessage, percent: 0 });
      setSubmitting(false);
    }
  }, [file]);

  const renderResultTab = () => {
    if (!result) return <p className="text-gray-400">暂无数据</p>;
    if (activeTab === "threats") {
      const threats = result.threats || [];
      if (!threats.length) return <p className="text-gray-400">未发现威胁</p>;
      const sevCn: Record<string, string> = { critical: "严重", high: "高危", medium: "中等", low: "低危" };
      const sevColor: Record<string, string> = { critical: "text-rose-500 border-rose-500/50", high: "text-orange-500 border-orange-500/50", medium: "text-yellow-500 border-yellow-500/50", low: "text-emerald-500 border-emerald-500/50" };
      return (
        <div className="space-y-4">
          {threats.map((t: Threat, i: number) => (
            <div key={i} className={`rounded-xl border-l-4 bg-white/3 p-5 ${sevColor[t.severity || ""] || "border-neon-blue/30"}`}>
              <p className={`font-display text-sm uppercase tracking-wider ${sevColor[t.severity || ""] ?.split(" ")[0] || "text-neon-blue"}`}>
                [{sevCn[t.severity || ""] || t.severity}] {t.title}
              </p>
              <p className="mt-2 text-sm text-gray-300">{t.description}</p>
              {t.recommendation && (
                <p className="mt-2 text-xs text-neon-blue/70">建议: {t.recommendation}</p>
              )}
            </div>
          ))}
        </div>
      );
    }
    if (activeTab === "chain") {
      const phases = result.attack_chain?.attack_phases || [];
      if (!phases.length) return <p className="text-gray-400">未生成攻击链</p>;
      return (
        <div className="space-y-3">
          {phases.map((p: AttackPhase, i: number) => (
            <div key={i} className="rounded-lg border border-neon-purple/20 bg-white/3 p-4">
              <p className="font-display text-sm text-neon-purple">{p.phase} — {p.name}</p>
              <p className="mt-1 text-xs text-gray-400">{p.description}</p>
              {p.mitre_technique && <p className="mt-1 text-xs text-orange-400">{p.mitre_technique}</p>}
            </div>
          ))}
        </div>
      );
    }
    if (activeTab === "profile") {
      const c = result.attacker_profile?.attacker_characteristics || {};
      const a = result.attacker_profile?.threat_assessment || {};
      return (
        <pre className="whitespace-pre-wrap font-body text-sm leading-7 text-gray-300">
{`攻击者画像

主要攻击源 IP: ${c.primary_source_ip || "无"}
攻击频率:      ${c.attack_frequency || 0} 次
唯一来源数:    ${c.unique_sources || 0}
威胁等级:      ${a.overall_threat_level || "未知"}
攻击复杂度:    ${a.attack_sophistication || "未知"}`}
        </pre>
      );
    }
    if (activeTab === "report") {
      return <pre className="whitespace-pre-wrap font-body text-sm leading-7 text-gray-300">{reportMd || "报告未生成"}</pre>;
    }
    return null;
  };

  const currentStepIndex = progress ? ANALYSIS_STEPS.findIndex((s) => s.key === progress.step) : -1;

  return (
    <section id="upload" className="mx-auto w-full max-w-7xl px-6 py-20 lg:px-10">
      <div className="stagger-3 mb-10 flex items-center gap-3">
        <span className="h-px w-12 bg-neon-blue/60" />
        <span className="font-display text-xs uppercase tracking-[0.4em] text-neon-blue/80">Upload & Analyze</span>
      </div>

      <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        {/* Upload Card */}
        <GlowCard color="blue" className="stagger-3">
          <h2 className="font-display text-lg uppercase tracking-[0.2em] text-white">📂 上传证据文件</h2>
          <p className="mt-3 font-body text-sm text-gray-400">
            上传客户端采集的 JSON 证据文件，服务端将自动进行威胁检测、LLM 深度分析并生成报告。
          </p>
          <div
            className={`mt-6 flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-14 text-center transition-all ${
              dragOver ? "border-neon-blue bg-neon-blue/5 shadow-[0_0_30px_rgba(0,240,255,0.15)]" : "border-gray-700 bg-white/3"
            }`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); }}
            onClick={() => fileInputRef.current?.click()}
            role="button"
          >
            <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={(e) => { if (e.target.files?.length) handleFile(e.target.files[0]); }} />
            <p className="text-4xl mb-3">📄</p>
            <p className="font-body text-sm text-gray-300">拖拽 JSON 证据文件到此处，或点击选择</p>
            {file && <p className="mt-3 font-display text-sm text-neon-blue">{file.name} ({(file.size / 1024).toFixed(1)} KB)</p>}
          </div>

          <div className="mt-6 flex gap-3">
            <button
              disabled={!file || submitting}
              onClick={startAnalysis}
              className="rounded-lg border border-neon-blue/40 bg-neon-blue/20 px-6 py-3 font-display text-sm uppercase tracking-[0.2em] text-neon-blue transition-all hover:bg-neon-blue/30 hover:shadow-[0_0_24px_rgba(0,240,255,0.3)] disabled:opacity-30"
            >
              {submitting ? "分析中..." : "🔍 开始分析"}
            </button>
            {file && (
              <button onClick={clearUpload} className="rounded-lg border border-gray-700 px-5 py-3 font-body text-sm text-gray-400 transition-colors hover:border-gray-500 hover:text-white">
                清除
              </button>
            )}
          </div>
        </GlowCard>

        {/* Steps Card */}
        <GlowCard color="purple" className="stagger-4">
          <h2 className="font-display text-sm uppercase tracking-[0.2em] text-neon-purple">分析步骤</h2>
          {progress && (
            <div className="mt-5">
              <div className="h-2 w-full overflow-hidden rounded-full bg-white/10">
                <div className="relative h-full rounded-full bg-gradient-to-r from-neon-blue to-neon-purple transition-[width] duration-300" style={{ width: `${progress.percent}%` }}>
                  <div className="absolute inset-0 animate-shimmer bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.15),transparent)]" />
                </div>
              </div>
              <p className="mt-2 font-body text-xs text-neon-blue">{progress.detail}</p>
              <p className="font-display text-xs text-gray-400">{progress.percent}%</p>
            </div>
          )}
          <ul className="mt-5 space-y-2">
            {ANALYSIS_STEPS.map((step, i) => {
              const isDone = currentStepIndex > i;
              const isActive = currentStepIndex === i;
              return (
                <li key={step.key} className="flex items-center gap-2 text-xs">
                  <span className={isDone ? "text-emerald-400" : isActive ? "animate-pulse text-neon-blue" : "text-gray-600"}>
                    {isDone ? "✓" : isActive ? "▸" : "○"}
                  </span>
                  <span className={isDone ? "text-gray-400 line-through" : isActive ? "text-neon-blue" : "text-gray-500"}>
                    {step.label}
                  </span>
                </li>
              );
            })}
          </ul>
        </GlowCard>
      </div>

      {/* Results */}
      {result && (
        <div className="stagger-5 mt-10">
          <GlowCard color="blue">
            <h2 className="font-display text-lg uppercase tracking-[0.2em] text-white">📊 分析结果</h2>
            <div className="mt-6 grid gap-4 sm:grid-cols-4">
              {[
                { label: "严重", val: result.summary?.critical || 0, color: "text-rose-500" },
                { label: "高危", val: result.summary?.high || 0, color: "text-orange-500" },
                { label: "中等", val: result.summary?.medium || 0, color: "text-yellow-500" },
                { label: "低危", val: result.summary?.low || 0, color: "text-emerald-500" },
              ].map((s) => (
                <div key={s.label} className="rounded-lg border border-gray-700 bg-white/3 p-4 text-center">
                  <p className={`font-display text-3xl ${s.color}`}>{s.val}</p>
                  <p className="mt-1 font-body text-xs text-gray-400">{s.label}</p>
                </div>
              ))}
            </div>

            <div className="mt-6 flex gap-2">
              {(["threats", "chain", "profile", "report"] as ResultTab[]).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`rounded-full border px-4 py-2 font-body text-xs uppercase tracking-wider transition-all ${
                    activeTab === tab
                      ? "border-neon-blue/60 bg-neon-blue/15 text-neon-blue"
                      : "border-gray-700 text-gray-400 hover:border-gray-500 hover:text-white"
                  }`}
                >
                  {{ threats: "威胁详情", chain: "攻击链", profile: "攻击者画像", report: "完整报告" }[tab]}
                </button>
              ))}
            </div>

            <div className="mt-6 max-h-[500px] overflow-y-auto rounded-xl border border-gray-700 bg-black/30 p-5">
              {renderResultTab()}
            </div>
          </GlowCard>
        </div>
      )}
    </section>
  );
}
