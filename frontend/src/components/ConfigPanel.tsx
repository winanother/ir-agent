"use client";

import { useEffect, useState } from "react";
import GlowCard from "@/components/GlowCard";
import { getConfig, saveConfig, testLLM, AppConfig } from "@/lib/api";

const protocolDefaults: Record<string, string> = {
  "openai-completions": "gpt-4o",
  qwen: "qwen-max",
  deepseek: "deepseek-chat",
  anthropic: "claude-3-opus",
  gemini: "gemini-1.5-pro",
  "azure-openai": "gpt-4o",
  ollama: "llama3",
};

export default function ConfigPanel() {
  const [form, setForm] = useState<AppConfig>({
    llm_protocol: "openai-completions",
    llm_model: "",
    llm_api_key: "",
    llm_api_url: "",
    llm_system_prompt: "",
  });
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  const showToast = (msg: string, type: "success" | "error" | "info" = "info") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  useEffect(() => {
    async function load() {
      try {
        const c = await getConfig();
        setForm(c);
      } catch {
        showToast("加载配置失败", "error");
      }
    }
    load();
  }, []);

  const handleProtocolChange = (v: string) => {
    setForm((prev) => ({
      ...prev,
      llm_protocol: v,
      llm_model: protocolDefaults[v] || prev.llm_model,
    }));
  };

  const handleSave = async () => {
    try {
      await saveConfig(form);
      showToast("配置已保存并重新加载", "success");
    } catch (e: unknown) {
      const errorMessage = e instanceof Error ? e.message : "未知错误";
      showToast("保存失败: " + errorMessage, "error");
    }
  };

  const handleReload = async () => {
    try {
      const c = await getConfig();
      setForm(c);
      showToast("配置已重新加载", "info");
    } catch {
      showToast("加载配置失败", "error");
    }
  };

  const handleTest = async () => {
    showToast("正在测试 LLM 连接...", "info");
    try {
      const d = await testLLM();
      if (d.success) showToast("连接成功! 响应: " + (d.reply || "").slice(0, 80), "success");
      else showToast("连接失败: " + d.error, "error");
    } catch (e: unknown) {
      const errorMessage = e instanceof Error ? e.message : "未知错误";
      showToast("测试失败: " + errorMessage, "error");
    }
  };

  const inputClass =
    "w-full rounded-lg border border-gray-700 bg-white/5 px-4 py-3 font-body text-sm text-gray-100 outline-none transition-all placeholder:text-gray-600 focus:border-neon-blue/60 focus:shadow-[0_0_20px_rgba(0,240,255,0.1)]";

  return (
    <section id="config" className="mx-auto w-full max-w-7xl px-6 py-20 lg:px-10">
      <div className="stagger-5 mb-10 flex items-center gap-3">
        <span className="h-px w-12 bg-neon-purple/60" />
        <span className="font-display text-xs uppercase tracking-[0.4em] text-neon-purple/80">Configuration</span>
      </div>

      <GlowCard color="purple" className="stagger-5 max-w-3xl">
        <h2 className="font-display text-lg uppercase tracking-[0.2em] text-white">🔧 LLM 配置</h2>

        <div className="mt-8 grid gap-6 sm:grid-cols-2">
          <div>
            <label className="mb-2 block font-body text-xs uppercase tracking-[0.2em] text-gray-400">API 协议</label>
            <select
              value={form.llm_protocol}
              onChange={(e) => handleProtocolChange(e.target.value)}
              className={inputClass + " cursor-pointer appearance-none"}
            >
              <option value="openai-completions">OpenAI Completions</option>
              <option value="qwen">阿里云通义千问 (DashScope)</option>
              <option value="deepseek">DeepSeek</option>
              <option value="anthropic">Anthropic Claude</option>
              <option value="gemini">Google Gemini</option>
              <option value="azure-openai">Azure OpenAI</option>
              <option value="ollama">Ollama (本地)</option>
            </select>
          </div>

          <div>
            <label className="mb-2 block font-body text-xs uppercase tracking-[0.2em] text-gray-400">模型名称</label>
            <input
              type="text"
              value={form.llm_model}
              onChange={(e) => setForm({ ...form, llm_model: e.target.value })}
              placeholder="例如: qwq-plus"
              className={inputClass}
            />
          </div>
        </div>

        <div className="mt-6">
          <label className="mb-2 block font-body text-xs uppercase tracking-[0.2em] text-gray-400">API Key</label>
          <input
            type="password"
            value={form.llm_api_key}
            onChange={(e) => setForm({ ...form, llm_api_key: e.target.value })}
            placeholder="sk-..."
            className={inputClass}
          />
        </div>

        <div className="mt-6">
          <label className="mb-2 block font-body text-xs uppercase tracking-[0.2em] text-gray-400">API URL（留空使用默认值）</label>
          <input
            type="text"
            value={form.llm_api_url}
            onChange={(e) => setForm({ ...form, llm_api_url: e.target.value })}
            placeholder="https://..."
            className={inputClass}
          />
        </div>

        <div className="mt-6">
          <label className="mb-2 block font-body text-xs uppercase tracking-[0.2em] text-gray-400">系统提示词</label>
          <textarea
            rows={3}
            value={form.llm_system_prompt}
            onChange={(e) => setForm({ ...form, llm_system_prompt: e.target.value })}
            className={inputClass + " resize-vertical min-h-[80px]"}
          />
        </div>

        <div className="mt-8 flex flex-wrap gap-3">
          <button
            onClick={handleSave}
            className="rounded-lg border border-neon-blue/40 bg-neon-blue/20 px-6 py-3 font-display text-sm uppercase tracking-[0.2em] text-neon-blue transition-all hover:bg-neon-blue/30 hover:shadow-[0_0_24px_rgba(0,240,255,0.3)]"
          >
            💾 保存配置
          </button>
          <button
            onClick={handleReload}
            className="rounded-lg border border-gray-600 px-5 py-3 font-body text-sm text-gray-300 transition-colors hover:border-gray-400 hover:text-white"
          >
            🔄 重新加载
          </button>
          <button
            onClick={handleTest}
            className="rounded-lg border border-neon-purple/40 bg-neon-purple/10 px-5 py-3 font-body text-sm text-neon-purple transition-all hover:bg-neon-purple/20 hover:shadow-[0_0_16px_rgba(139,92,246,0.2)]"
          >
            ⚡ 测试连接
          </button>
        </div>
      </GlowCard>

      {/* Toast */}
      {toast && (
        <div
          className={`fixed right-6 top-24 z-[200] animate-fade-in-up rounded-xl border px-6 py-4 font-body text-sm shadow-2xl backdrop-blur-xl ${
            toast.type === "success"
              ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300"
              : toast.type === "error"
                ? "border-rose-500/30 bg-rose-500/15 text-rose-300"
                : "border-neon-blue/30 bg-neon-blue/15 text-neon-blue"
          }`}
        >
          {toast.msg}
        </div>
      )}
    </section>
  );
}
