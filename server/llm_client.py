"""
LLM 客户端 - 统一大模型 API 调用封装
支持 OpenAI / Qwen / Anthropic / Gemini / DeepSeek / Ollama / Azure OpenAI 协议
"""

import json
import logging
import aiohttp
from typing import Dict, Any, Optional, List
from server.settings import Settings, LLM_PROTOCOLS


class LLMClient:
    """大模型 API 统一客户端"""

    def __init__(self, settings: Settings):
        self.logger = logging.getLogger(__name__)
        self.settings = settings
        self.protocol = settings.llm_protocol
        self.api_url = settings.llm_api_url
        self.api_key = settings.llm_api_key
        self.model = settings.llm_model
        self.system_prompt = settings.llm_system_prompt
        self.protocol_info = LLM_PROTOCOLS.get(self.protocol, {})
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建 aiohttp 会话"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=120)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """关闭会话"""
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    #  核心对话方法
    # ------------------------------------------------------------------

    async def chat(self, user_message: str, system_prompt: Optional[str] = None) -> str:
        """
        统一聊天接口 —— 根据协议自动适配请求格式

        Args:
            user_message: 用户消息
            system_prompt: 可选的系统提示词覆盖

        Returns:
            模型回复文本
        """
        sys_prompt = system_prompt or self.system_prompt

        try:
            if self.protocol in ("openai-completions", "qwen", "deepseek", "azure-openai"):
                return await self._chat_openai_compatible(user_message, sys_prompt)
            elif self.protocol == "anthropic":
                return await self._chat_anthropic(user_message, sys_prompt)
            elif self.protocol == "gemini":
                return await self._chat_gemini(user_message, sys_prompt)
            elif self.protocol == "ollama":
                return await self._chat_ollama(user_message, sys_prompt)
            else:
                # 兜底：按 OpenAI 兼容协议尝试
                return await self._chat_openai_compatible(user_message, sys_prompt)
        except Exception as e:
            self.logger.error(f"LLM 调用失败 [{self.protocol}]: {e}")
            raise

    # ------------------------------------------------------------------
    #  协议适配层
    # ------------------------------------------------------------------

    async def _chat_openai_compatible(self, user_message: str, system_prompt: str) -> str:
        """OpenAI 兼容协议（OpenAI / Qwen / DeepSeek / Azure）"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
        }

        # 自动补全 URL：如果以 /v1 结尾则补上 /chat/completions
        url = self.api_url.rstrip("/")
        if url.endswith("/v1") or url.endswith("/v1/"):
            url = url.rstrip("/") + "/chat/completions"
        elif not url.endswith("/chat/completions"):
            if "/chat/completions" not in url:
                url = url + "/chat/completions"

        self.logger.debug(f"OpenAI compatible request -> {url}")

        # 第一次尝试非流式，如果模型要求 stream 则自动切换
        session = await self._get_session()
        async with session.post(url, headers=headers, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data["choices"][0]["message"]["content"]

            # 检查是否需要 stream 模式
            error_text = await resp.text()
            if resp.status == 400 and "stream" in error_text.lower():
                self.logger.info("Model requires stream mode, switching...")
            else:
                self.logger.error(f"LLM API error {resp.status}: {error_text[:500]}")
                resp.raise_for_status()

        # 流式模式
        payload["stream"] = True
        return await self._stream_openai_compatible(url, headers, payload)

    async def _stream_openai_compatible(self, url: str, headers: dict, payload: dict) -> str:
        """OpenAI 兼容协议的流式响应处理"""
        session = await self._get_session()
        full_content = []

        async with session.post(url, headers=headers, json=payload) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                self.logger.error(f"LLM stream error {resp.status}: {error_text[:500]}")
                resp.raise_for_status()

            async for line in resp.content:
                line = line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str == "[DONE]":
                        break
                    try:
                        data = json.loads(data_str)
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            full_content.append(content)
                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue

        return "".join(full_content)

    async def _chat_anthropic(self, user_message: str, system_prompt: str) -> str:
        """Anthropic Claude 协议"""
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message},
            ],
        }
        session = await self._get_session()
        async with session.post(self.api_url, headers=headers, json=payload) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["content"][0]["text"]

    async def _chat_gemini(self, user_message: str, system_prompt: str) -> str:
        """Google Gemini 协议"""
        url = self.api_url.replace("{model}", self.model)
        params = {"key": self.api_key}
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [
                {"role": "user", "parts": [{"text": user_message}]},
            ],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096},
        }
        session = await self._get_session()
        async with session.post(url, params=params, json=payload) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    async def _chat_ollama(self, user_message: str, system_prompt: str) -> str:
        """Ollama 本地模型协议"""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
        }
        session = await self._get_session()
        async with session.post(self.api_url, json=payload) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["message"]["content"]

    # ------------------------------------------------------------------
    #  便捷分析方法 —— 供各模块直接调用
    # ------------------------------------------------------------------

    async def analyze_threats(self, threats_data: str) -> str:
        """分析威胁数据并返回专业安全分析"""
        prompt = f"""请对以下终端安全扫描发现的威胁数据进行专业分析。

## 分析要求
1. 对每个威胁进行深入分析，判断其真实危害等级
2. 识别误报（False Positive），说明判断依据
3. 分析各威胁之间的关联性
4. 给出每个威胁的具体处置建议

## 输出格式（严格遵守）
按以下 Markdown 结构输出，不得省略任何章节：

### 威胁总览
用表格列出所有威胁，列：序号、威胁类型、风险等级（【严重】【高危】【中危】【低危】之一）、是否误报、关键特征摘要。

### 逐条分析
对每个威胁按以下格式分析：
**[序号] 威胁类型名称**
- 风险等级：【严重/高危/中危/低危】
- 分析：（详细分析威胁的技术特征、危害和依据）
- 关联性：（与其他威胁的关联，无则写"暂未发现关联"）
- 处置建议：（具体可执行的操作步骤）

### 综合评估
- 威胁关联性总结
- 整体风险等级判定
- 优先处置顺序建议

## 威胁数据
{threats_data}"""
        return await self.chat(prompt)

    async def analyze_attack_chain(self, timeline_data: str, attacker_profile: str) -> str:
        """基于时间线和攻击者画像进行攻击链深度分析"""
        prompt = f"""请基于以下攻击时间线数据和攻击者画像，进行完整的攻击链还原分析。

## 分析要求
1. 还原攻击者的完整攻击路径（从初始入侵到最终目的）
2. 映射到 MITRE ATT&CK 框架，标注每个阶段使用的技术
3. 评估攻击者的技术水平和动机
4. 判断是否存在高级持续性威胁（APT）特征
5. 提供针对性的防御建议

## 输出格式（严格遵守）
按以下 Markdown 结构输出，不得省略任何章节：

### 攻击链还原
按时间线顺序列出攻击阶段，每个阶段格式：
**阶段 N：[阶段名称]（时间戳）**
- 攻击行为：（具体操作描述）
- ATT&CK 技术：（T编号 + 技术名称，如 T1059.001 - PowerShell）
- 影响范围：（受影响的系统/数据）

### 攻击者评估
- 技术水平：（初级/中级/高级/国家级）
- 攻机动机：（推测内容标注"推测"）
- APT 特征判定：（是/否/无法确定，列出判断依据）
- 使用工具和手法总结

### 防御建议
按优先级分层：
- **立即执行**：（紧急止血措施）
- **短期加固**：（1-2周内完成）
- **长期建设**：（架构层面改进）

## 攻击时间线
{timeline_data}

## 攻击者画像
{attacker_profile}"""
        return await self.chat(prompt)

    async def generate_report_analysis(self, scan_summary: str) -> str:
        """生成报告级别的综合安全分析"""
        prompt = f"""请基于以下终端安全扫描摘要数据，生成一份专业的安全态势总结分析。

## 分析要求
1. 总结当前系统的整体安全态势
2. 指出最关键的风险点并排定优先级
3. 分析潜在的攻击趋势和隐患
4. 给出分层级的安全建议（立即、短期、长期）
5. 评估安全加固的紧迫程度

## 输出格式（严格遵守）
按以下 Markdown 结构输出，不得省略任何章节：

### 安全态势总评
用 2-3 句话概括当前系统安全状态，给出整体风险等级（【严重】【高危】【中危】【低危】）。

### 关键风险点
按优先级排列，格式：
1. **[风险名称]** - 风险等级：【X危】- （简要描述及影响范围）

### 攻击趋势与隐患
分析当前威胁数据反映出的趋势特征，标注推测内容。

### 分级安全建议
**立即执行（0-24小时）**
- （紧急处置措施）

**短期加固（1-2周）**
- （安全加固措施）

**长期建设（1-3个月）**
- （架构层面改进）

### 紧迫度评估
- 加固紧迫度：（紧急/较高/一般/低）
- 建议完成时限：（具体天数或周数）
- 主要风险窗口：（描述当前最大的暴露面）

## 扫描摘要数据
{scan_summary}"""
        return await self.chat(prompt)

    async def analyze_process(self, process_info: str) -> str:
        """分析可疑进程"""
        prompt = f"""请分析以下可疑进程信息，判断其是否为恶意进程。

## 分析要求
1. 分析进程名称、命令行参数、CPU 占用等特征
2. 判断是否为已知恶意软件（挖矿、后门、木马等）
3. 分析其可能的危害和传播方式
4. 给出处置建议

## 输出格式（严格遵守）
按以下 Markdown 结构输出，不得省略任何章节：

### 进程逐条分析
对每个可疑进程按以下格式：
**[进程名称]（PID: xxx）**
- 风险等级：【严重/高危/中危/低危】
- 进程类型：（挖矿程序/后门/木马/正常进程误报/待确认）
- 技术特征：（命令行参数、网络连接、文件路径等关键指标）
- 危害分析：（可能造成的损害和影响范围）
- 处置建议：（具体操作命令或步骤）

### 综合判定
- 恶意进程数量 / 总分析数量
- 是否存在协同行为（如挖矿+后门组合）
- 优先处置顺序

## 进程信息
{process_info}"""
        return await self.chat(prompt)

    async def analyze_cron_entry(self, cron_info: str) -> str:
        """分析可疑计划任务"""
        prompt = f"""请分析以下计划任务（crontab）条目，判断其是否为恶意行为。

## 分析要求
1. 解析命令的实际功能
2. 分析执行时间模式是否异常
3. 判断是否包含恶意行为（如下载执行、反向Shell、数据外传等）
4. 如有 Base64 编码内容请尝试解码分析
5. 给出风险等级和处置建议

## 输出格式（严格遵守）
按以下 Markdown 结构输出，不得省略任何章节：

### 计划任务逐条分析
对每个条目按以下格式：
**[任务条目原文]**
- 风险等级：【严重/高危/中危/低危】
- 执行时间：（解析 cron 表达式，说明执行频率和时间点）
- 命令解析：（逐步拆解命令功能，Base64 等编码需解码后展示）
- 行为判定：（正常维护/可疑/恶意，及判定依据）
- 恶意行为类型：（下载执行/反向Shell/数据外传/挖矿/无，不适用则写"无"）
- 处置建议：（禁用/删除任务 + 清理相关文件的具体命令）

### 综合评估
- 恶意任务数量
- 任务间是否存在关联（如多任务协作）
- 建议处置顺序

## 计划任务信息
{cron_info}"""
        return await self.chat(prompt)

    async def analyze_login_activity(self, login_data: str) -> str:
        """分析登录活动"""
        prompt = f"""请分析以下系统登录活动数据，识别可疑登录行为。

## 分析要求
1. 分析登录来源 IP 的地理分布和访问模式
2. 识别暴力破解、撞库等攻击迹象
3. 判断成功登录中是否存在异常（非工作时间、陌生 IP 等）
4. 分析失败登录的攻击特征（频率、目标用户、来源分布）
5. 给出访问控制加固建议

## 输出格式（严格遵守）
按以下 Markdown 结构输出，不得省略任何章节：

### 登录概况
- 分析时间范围
- 总登录次数（成功/失败）
- 涉及用户数量和来源 IP 数量
- 异常登录占比

### 异常登录识别
按异常类型分类：
**暴力破解特征**
- （如有，列出攻击 IP、目标用户、尝试频率、时间窗口）

**可疑成功登录**
- （如有，列出异常登录记录：时间、IP、用户、异常原因）

**其他异常模式**
- （如撞库、Credential Stuffing 等特征）

### 攻击特征分析
- 攻击来源分布（IP/地域，推测内容标注"推测"）
- 攻击目标偏好（特定用户/随机扫描）
- 攻击时间规律（集中时段/持续性）
- 攻击手法判定

### 加固建议
**立即执行**
- （如封锁 IP、锁定账户等）

**访问控制优化**
- （如 fail2ban、IP 白名单、MFA 等策略建议）

## 登录活动数据
{login_data}"""
        return await self.chat(prompt)


__all__ = ['LLMClient']
