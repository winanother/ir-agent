# 应急响应智能体 - 客户端-服务端架构

基于大模型的自动化应急响应智能体系统，采用**客户端-服务端**远程取证分析架构，**跨平台支持 Linux 和 Windows 系统**，检测攻击痕迹并生成攻击链还原/攻击者溯源报告。

## 快速开始

### 环境要求
- Python 3.8+
- **Linux / Windows** 系统
- pip 包管理器（仅服务端需要）

### 安装依赖（服务端）
```bash
cd emergency-response-agent
pip install -r requirements.txt
```

> **注意**: 客户端（采集器）**零依赖设计**，仅使用 Python 标准库，无需 pip install，可直接在 Linux 和 Windows 上运行。

### 配置 LLM

编辑项目根目录 `config.json` 或 `~/.emergency_response_agent/config.json`：

```json
{
  "llm_protocol": "openai-completions",
  "llm_api_key": "sk-xxx",
  "llm_model": "qwq-plus",
  "llm_system_prompt": "你是一个专业的网络安全分析师...",
  "llm_api_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"
}
```

也可通过环境变量配置：
```bash
export LLM_PROTOCOL="qwen"
export LLM_API_KEY="sk-xxx"
export LLM_MODEL="qwen-max"
```

## 系统架构

```
┌──────────────────────┐       HTTP POST       ┌──────────────────────┐
│  客户端 (client)     │  ── 证据 JSON ──>      │  服务端 (server)    │
│  Linux 或 Windows    │                       │  分析服务器          │
│  零依赖 · 自动识别 OS│  <── 分析报告 ───      │  LLM 智能分析引擎    │
└──────────────────────┘                       └──────────────────────┘
```

## 跨平台支持

| 功能 | Linux | Windows |
|------|-------|---------|
| 客户端采集器 | ✅ | ✅ |
| 服务端分析引擎 | ✅ | ✅ |
| 零依赖运行 | ✅ 客户端 | ✅ 客户端 |

客户端采集器会**自动识别当前操作系统**，使用对应的采集策略：
- **Linux**: 通过 `ps`、`ss`、`/var/log/*`、`crontab` 等原生命令采集
- **Windows**: 通过 **PowerShell** (`Get-Process`、`Get-WinEvent`、`Get-ScheduledTask` 等) 和 `cmd` 命令采集

## 使用方法

### 服务端（分析服务器上部署）

```bash
# 启动分析服务端（默认监听 0.0.0.0:8080）
python -m server

# 指定地址和 API 端口
python -m server -H 127.0.0.1 -p 9090

# 启用 Web 管理面板（在 8888 端口）
python -m server -w 8888

# API + Web 面板 双端口运行
python -m server -p 8080 -w 8888

# 指定配置文件
python -m server -c /path/to/config.json
```

### 客户端 - Linux

```bash
# 采集证据并保存到本地
python -m client.collector

# 采集证据并上传到分析服务端
python -m client.collector -u http://server-ip:8080

# 上传的同时保存本地副本
python -m client.collector -u http://server-ip:8080 --save

# 指定输出路径
python -m client.collector -o /tmp/evidence.json

# 自定义日志采集行数
python -m client.collector -n 1000 -v
```

### 客户端 - Windows

```powershell
# 在 Windows 终端 / PowerShell 中运行（以管理员身份运行以获取完整数据）
python -m client.collector

# 采集并上传到服务端
python -m client.collector --upload http://server-ip:8080

# 指定输出路径
python -m client.collector -o C:\temp\evidence.json

# 上传并保存本地副本
python -m client.collector --upload http://server-ip:8080 --save -v
```

> **Windows 提示**: 建议以**管理员权限**运行，否则部分安全日志和系统信息可能无法采集。

### 分析已保存的证据文件

**方式 1：本地分析工具（推荐，无需启动 HTTP 服务）**

```bash
# 分析单个证据文件
python -m server.analyze_local evidence.json

# 分析多个证据文件
python -m server.analyze_local evidence1.json evidence2.json

# 指定报告输出目录
python -m server.analyze_local evidence.json -o /path/to/reports/

# 仅使用本地规则分析（不调用 LLM）
python -m server.analyze_local evidence.json --no-llm

# 指定配置文件
python -m server.analyze_local evidence.json --config /path/to/config.json
```

**方式 2：通过 HTTP API 上传到运行中的服务端**

```bash
# 同步分析（等待结果返回）
curl -X POST http://server:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d @evidence.json

# 异步分析（立即返回 task_id，后续查询结果）
curl -X POST http://server:8080/api/v1/evidence \
  -H "Content-Type: application/json" \
  -d @evidence.json

# 查询任务状态
curl http://server:8080/api/v1/tasks/{task_id}

# 下载报告
curl -O http://server:8080/api/v1/reports/{task_id}
```

## 服务端 API

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/api/v1/health` | 健康检查 |
| `POST` | `/api/v1/evidence` | 提交证据（异步分析，立即返回 task_id） |
| `POST` | `/api/v1/analyze` | 提交证据并等待分析完成（同步） |
| `GET` | `/api/v1/tasks` | 列出所有分析任务 |
| `GET` | `/api/v1/tasks/{task_id}` | 查询指定任务状态 |
| `GET` | `/api/v1/reports/{task_id}` | 下载分析报告 |

## Web 管理面板

通过 `--web-port` 参数可启用可视化管理面板，提供以下功能：

| 功能 | 说明 |
|------|------|
| 服务状态概览 | 实时查看任务统计、LLM 状态、服务器时间 |
| 上传分析 | 在浏览器中上传 JSON 证据文件，在线查看威胁检测结果、攻击链、攻击者画像 |
| 任务列表 | 查看所有分析任务的状态和报告下载 |
| 配置管理 | 在线修改 LLM 协议、模型、API Key 等配置，支持热重载无需重启服务 |

```bash
# 启用 Web 管理面板（需提前编译前端或使用旧版面板）
python -m server -w 8888

# 然后访问 http://your-server:8888 即可使用管理面板
```

> **安全提示**: Web 管理面板包含配置修改功能，建议仅在可信网络中使用或通过防火墙限制访问。

### 编译 Next.js 赛博朋克管理面板

项目默认使用一个极其轻量的单文件旧版面板，但内置了一套采用 Next.js + Tailwind CSS 编写的现代化赛博朋克风格可视化面板（位于 `frontend/` 目录）。

现在你可以直接通过 Python 命令触发前端编译：

```bash
# 仅编译前端面板
python -m server --build-web

# 编译前端后，再启动 API + Web 面板
python -m server -p 8080 -w 8888 --build-web
```

如果你更习惯手动构建，也可以继续使用：

```bash
cd frontend
npm install
npm run build
cd ..
python -m server -p 8080 -w 8888
```

服务端会优先加载 `frontend/out/` 中已经编译好的新版面板；如果该目录不存在，则自动回退到旧版 `server/templates/dashboard.html`。
## 支持的 API 协议

| 协议 ID | 提供商 | 支持模型 |
|--------|--------|----------|
| `openai-completions` | OpenAI | gpt-4o, gpt-4-turbo, gpt-3.5 |
| `qwen` | 阿里云通义千问 | qwen-max, qwen-plus, qwq-plus |
| `anthropic` | Anthropic Claude | claude-3-opus, sonnet, haiku |
| `gemini` | Google Gemini | gemini-1.5-pro, flash |
| `azure-openai` | Azure OpenAI | gpt-4o, gpt-4-turbo |
| `deepseek` | DeepSeek | deepseek-chat, coder |
| `ollama` | Ollama (本地) | llama3, mistral, gemma |

## 检测能力

### Linux 系统威胁扫描
- **影子账户** - 检测 UID 为 0 的非 root 账户
- **挖矿进程** - 检测常见挖矿软件（xmrig, minerd, cpuminer 等）
- **恶意网络连接** - 检测可疑 C2 端口（4444, 5555, 31337 等）
- **恶意计划任务** - 检测 cron 中的可疑命令（curl|bash, 反向 Shell 等）
- **可疑进程** - 高 CPU 占用、/tmp 目录执行、Base64 解码等异常行为
- **文件系统指标** - /tmp 可执行文件、/dev/shm 异常文件、隐藏文件检测

### Windows 系统威胁扫描
- **管理员组异常成员** - 检测非预期的 Administrators 组成员
- **可疑进程** - 检测 mimikatz、psexec、cobalt strike 等攻击工具
- **恶意 PowerShell** - 检测编码命令、远程下载、执行策略绕过等
- **计划任务 & 启动项** - 检测可疑的 Scheduled Tasks 和注册表 Run 键
- **RDP 安全** - 检测 RDP 是否启用及 NLA 网络级别认证状态
- **UAC 状态** - 检测用户账户控制是否被禁用
- **SMBv1 协议** - 检测过时且存在 EternalBlue 漏洞的 SMBv1
- **WMI 持久化** - 检测 WMI 事件订阅持久化机制
- **NTFS ADS** - 检测替代数据流隐藏的恶意数据

### 攻击链还原

发现威胁后自动生成：
1. **攻击时间线** - 按时间顺序排列检测到的攻击活动
2. **攻击阶段分析** - 映射到 MITRE ATT&CK 框架
3. **攻击者画像** - 描绘攻击者特征和行为模式
4. **溯源建议** - 提供处置和取证建议

### LLM 深度分析

| 分析维度 | 说明 |
|----------|------|
| 威胁综合分析 | 判断真实危害等级，识别误报，分析关联性 |
| 可疑进程分析 | 判断是否为已知恶意软件，分析危害和传播方式 |
| 恶意计划任务分析 | 解析命令功能，解码 Base64，判断恶意行为 |
| 登录活动分析 | 分析来源 IP 地理分布、暴力破解特征 |
| 攻击链深度还原 | 完整攻击路径还原，MITRE ATT&CK 映射，APT 判断 |
| 综合安全态势 | 整体安全态势总结，风险优先级排定，加固建议 |

## 目录结构

```
emergency-response-agent/
├── config.json              # LLM 配置文件
├── requirements.txt         # Python 依赖（仅服务端）
│
├── client/                  # 客户端 - 轻量级取证采集器（Linux & Windows）
│   ├── __init__.py
│   ├── __main__.py          # python -m client.collector 入口
│   └── collector.py         # 取证采集器（零依赖，自动识别 OS）
│
├── server/                  # 服务端 - LLM 智能分析引擎
│   ├── __init__.py
│   ├── __main__.py          # python -m server 入口
│   ├── app.py               # aiohttp HTTP API 服务
│   ├── web_dashboard.py     # Web 可视化管理面板（SPA）
│   ├── analyzer.py          # 证据分析引擎（本地规则 + LLM）
│   ├── report_builder.py    # 报告生成器
│   ├── settings.py          # 多协议 API 配置管理
│   └── llm_client.py        # 统一大模型 API 客户端
│
├── frontend/                # Next.js 赛博朋克风格 Web 管理面板
│   ├── package.json         # 前端依赖配置
│   ├── next.config.js       # Next.js 构建配置
│   ├── src/                 # 源代码（页面、组件、样式）
│   └── out/                 # 编译产物（服务端自动加载）
│
├── evidence/                # 客户端上传的原始证据存储目录
│
└── reports/                 # 生成的分析报告输出目录（.md + .json）
```

## 集成测试

```bash
# 端到端测试：模拟 客户端采集 -> 服务端分析 完整流程
python test_integration.py
```

## 批量远程取证

Linux 批量采集：
```bash
for host in host1 host2 host3; do
  ssh $host "python3 -m client.collector --upload http://analysis-server:8080"
done
```

Windows 批量采集（WinRM）：
```powershell
$hosts = @("win-host1", "win-host2", "win-host3")
foreach ($h in $hosts) {
    Invoke-Command -ComputerName $h -ScriptBlock {
        python -m client.collector --upload http://analysis-server:8080
    }
}
```

## 报告格式

生成两种格式的报告：
- **Markdown** (`.md`) - 人类可读的详细报告
- **JSON** (`.json`) - 机器可读的结构化数据

报告包含：
- 综合安全态势分析（LLM 生成）
- 主机概况与账户信息
- 威胁发现详情
- AI 深度分析结果
- 攻击链分析（MITRE ATT&CK 映射）
- 攻击者画像
- IOC（攻击指标）
- 分层安全建议

## 注意事项

1. **权限要求** - Linux 需要 root/sudo；Windows 建议管理员权限运行
2. **客户端零依赖** - 采集器仅使用 Python 标准库，可在任何有 Python 3.8+ 的 Linux/Windows 上运行
3. **服务端依赖** - 服务端需要 `aiohttp`，通过 `pip install -r requirements.txt` 安装
4. **Windows 采集** - 客户端在 Windows 上通过 PowerShell 采集，需要 PowerShell 5.1+
5. **隐私保护** - 所有数据本地处理（或发送到指定的分析服务端），不上传第三方服务器
6. **LLM 可选** - 未配置 LLM 时系统仍可正常运行，使用本地规则分析模式

## License

MIT License
