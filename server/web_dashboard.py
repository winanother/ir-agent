"""
Web 可视化面板 — 提供服务端交互式管理界面

功能：
    - 查看/修改 LLM 配置
    - 上传证据文件并在线分析
    - 查看分析任务列表与报告
    - 服务端健康状态概览

用法：
    python -m server --web-port 8888          # 在 8888 端口启用 Web 面板
    python -m server --web-port 8888 --port 8080   # API 8080 + Web 8888
"""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from server.app import AnalysisServer

logger = logging.getLogger("web_dashboard")


# ======================================================================
#  内嵌 HTML — 单页应用（SPA），无外部依赖
# ======================================================================

LEGACY_DASHBOARD_HTML = Path(__file__).with_name("templates").joinpath("dashboard.html").read_text(encoding="utf-8")
FRONTEND_OUT_DIR = Path(__file__).resolve().parent.parent.joinpath("frontend", "out")
FRONTEND_INDEX_FILE = FRONTEND_OUT_DIR.joinpath("index.html")


# ======================================================================
#  Web Dashboard 路由处理器
# ======================================================================

def setup_web_routes(app: web.Application, server: "AnalysisServer"):
    """向 aiohttp app 注册 Web 面板所需的路由"""

    async def handle_dashboard(request: web.Request) -> web.Response:
        """返回前端单页面"""
        if FRONTEND_INDEX_FILE.exists():
            return web.FileResponse(FRONTEND_INDEX_FILE)
        return web.Response(text=LEGACY_DASHBOARD_HTML, content_type="text/html", charset="utf-8")

    async def handle_get_config(request: web.Request) -> web.Response:
        """获取当前 LLM 配置"""
        s = server.settings
        # API Key 脱敏返回给前端
        masked_key = ""
        if s.llm_api_key:
            k = s.llm_api_key
            if len(k) > 8:
                masked_key = k[:4] + "*" * (len(k) - 8) + k[-4:]
            else:
                masked_key = "*" * len(k)

        return web.json_response({
            "llm_protocol": s.llm_protocol,
            "llm_model": s.llm_model,
            "llm_api_key": masked_key,
            "llm_api_url": s.llm_api_url,
            "llm_system_prompt": s.llm_system_prompt,
        })

    async def handle_save_config(request: web.Request) -> web.Response:
        """保存配置并热重载"""
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        s = server.settings

        # 更新字段（仅更新非空值）
        if body.get("llm_protocol"):
            s.llm_protocol = body["llm_protocol"]
        if body.get("llm_model"):
            s.llm_model = body["llm_model"]
        # API Key: 如果全是 * 则不更新（表示用户没修改）
        new_key = body.get("llm_api_key", "")
        if new_key and not all(c == "*" for c in new_key):
            s.llm_api_key = new_key
        if body.get("llm_api_url"):
            s.llm_api_url = body["llm_api_url"]
        if body.get("llm_system_prompt"):
            s.llm_system_prompt = body["llm_system_prompt"]

        # 持久化到配置文件
        try:
            s.save_config()
        except Exception as e:
            logger.warning(f"配置文件保存失败: {e}")

        # 热重载：重新初始化 LLM 客户端和分析器
        try:
            await server.cleanup()
            await server.init()
            logger.info("配置已热重载")
        except Exception as e:
            logger.error(f"热重载失败: {e}")
            return web.json_response({"error": f"配置已保存但重载失败: {e}"}, status=500)

        return web.json_response({"status": "ok", "message": "配置已保存并重新加载"})

    async def handle_test_llm(request: web.Request) -> web.Response:
        """测试 LLM 连接"""
        if not server.llm_client:
            return web.json_response({"success": False, "error": "LLM 未配置或未启用"})

        try:
            reply = await server.llm_client.chat("请回复'连接正常'四个字，不要回复其他内容。")
            return web.json_response({"success": True, "reply": reply[:200]})
        except Exception as e:
            return web.json_response({"success": False, "error": str(e)[:300]})

    async def handle_web_analyze(request: web.Request) -> web.Response:
        """Web 端上传证据 — 创建异步任务并返回 task_id，前端轮询进度"""
        try:
            evidence = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        if not isinstance(evidence, dict):
            return web.json_response({"error": "证据必须是 JSON 对象"}, status=400)

        import asyncio

        # 复用 AnalysisServer 的任务机制，这样概览和任务列表能看到
        task_id = str(uuid.uuid4())[:8]
        hostname = evidence.get("host_info", {}).get("hostname", "unknown")
        now = datetime.now()

        # 保存证据文件
        evidence_file = server.evidence_dir / f"evidence_{hostname}_{now.strftime('%Y%m%d_%H%M%S')}_{task_id}.json"
        with open(evidence_file, "w", encoding="utf-8") as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2)

        # 创建任务（注册到 server.tasks，让概览/任务列表都能看到）
        task = {
            "task_id": task_id,
            "status": "analyzing",
            "hostname": hostname,
            "submitted_at": now.isoformat(),
            "evidence_file": str(evidence_file),
            "report_file": None,
            "analysis_result": None,
            "error": None,
            "progress": {"step": "initializing", "detail": "正在初始化分析引擎...", "percent": 5},
            "source": "web",
        }
        server.tasks[task_id] = task

        # 异步启动分析
        asyncio.create_task(server._run_analysis(task_id, evidence))

        return web.json_response({
            "task_id": task_id,
            "status": "analyzing",
            "message": "分析任务已创建",
        })

    async def handle_web_task_progress(request: web.Request) -> web.Response:
        """查询 Web 分析任务的详细进度（含 progress 和完成后的完整结果）"""
        task_id = request.match_info["task_id"]
        task = server.tasks.get(task_id)
        if not task:
            return web.json_response({"error": "Task not found"}, status=404)

        resp = {
            "task_id": task["task_id"],
            "status": task["status"],
            "hostname": task["hostname"],
            "progress": task.get("progress"),
            "error": task.get("error"),
        }

        # 如果已完成，附带分析结果和报告
        if task["status"] == "completed":
            resp["analysis"] = task.get("analysis_result")
            # 读取 Markdown 报告内容
            report_file = task.get("report_file")
            if report_file:
                try:
                    from pathlib import Path as _P
                    resp["report_md"] = _P(report_file).read_text(encoding="utf-8")
                except Exception:
                    resp["report_md"] = ""

        return web.json_response(resp)

    # 注册路由
    app.router.add_get("/", handle_dashboard)
    app.router.add_get("/web/api/config", handle_get_config)
    app.router.add_post("/web/api/config", handle_save_config)
    app.router.add_post("/web/api/test-llm", handle_test_llm)
    app.router.add_post("/web/api/analyze", handle_web_analyze)
    app.router.add_get("/web/api/task/{task_id}", handle_web_task_progress)

    # 挂载 Next.js 静态文件
    if FRONTEND_OUT_DIR.exists():
        # 挂载子目录（如 _next/）
        for child in FRONTEND_OUT_DIR.iterdir():
            if child.is_dir():
                app.router.add_static(f"/{child.name}/", path=child, name=f"static_{child.name}")

        # 挂载根目录下的静态文件（favicon.ico 等）
        async def handle_static_file(request: web.Request) -> web.Response:
            filename = request.match_info.get("filename", "")
            filepath = FRONTEND_OUT_DIR / filename
            if filepath.is_file() and filepath.resolve().is_relative_to(FRONTEND_OUT_DIR.resolve()):
                return web.FileResponse(filepath)
            return web.Response(status=404, text="Not Found")

        app.router.add_get("/{filename}", handle_static_file)

    logger.info("Web 面板路由已注册")


def create_web_app(server: "AnalysisServer", manage_lifecycle: bool = True) -> web.Application:
    """
    创建独立的 Web 面板应用（用于在独立端口运行）。
    共享同一个 AnalysisServer 实例。

    参数:
        server: 共享的 AnalysisServer 实例
        manage_lifecycle: 是否注册 startup/cleanup 钩子来管理 server 生命周期。
                         在双端口模式下由调用方手动管理，应传 False。
    """
    app = web.Application()

    # 注册 Web 面板路由
    setup_web_routes(app, server)

    # 也注册 API 路由，这样 Web 面板可以直接调用 API
    app.router.add_get("/api/v1/health", server.handle_health)
    app.router.add_post("/api/v1/evidence", server.handle_submit_evidence)
    app.router.add_post("/api/v1/analyze", server.handle_upload_and_analyze)
    app.router.add_get("/api/v1/tasks", server.handle_list_tasks)
    app.router.add_get("/api/v1/tasks/{task_id}", server.handle_get_task)
    app.router.add_get("/api/v1/reports/{task_id}", server.handle_get_report)

    if manage_lifecycle:
        async def on_startup(app):
            await server.init()

        async def on_cleanup(app):
            await server.cleanup()

        app.on_startup.append(on_startup)
        app.on_cleanup.append(on_cleanup)

    return app
