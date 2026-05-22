"""
分析服务端 - 基于 aiohttp 的 HTTP API

接收客户端证据数据，调用 LLM 进行智能分析，生成应急响应报告。

用法：
    python -m server                                   # 默认 API 0.0.0.0:8080
    python -m server --host 127.0.0.1 --port 9090      # 指定 API 地址
    python -m server --web-port 8888                    # 启用 Web 管理面板
    python -m server --port 8080 --web-port 8888        # API + Web 双端口
"""

import asyncio
import json
import logging
import signal
import uuid
import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from aiohttp import web

from server.analyzer import EvidenceAnalyzer
from server.report_builder import ServerReportBuilder

from server.settings import Settings
from server.llm_client import LLMClient


class AnalysisServer:
    """分析服务端"""

    def __init__(self, settings: Settings):
        self.logger = logging.getLogger("server")
        self.settings = settings
        self.llm_client: Optional[LLMClient] = None
        self.analyzer: Optional[EvidenceAnalyzer] = None
        self.report_builder: Optional[ServerReportBuilder] = None
        self.tasks: Dict[str, Dict[str, Any]] = {}  # task_id -> task_info

        self.reports_dir = Path("reports")
        self.evidence_dir = Path("evidence")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    async def init(self):
        """初始化 LLM 客户端和分析器"""
        if self.settings.has_llm:
            try:
                self.llm_client = LLMClient(self.settings)
                self.analyzer = EvidenceAnalyzer(self.llm_client)
                self.report_builder = ServerReportBuilder(self.llm_client)
                self.logger.info("LLM 客户端初始化成功，智能分析已启用")
            except Exception as e:
                self.logger.warning(f"LLM 初始化失败: {e}，将使用本地分析")
                self.analyzer = EvidenceAnalyzer(None)
                self.report_builder = ServerReportBuilder(None)
        else:
            self.logger.info("未配置 LLM，使用本地分析模式")
            self.analyzer = EvidenceAnalyzer(None)
            self.report_builder = ServerReportBuilder(None)

    async def cleanup(self):
        """清理资源"""
        if self.llm_client:
            await self.llm_client.close()

    # ==================================================================
    #  API 路由处理器
    # ==================================================================

    async def handle_health(self, request: web.Request) -> web.Response:
        """健康检查"""
        return web.json_response({
            "status": "ok",
            "llm_enabled": self.llm_client is not None,
            "tasks_count": len(self.tasks),
            "server_time": datetime.now().isoformat(),
        })

    async def handle_submit_evidence(self, request: web.Request) -> web.Response:
        """接收客户端提交的证据数据"""
        try:
            evidence = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        # 基本验证
        if not isinstance(evidence, dict):
            return web.json_response({"error": "Evidence must be a JSON object"}, status=400)

        task_id = str(uuid.uuid4())[:8]
        hostname = evidence.get("host_info", {}).get("hostname", "unknown")
        now = datetime.now()

        # 保存原始证据
        evidence_file = self.evidence_dir / f"evidence_{hostname}_{now.strftime('%Y%m%d_%H%M%S')}_{task_id}.json"
        with open(evidence_file, "w", encoding="utf-8") as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2)

        # 创建任务
        task = {
            "task_id": task_id,
            "status": "queued",
            "hostname": hostname,
            "submitted_at": now.isoformat(),
            "evidence_file": str(evidence_file),
            "report_file": None,
            "analysis_result": None,
            "error": None,
        }
        self.tasks[task_id] = task

        self.logger.info(f"收到证据: task_id={task_id}, hostname={hostname}")

        # 异步启动分析
        asyncio.create_task(self._run_analysis(task_id, evidence))

        return web.json_response({
            "task_id": task_id,
            "status": "queued",
            "message": f"证据已接收，分析任务已排队。查询进度: GET /api/v1/tasks/{task_id}",
        })

    async def handle_get_task(self, request: web.Request) -> web.Response:
        """查询任务状态"""
        task_id = request.match_info["task_id"]
        task = self.tasks.get(task_id)
        if not task:
            return web.json_response({"error": "Task not found"}, status=404)

        # 返回任务信息（不含大量 analysis_result 原始数据）
        resp = {
            "task_id": task["task_id"],
            "status": task["status"],
            "hostname": task["hostname"],
            "submitted_at": task["submitted_at"],
            "report_file": task["report_file"],
            "error": task["error"],
            "progress": task.get("progress"),
        }
        return web.json_response(resp)

    async def handle_list_tasks(self, request: web.Request) -> web.Response:
        """列出所有任务"""
        tasks_list = []
        for t in sorted(self.tasks.values(), key=lambda x: x["submitted_at"], reverse=True):
            tasks_list.append({
                "task_id": t["task_id"],
                "status": t["status"],
                "hostname": t["hostname"],
                "submitted_at": t["submitted_at"],
                "report_file": t["report_file"],
            })
        return web.json_response({"tasks": tasks_list[:50]})

    async def handle_get_report(self, request: web.Request) -> web.Response:
        """下载报告"""
        task_id = request.match_info["task_id"]
        task = self.tasks.get(task_id)
        if not task:
            return web.json_response({"error": "Task not found"}, status=404)
        if task["status"] != "completed":
            return web.json_response({"error": f"Task status: {task['status']}"}, status=400)
        if not task["report_file"] or not Path(task["report_file"]).exists():
            return web.json_response({"error": "Report file not found"}, status=404)

        report_path = Path(task["report_file"])
        return web.FileResponse(
            path=report_path,
            headers={
                "Content-Disposition": f'attachment; filename="{report_path.name}"',
            },
        )

    async def handle_upload_and_analyze(self, request: web.Request) -> web.Response:
        """同步分析：上传证据并等待分析完成"""
        try:
            evidence = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        task_id = str(uuid.uuid4())[:8]
        hostname = evidence.get("host_info", {}).get("hostname", "unknown")
        now = datetime.now()

        # 保存证据
        evidence_file = self.evidence_dir / f"evidence_{hostname}_{now.strftime('%Y%m%d_%H%M%S')}_{task_id}.json"
        with open(evidence_file, "w", encoding="utf-8") as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2)

        task = {
            "task_id": task_id,
            "status": "analyzing",
            "hostname": hostname,
            "submitted_at": now.isoformat(),
            "evidence_file": str(evidence_file),
            "report_file": None,
            "analysis_result": None,
            "error": None,
        }
        self.tasks[task_id] = task

        # 同步执行分析
        await self._run_analysis(task_id, evidence)

        task = self.tasks[task_id]
        return web.json_response({
            "task_id": task_id,
            "status": task["status"],
            "report_file": task["report_file"],
            "error": task["error"],
        })

    # ==================================================================
    #  后台分析流程
    # ==================================================================

    async def _run_analysis(self, task_id: str, evidence: Dict[str, Any]):
        """执行完整的分析流程"""
        task = self.tasks[task_id]
        task["status"] = "analyzing"
        task["progress"] = {"step": "initializing", "detail": "正在初始化分析引擎...", "percent": 5}

        try:
            self.logger.info(f"[{task_id}] 开始分析...")

            # 阶段 1: 威胁检测（本地规则 + LLM 增强）
            task["progress"] = {"step": "local_detection", "detail": "正在执行本地规则威胁检测...", "percent": 10}
            self.logger.info(f"[{task_id}] 阶段 1: 威胁检测")
            analysis_result = await self.analyzer.analyze_evidence(evidence, progress_callback=self._make_progress_cb(task_id))

            # 阶段 2: 生成报告
            task["progress"] = {"step": "report_generation", "detail": "正在生成分析报告...", "percent": 90}
            self.logger.info(f"[{task_id}] 阶段 2: 生成报告")
            report_md = await self.report_builder.build_report(evidence, analysis_result)

            # 保存报告
            hostname = evidence.get("host_info", {}).get("hostname", "unknown")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.reports_dir / f"report_{hostname}_{ts}_{task_id}.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_md)

            # 同时保存 JSON 分析结果
            json_file = self.reports_dir / f"analysis_{hostname}_{ts}_{task_id}.json"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(analysis_result, f, ensure_ascii=False, indent=2)

            task["status"] = "completed"
            task["progress"] = {"step": "done", "detail": "分析完成", "percent": 100}
            task["report_file"] = str(report_file)
            task["analysis_result"] = analysis_result
            self.logger.info(f"[{task_id}] 分析完成: {report_file}")

        except Exception as e:
            task["status"] = "failed"
            task["progress"] = {"step": "error", "detail": f"分析失败: {str(e)[:200]}", "percent": 0}
            task["error"] = str(e)
            self.logger.error(f"[{task_id}] 分析失败: {e}", exc_info=True)

    def _make_progress_cb(self, task_id: str):
        """创建一个进度回调函数供 analyzer 调用"""
        def callback(step: str, detail: str, percent: int):
            task = self.tasks.get(task_id)
            if task:
                task["progress"] = {"step": step, "detail": detail, "percent": percent}
        return callback


# ==================================================================
#  应用工厂
# ==================================================================

def create_app(settings: Settings) -> web.Application:
    """创建 aiohttp 应用"""
    server = AnalysisServer(settings)
    app = web.Application()

    # 路由注册
    app.router.add_get("/api/v1/health", server.handle_health)
    app.router.add_post("/api/v1/evidence", server.handle_submit_evidence)
    app.router.add_post("/api/v1/analyze", server.handle_upload_and_analyze)
    app.router.add_get("/api/v1/tasks", server.handle_list_tasks)
    app.router.add_get("/api/v1/tasks/{task_id}", server.handle_get_task)
    app.router.add_get("/api/v1/reports/{task_id}", server.handle_get_report)

    async def on_startup(app):
        await server.init()

    async def on_cleanup(app):
        await server.cleanup()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    return app


def _build_frontend():
    """编译 Next.js 前端面板到 frontend/out/ 静态文件"""
    import shutil
    import subprocess as sp

    project_root = Path(__file__).resolve().parent.parent
    frontend_dir = project_root / "frontend"
    package_json = frontend_dir / "package.json"

    if not package_json.exists():
        print("[ERROR] 未找到 frontend/package.json，跳过编译")
        return False

    # 检查 npm 是否可用
    npm_cmd = shutil.which("npm")
    if not npm_cmd:
        print("[ERROR] 未找到 npm 命令，请先安装 Node.js")
        return False

    # npm install (如果 node_modules 不存在)
    node_modules = frontend_dir / "node_modules"
    if not node_modules.exists():
        print("[BUILD] 正在安装前端依赖 (npm install)...")
        ret = sp.run([npm_cmd, "install"], cwd=str(frontend_dir))
        if ret.returncode != 0:
            print("[ERROR] npm install 失败")
            return False

    # npm run build
    print("[BUILD] 正在编译前端面板 (npm run build)...")
    ret = sp.run([npm_cmd, "run", "build"], cwd=str(frontend_dir))
    if ret.returncode != 0:
        print("[ERROR] npm run build 失败")
        return False

    out_dir = frontend_dir / "out"
    if out_dir.exists() and (out_dir / "index.html").exists():
        print(f"[BUILD] 编译完成 -> {out_dir}")
        return True
    else:
        print("[ERROR] 编译产物异常，未找到 out/index.html")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="应急响应分析服务端",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m server                       # 默认启动 API (0.0.0.0:8080)
  python -m server -p 9090               # 指定 API 端口
  python -m server -w 8888               # 启用 Web 管理面板
  python -m server -p 8080 -w 8888       # API + Web 双端口
  python -m server -c config.json        # 指定配置文件
  python -m server --build-web           # 仅编译前端面板
  python -m server -w 8888 --build-web   # 编译前端后启动服务
        """,
    )
    parser.add_argument("-H", "--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=8080, help="API 端口 (默认 8080)")
    parser.add_argument("-w", "--web-port", type=int, default=None, help="Web 面板端口 (如 8888)")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--build-web", action="store_true", help="编译 Next.js 前端面板 (需要 Node.js)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # 如果指定了 --build-web，先编译前端
    if args.build_web:
        ok = _build_frontend()
        if not ok:
            sys.exit(1)
        # 如果没有指定端口参数，说明只想编译，编译完退出
        if args.web_port is None and args.port == 8080:
            # 检查是否只传了 --build-web 而没有其他参数
            import sys as _sys
            raw_args = _sys.argv[1:]
            non_build_args = [a for a in raw_args if a not in ("--build-web",)]
            if not non_build_args:
                print("[OK] 前端编译完成，退出。")
                sys.exit(0)

    print("\n" + "=" * 60)
    print("  应急响应分析服务端 v1.0")
    print("=" * 60)

    if args.config:
        settings = Settings(config_file=Path(args.config))
    else:
        settings = Settings()

    print(f"  LLM 协议: {settings.llm_protocol}")
    print(f"  LLM 模型: {settings.llm_model}")
    print(f"  LLM 可用: {'是' if settings.has_llm else '否'}")
    print(f"  API 地址: {args.host}:{args.port}")
    if args.web_port:
        print(f"  Web 面板: {args.host}:{args.web_port}")
    print("=" * 60 + "\n")

    if args.web_port:
        # 双端口模式：API + Web 面板分别监听
        asyncio.run(_run_dual(settings, args.host, args.port, args.web_port))
    else:
        # 单端口模式：仅 API
        app = create_app(settings)
        web.run_app(app, host=args.host, port=args.port,
                    print=lambda msg: logging.getLogger("server").info(msg))


async def _run_dual(settings: Settings, host: str, api_port: int, web_port: int):
    """同时运行 API 服务和 Web 管理面板（共享同一个 AnalysisServer 实例）"""
    from server.web_dashboard import create_web_app

    # 创建共享的 AnalysisServer
    server = AnalysisServer(settings)

    # ── API 应用 ──
    api_app = web.Application()
    api_app.router.add_get("/api/v1/health", server.handle_health)
    api_app.router.add_post("/api/v1/evidence", server.handle_submit_evidence)
    api_app.router.add_post("/api/v1/analyze", server.handle_upload_and_analyze)
    api_app.router.add_get("/api/v1/tasks", server.handle_list_tasks)
    api_app.router.add_get("/api/v1/tasks/{task_id}", server.handle_get_task)
    api_app.router.add_get("/api/v1/reports/{task_id}", server.handle_get_report)

    # ── Web 面板应用（包含 API 路由 + Web 路由，生命周期由此函数手动管理） ──
    web_app = create_web_app(server, manage_lifecycle=False)

    # 初始化 server（仅一次）
    await server.init()

    # 启动 API Runner
    api_runner = web.AppRunner(api_app)
    await api_runner.setup()
    api_site = web.TCPSite(api_runner, host, api_port)
    await api_site.start()

    # 启动 Web Runner
    web_runner = web.AppRunner(web_app)
    await web_runner.setup()
    web_site = web.TCPSite(web_runner, host, web_port)
    await web_site.start()

    log = logging.getLogger("server")
    log.info(f"API 服务已启动: http://{host}:{api_port}")
    log.info(f"Web 管理面板已启动: http://{host}:{web_port}")

    # 保持运行直到收到中断信号
    stop_event = asyncio.Event()

    # 注册信号处理（跨平台兼容）
    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
    except NotImplementedError:
        # Windows 不支持 add_signal_handler，通过 KeyboardInterrupt 退出
        pass

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        log.info("正在关闭服务...")
        await server.cleanup()
        await api_runner.cleanup()
        await web_runner.cleanup()


if __name__ == "__main__":
    main()
