"""
证据分析引擎 — 对客户端采集的数据进行威胁检测与 LLM 深度分析

分析流程:
    1. 本地规则检测（影子账户、挖矿进程、恶意 cron、可疑连接等）
    2. LLM 智能分析（逐类别深度分析 + 攻击链还原）
    3. 攻击者画像生成
    4. 综合评估
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from server.llm_client import LLMClient


class EvidenceAnalyzer:
    """证据分析引擎"""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.logger = logging.getLogger("analyzer")
        self.llm = llm_client

    async def analyze_evidence(self, evidence: Dict[str, Any], progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        分析客户端提交的完整证据，返回分析结果。

        Args:
            evidence: 客户端采集的证据数据
            progress_callback: 可选的进度回调 callback(step, detail, percent)

        Returns:
            {
                "threats": [...],
                "summary": {...},
                "attack_chain": {...},
                "attacker_profile": {...},
                "llm_analysis": {...},
            }
        """
        def _progress(step: str, detail: str, percent: int):
            if progress_callback:
                progress_callback(step, detail, percent)

        result = {
            "analysis_time": datetime.now().isoformat(),
            "hostname": evidence.get("host_info", {}).get("hostname", "unknown"),
            "threats": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "attack_chain": {},
            "attacker_profile": {},
            "llm_analysis": {},
        }

        # ── 本地规则检测 ──
        is_windows = evidence.get("platform", "linux") == "windows"
        platform_name = "Windows" if is_windows else "Linux"
        self.logger.info(f"执行本地规则威胁检测（{platform_name}）...")

        threats = []

        _progress("detect_shadow_accounts", "正在检测影子账户...", 12)
        threats.extend(self._detect_shadow_accounts(evidence))

        _progress("detect_processes", "正在检测可疑进程...", 18)
        threats.extend(self._detect_suspicious_processes(evidence))

        _progress("detect_cron", "正在检测恶意计划任务...", 25)
        threats.extend(self._detect_malicious_cron(evidence))

        _progress("detect_network", "正在检测可疑网络连接...", 32)
        threats.extend(self._detect_suspicious_network(evidence))

        _progress("detect_auth", "正在分析认证日志...", 38)
        threats.extend(self._detect_auth_anomalies(evidence))

        _progress("detect_files", "正在检测文件系统指标...", 44)
        threats.extend(self._detect_file_indicators(evidence))

        # Windows 专有检测
        if is_windows:
            _progress("detect_windows", "正在检测 Windows 专有威胁...", 50)
            threats.extend(self._detect_windows_threats(evidence))

        result["threats"] = threats

        # 统计
        for t in threats:
            sev = t.get("severity", "low")
            if sev in result["summary"]:
                result["summary"][sev] += 1

        self.logger.info(
            f"本地检测完成: {len(threats)} 个威胁 "
            f"(C:{result['summary']['critical']} H:{result['summary']['high']} "
            f"M:{result['summary']['medium']} L:{result['summary']['low']})"
        )

        # ── 生成攻击链 ──
        _progress("build_chain", "正在构建攻击链...", 55)
        result["attack_chain"] = self._build_attack_chain(threats, evidence)

        # ── 生成攻击者画像 ──
        _progress("build_profile", "正在生成攻击者画像...", 60)
        result["attacker_profile"] = self._build_attacker_profile(threats, evidence)

        # ── LLM 深度分析 ──
        if self.llm and threats:
            self.logger.info("调用 LLM 进行深度分析...")
            _progress("llm_analysis", "正在调用 LLM 深度分析...", 65)
            result["llm_analysis"] = await self._run_llm_analysis(threats, evidence, result, _progress)
        else:
            if not self.llm:
                self.logger.info("未配置 LLM，跳过深度分析")
            else:
                self.logger.info("未发现威胁，跳过深度分析")

        _progress("local_complete", "分析引擎处理完成", 88)
        return result

    # ==================================================================
    #  本地规则检测
    # ==================================================================

    def _detect_shadow_accounts(self, evidence: Dict) -> List[Dict]:
        """检测影子账户（UID=0 的非 root 账户）"""
        threats = []
        for acc in evidence.get("accounts", {}).get("uid0_accounts", []):
            threats.append({
                "type": "shadow_account",
                "severity": "critical",
                "title": f"影子账户: {acc.get('username', '?')}",
                "description": f"UID 为 0 的非 root 账户，具有超级管理员权限",
                "details": acc,
                "recommendation": "立即禁用该账户并调查创建来源",
                "timestamp": datetime.now().isoformat(),
            })
        return threats

    def _detect_suspicious_processes(self, evidence: Dict) -> List[Dict]:
        """检测可疑进程"""
        threats = []
        indicators = evidence.get("processes", {}).get("suspicious_indicators", [])

        # 挖矿关键词
        mining_keywords = {"xmrig", "minerd", "cpuminer", "ethminer", "cgminer", "stratum", "pool."}

        for ind in indicators:
            kw = ind.get("keyword", "").lower()
            cmd = ind.get("command", "")
            cpu = ind.get("cpu", 0)

            is_mining = any(mk in kw for mk in mining_keywords)

            if is_mining:
                threats.append({
                    "type": "mining_process",
                    "severity": "high",
                    "title": f"挖矿进程: PID {ind.get('pid', '?')}",
                    "description": f"检测到挖矿特征 '{kw}'，CPU={cpu}%",
                    "details": ind,
                    "recommendation": "立即终止进程并检查持久化机制",
                    "timestamp": datetime.now().isoformat(),
                })
            else:
                threats.append({
                    "type": "suspicious_process",
                    "severity": "medium",
                    "title": f"可疑进程: PID {ind.get('pid', '?')} ({kw})",
                    "description": f"进程包含可疑特征 '{kw}'",
                    "details": ind,
                    "recommendation": "人工审查进程命令行和来源",
                    "timestamp": datetime.now().isoformat(),
                })

        # 高 CPU 进程检测（>80%）
        for proc in evidence.get("processes", {}).get("top_cpu", []):
            if proc.get("cpu", 0) > 80:
                cmd = proc.get("command", "")
                # 排除已知安全进程
                safe_procs = ["Xorg", "gnome-shell", "firefox", "chrome", "python", "java", "node", "mysqld", "postgres"]
                if not any(sp.lower() in cmd.lower() for sp in safe_procs):
                    threats.append({
                        "type": "high_cpu_process",
                        "severity": "medium",
                        "title": f"高 CPU 进程: {cmd[:50]}",
                        "description": f"CPU 占用 {proc.get('cpu', 0)}%",
                        "details": proc,
                        "recommendation": "检查进程是否为合法业务进程",
                        "timestamp": datetime.now().isoformat(),
                    })

        return threats

    def _detect_malicious_cron(self, evidence: Dict) -> List[Dict]:
        """检测恶意计划任务（支持 Linux cron 和 Windows 计划任务）"""
        threats = []
        cron = evidence.get("cron_jobs", {})
        is_windows = evidence.get("platform", "linux") == "windows"

        # 合并所有计划任务内容
        combined = "\n".join([
            cron.get("system_crontab", ""),
            cron.get("user_crontabs", ""),
            cron.get("anacrontab", ""),
            cron.get("scheduled_tasks_detail", ""),
            cron.get("startup_programs", ""),
        ] + list(cron.get("cron_d_contents", {}).values()))

        if not combined.strip():
            return threats

        # 通用恶意模式（Linux + Windows）
        malware_patterns = {
            r'curl.*\|.*(?:bash|sh)': ("critical", "无文件攻击: curl | bash"),
            r'wget.*\|.*(?:bash|sh)': ("critical", "无文件攻击: wget | sh"),
            r'/tmp/.*\.sh': ("high", "/tmp 目录脚本执行"),
            r'/dev/shm/': ("high", "/dev/shm 内存文件系统活动"),
            r'nc\s+.*-e': ("critical", "Netcat 反向 Shell"),
            r'mkfifo.*nc': ("critical", "命名管道反向 Shell"),
            r'base64.*-d': ("medium", "Base64 解码执行"),
            r'chattr.*\+i': ("high", "文件不可变属性设置"),
            r'nohup.*&': ("medium", "后台持久运行进程"),
            r'python.*-c.*import.*socket': ("high", "Python 反向 Shell"),
        }

        # Windows 专有恶意模式
        if is_windows:
            malware_patterns.update({
                r'powershell.*-enc': ("critical", "PowerShell 编码命令执行"),
                r'powershell.*-e\s+[A-Za-z0-9+/=]{20,}': ("critical", "PowerShell Base64 编码执行"),
                r'powershell.*downloadstring': ("critical", "PowerShell 远程下载执行"),
                r'powershell.*iex': ("high", "PowerShell Invoke-Expression"),
                r'powershell.*bypass': ("high", "PowerShell 执行策略绕过"),
                r'certutil.*-urlcache': ("high", "Certutil 远程下载"),
                r'certutil.*-decode': ("high", "Certutil 解码执行"),
                r'bitsadmin.*\/transfer': ("high", "BITS 传输下载"),
                r'mshta\s+http': ("critical", "MSHTA 远程脚本执行"),
                r'regsvr32.*\/s.*\/n.*\/u.*\/i:http': ("critical", "Regsvr32 远程脚本加载"),
                r'wmic.*process.*call.*create': ("high", "WMIC 远程进程创建"),
                r'schtasks.*\/create': ("medium", "计划任务创建"),
                r'\\appdata\\local\\temp\\': ("medium", "Temp 目录可执行文件"),
                r'\\windows\\temp\\': ("medium", "Windows Temp 目录活动"),
            })

        for pattern, (severity, title) in malware_patterns.items():
            for match in re.finditer(pattern, combined, re.IGNORECASE):
                threats.append({
                    "type": "malicious_cron",
                    "severity": severity,
                    "title": title,
                    "description": f"计划任务中发现恶意模式: {match.group(0)[:100]}",
                    "details": {
                        "matched_pattern": pattern,
                        "matched_text": match.group(0)[:200],
                    },
                    "recommendation": "立即移除恶意计划任务并追查来源",
                    "timestamp": datetime.now().isoformat(),
                })

        return threats

    def _detect_suspicious_network(self, evidence: Dict) -> List[Dict]:
        """检测可疑网络连接"""
        threats = []
        network = evidence.get("network", {})

        for port in network.get("suspicious_ports", []):
            threats.append({
                "type": "suspicious_connection",
                "severity": "high",
                "title": f"可疑端口连接: {port}",
                "description": f"检测到非常用端口 {port} 的活动连接，可能是 C2 通信或后门",
                "details": {"port": port},
                "recommendation": "排查连接来源和目的 IP",
                "timestamp": datetime.now().isoformat(),
            })

        return threats

    def _detect_auth_anomalies(self, evidence: Dict) -> List[Dict]:
        """检测认证异常（支持 Linux 和 Windows 日志格式）"""
        threats = []
        logs = evidence.get("log_analysis", {})
        is_windows = evidence.get("platform", "linux") == "windows"

        # 分析 auth_log / secure_log 中的登录信息
        for log_key in ["auth_log", "secure_log"]:
            content = logs.get(log_key, "")
            if not content:
                continue

            # Windows 格式登录事件（采集器已转换格式：Accepted logon for user from ip LogonType=X）
            if is_windows:
                for match in re.finditer(r'Accepted\s+logon\s+for\s+(\S+)\s+from\s+(\S+)\s+LogonType=(\d+)', content, re.IGNORECASE):
                    user, ip, logon_type = match.groups()
                    logon_type_names = {
                        "2": "Interactive", "3": "Network", "10": "RemoteInteractive(RDP)",
                        "11": "CachedInteractive",
                    }
                    method = logon_type_names.get(logon_type, f"Type{logon_type}")
                    # RDP 登录标记更高优先级
                    severity = "medium" if logon_type == "10" else "low"
                    threats.append({
                        "type": "successful_login",
                        "severity": severity,
                        "title": f"登录记录: {user} from {ip} ({method})",
                        "description": f"用户 {user} 通过 {method} 从 {ip} 登录 (Windows)",
                        "details": {"username": user, "source_ip": ip, "method": method, "logon_type": logon_type},
                        "recommendation": "验证是否为授权行为" + ("，特别关注 RDP 远程登录" if logon_type == "10" else ""),
                        "timestamp": datetime.now().isoformat(),
                    })
                continue  # Windows 格式已处理，跳过 Linux 格式解析

            # Linux 格式：成功登录
            for match in re.finditer(r'Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)', content, re.IGNORECASE):
                method, user, ip = match.groups()
                threats.append({
                    "type": "successful_login",
                    "severity": "low",
                    "title": f"登录记录: {user} from {ip}",
                    "description": f"用户 {user} 通过 {method} 从 {ip} 登录",
                    "details": {"username": user, "source_ip": ip, "method": method},
                    "recommendation": "验证是否为授权行为",
                    "timestamp": datetime.now().isoformat(),
                })

            # 失败登录统计
            failed_counts = {}
            for match in re.finditer(r'Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)', content, re.IGNORECASE):
                method, user, ip = match.groups()
                key = f"{ip}_{user}"
                failed_counts[key] = failed_counts.get(key, 0) + 1

            for key, count in failed_counts.items():
                if count >= 3:
                    ip, user = key.rsplit("_", 1)
                    threats.append({
                        "type": "failed_login_bruteforce",
                        "severity": "high" if count >= 10 else "medium",
                        "title": f"暴力破解: {count} 次失败 ({ip} -> {user})",
                        "description": f"从 {ip} 对用户 {user} 进行了 {count} 次失败登录",
                        "details": {"username": user, "source_ip": ip, "attempt_count": count},
                        "recommendation": "考虑封禁 IP，检查账户安全",
                        "timestamp": datetime.now().isoformat(),
                    })

            # 提权活动
            for match in re.finditer(r'(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)', content):
                user, tty, pwd, target_user, command = match.groups()
                suspicious = any(cmd in command.lower() for cmd in ["bash", "sh", "su", "chmod", "passwd", "chown"])
                threats.append({
                    "type": "privilege_escalation",
                    "severity": "high" if suspicious else "low",
                    "title": f"提权: {user} -> {target_user}",
                    "description": f"用户 {user} 提权执行: {command[:80]}",
                    "details": {
                        "original_user": user,
                        "target_user": target_user,
                        "command": command,
                        "is_suspicious": suspicious,
                    },
                    "recommendation": "验证是否为授权操作",
                    "timestamp": datetime.now().isoformat(),
                })

        # 分析 syslog / messages 中的服务变化
        for log_key in ["syslog", "messages"]:
            content = logs.get(log_key, "")
            if not content:
                continue
            for match in re.finditer(r'(stopped|started|restarted)\s+(\S+)', content, re.IGNORECASE):
                threats.append({
                    "type": "service_activity",
                    "severity": "medium",
                    "title": f"服务变化: {match.group(2)}",
                    "description": f"服务 {match.group(2)} 被 {match.group(1)}",
                    "details": {"service_name": match.group(2), "activity": match.group(0)[:100]},
                    "recommendation": "验证是否为授权操作",
                    "timestamp": datetime.now().isoformat(),
                })

        return threats

    def _detect_file_indicators(self, evidence: Dict) -> List[Dict]:
        """检测文件系统安全指标"""
        threats = []
        fi = evidence.get("file_indicators", {})

        # /tmp 可执行文件
        tmp_exec = fi.get("tmp_executables", "")
        if tmp_exec.strip():
            lines = [l for l in tmp_exec.strip().split("\n") if l.strip()]
            if lines:
                threats.append({
                    "type": "suspicious_file",
                    "severity": "medium",
                    "title": f"/tmp 可执行文件: {len(lines)} 个",
                    "description": f"在 /tmp 目录发现 {len(lines)} 个可执行文件",
                    "details": {"count": len(lines), "files": tmp_exec[:500]},
                    "recommendation": "逐一审查这些文件的来源和功能",
                    "timestamp": datetime.now().isoformat(),
                })

        # /dev/shm 文件
        devshm = fi.get("devshm_files", "")
        if devshm.strip():
            lines = [l for l in devshm.strip().split("\n") if l.strip() and not l.startswith("total")]
            # 排除 . 和 ..
            real_files = [l for l in lines if not l.endswith(" .") and not l.endswith(" ..")]
            if real_files:
                threats.append({
                    "type": "suspicious_file",
                    "severity": "high",
                    "title": f"/dev/shm 异常文件: {len(real_files)} 个",
                    "description": "在内存文件系统 /dev/shm 发现文件，可能是无文件攻击组件",
                    "details": {"count": len(real_files), "files": devshm[:500]},
                    "recommendation": "立即检查文件内容并保存取证副本",
                    "timestamp": datetime.now().isoformat(),
                })

        # /tmp 隐藏文件
        hidden = fi.get("hidden_in_tmp", "")
        if hidden.strip():
            lines = [l for l in hidden.strip().split("\n") if l.strip()]
            if lines:
                threats.append({
                    "type": "suspicious_file",
                    "severity": "medium",
                    "title": f"/tmp 隐藏文件: {len(lines)} 个",
                    "description": "在 /tmp 目录发现隐藏文件",
                    "details": {"count": len(lines), "files": hidden[:500]},
                    "recommendation": "检查隐藏文件内容",
                    "timestamp": datetime.now().isoformat(),
                })

        return threats

    # ==================================================================
    #  Windows 专有威胁检测
    # ==================================================================

    def _detect_windows_threats(self, evidence: Dict) -> List[Dict]:
        """检测 Windows 专有安全威胁"""
        threats = []
        win = evidence.get("windows_specific", {})
        logs = evidence.get("log_analysis", {})
        fi = evidence.get("file_indicators", {})
        accounts = evidence.get("accounts", {})

        # ── RDP 安全检查 ──
        rdp_settings = win.get("rdp_settings", "")
        if "fDenyTSConnections = 0" in rdp_settings:
            threats.append({
                "type": "rdp_enabled",
                "severity": "medium",
                "title": "RDP 远程桌面已启用",
                "description": "Windows 远程桌面协议已启用，可能成为攻击入口",
                "details": {"rdp_settings": rdp_settings[:300]},
                "recommendation": "如非必要请禁用 RDP，否则启用 NLA 并限制访问 IP",
                "timestamp": datetime.now().isoformat(),
            })
            if "UserAuthentication (NLA) = 0" in rdp_settings:
                threats.append({
                    "type": "rdp_nla_disabled",
                    "severity": "high",
                    "title": "RDP NLA 网络级别认证未启用",
                    "description": "远程桌面未启用网络级别认证，降低了暴力破解难度",
                    "details": {"rdp_settings": rdp_settings[:300]},
                    "recommendation": "立即启用 NLA 网络级别认证",
                    "timestamp": datetime.now().isoformat(),
                })

        # ── UAC 检查 ──
        uac = win.get("uac_settings", "")
        if "EnableLUA = 0" in uac:
            threats.append({
                "type": "uac_disabled",
                "severity": "high",
                "title": "UAC 用户账户控制已禁用",
                "description": "Windows UAC 已被禁用，恶意软件可无提示获取管理员权限",
                "details": {"uac_settings": uac[:300]},
                "recommendation": "立即重新启用 UAC",
                "timestamp": datetime.now().isoformat(),
            })

        # ── SMB 检查 ──
        smb = win.get("smb_config", "")
        if "EnableSMB1Protocol" in smb and "True" in smb.split("EnableSMB1Protocol")[1][:20]:
            threats.append({
                "type": "smb1_enabled",
                "severity": "high",
                "title": "SMBv1 协议已启用",
                "description": "过时的 SMBv1 协议已启用，存在 EternalBlue 等严重漏洞风险",
                "details": {"smb_config": smb[:300]},
                "recommendation": "禁用 SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                "timestamp": datetime.now().isoformat(),
            })

        # ── 密码永不过期账户 ──
        pwd_never_expires = accounts.get("password_never_expires", "")
        if pwd_never_expires.strip():
            threats.append({
                "type": "password_never_expires",
                "severity": "medium",
                "title": f"密码永不过期账户: {pwd_never_expires[:100]}",
                "description": "存在密码永不过期的活动账户，违反安全最佳实践",
                "details": {"accounts": pwd_never_expires[:300]},
                "recommendation": "为所有账户设置密码过期策略",
                "timestamp": datetime.now().isoformat(),
            })

        # ── WMI 持久化检测 ──
        wmi_subs = win.get("wmi_subscriptions", "")
        if wmi_subs.strip() and "Name" in wmi_subs:
            threats.append({
                "type": "wmi_persistence",
                "severity": "high",
                "title": "WMI 事件订阅持久化",
                "description": "检测到 WMI 事件订阅，可能是恶意软件持久化机制",
                "details": {"wmi_subscriptions": wmi_subs[:500]},
                "recommendation": "审查所有 WMI 事件订阅，移除可疑条目",
                "timestamp": datetime.now().isoformat(),
            })

        # ── PowerShell 可疑脚本块 ──
        ps_events = logs.get("powershell_events", "")
        if ps_events.strip():
            ps_suspicious = [
                "invoke-mimikatz", "invoke-expression", "downloadstring",
                "net.webclient", "start-bitstransfer", "invoke-shellcode",
                "invoke-dllinjection", "invoke-reflectivepeinjection",
                "-enc ", "frombase64string", "amsiutils", "disable-realtimemonitoring",
            ]
            for pattern in ps_suspicious:
                if pattern in ps_events.lower():
                    threats.append({
                        "type": "malicious_powershell",
                        "severity": "critical",
                        "title": f"可疑 PowerShell 活动: {pattern}",
                        "description": f"PowerShell 脚本块日志中发现可疑模式 '{pattern}'",
                        "details": {"pattern": pattern, "log_snippet": ps_events[:500]},
                        "recommendation": "立即调查 PowerShell 执行历史，检查是否存在恶意脚本",
                        "timestamp": datetime.now().isoformat(),
                    })
                    break

        # ── NTFS ADS 检测 ──
        ads = fi.get("alternate_data_streams", "")
        if ads.strip() and "Stream" in ads:
            threats.append({
                "type": "ntfs_ads",
                "severity": "high",
                "title": "NTFS 替代数据流 (ADS)",
                "description": "在临时目录发现 NTFS 替代数据流，可能隐藏恶意数据",
                "details": {"ads_info": ads[:500]},
                "recommendation": "检查替代数据流内容，确认是否包含恶意代码",
                "timestamp": datetime.now().isoformat(),
            })

        # ── BITS 传输任务检测 ──
        bits = win.get("bits_jobs", "")
        if bits.strip() and "DisplayName" in bits:
            threats.append({
                "type": "bits_job",
                "severity": "medium",
                "title": "活跃的 BITS 传输任务",
                "description": "发现活跃的 BITS 传输任务，可能被恶意软件利用下载负载",
                "details": {"bits_jobs": bits[:500]},
                "recommendation": "检查 BITS 任务的目标 URL 和下载内容",
                "timestamp": datetime.now().isoformat(),
            })

        # ── PowerShell Profile 篡改检测 ──
        ps_profile = win.get("powershell_profile", "")
        if ps_profile.strip() and "===" in ps_profile:
            threats.append({
                "type": "powershell_profile",
                "severity": "medium",
                "title": "PowerShell Profile 文件存在",
                "description": "检测到 PowerShell Profile 文件，可能被植入恶意启动代码",
                "details": {"profile_content": ps_profile[:500]},
                "recommendation": "审查 PowerShell Profile 文件内容，确认无恶意代码",
                "timestamp": datetime.now().isoformat(),
            })

        return threats

    # ==================================================================
    #  攻击链构建
    # ==================================================================

    def _build_attack_chain(self, threats: List[Dict], evidence: Dict) -> Dict[str, Any]:
        """基于威胁发现构建攻击链"""
        types_detected = set(t.get("type") for t in threats)

        phases = []

        if "failed_login_bruteforce" in types_detected:
            phases.append({
                "phase": "Initial Access",
                "name": "初始访问",
                "description": "检测到暴力破解尝试",
                "mitre_technique": "T1110 - Brute Force",
            })

        if "successful_login" in types_detected:
            phases.append({
                "phase": "Initial Access",
                "name": "成功入侵",
                "description": "攻击者已成功登录系统",
                "mitre_technique": "T1078 - Valid Accounts",
            })

        if "privilege_escalation" in types_detected:
            phases.append({
                "phase": "Privilege Escalation",
                "name": "权限提升",
                "description": "检测到权限提升活动",
                "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
            })

        if "shadow_account" in types_detected:
            phases.append({
                "phase": "Persistence",
                "name": "持久化 - 影子账户",
                "description": "攻击者创建了 UID=0 的影子账户",
                "mitre_technique": "T1136 - Create Account",
            })

        if "malicious_cron" in types_detected:
            phases.append({
                "phase": "Persistence",
                "name": "持久化 - 计划任务",
                "description": "通过恶意计划任务实现持久化",
                "mitre_technique": "T1053 - Scheduled Task/Job",
            })

        if "suspicious_connection" in types_detected:
            phases.append({
                "phase": "Command and Control",
                "name": "命令控制",
                "description": "检测到可疑 C2 通信端口",
                "mitre_technique": "T1071 - Application Layer Protocol",
            })

        if "mining_process" in types_detected:
            phases.append({
                "phase": "Impact",
                "name": "资源劫持",
                "description": "系统被植入挖矿程序",
                "mitre_technique": "T1496 - Resource Hijacking",
            })

        # 时间线
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_threats = sorted(threats, key=lambda x: severity_order.get(x.get("severity", "low"), 9))

        timeline = []
        for t in sorted_threats[:50]:
            timeline.append({
                "detected_at": t.get("timestamp", ""),
                "phase": self._threat_to_phase(t.get("type", "")),
                "type": t.get("type", ""),
                "severity": t.get("severity", ""),
                "description": t.get("title", ""),
            })

        return {
            "attack_phases": phases,
            "timeline": timeline,
            "recommendations": self._generate_recommendations(threats),
        }

    def _threat_to_phase(self, threat_type: str) -> str:
        """将威胁类型映射到攻击阶段"""
        mapping = {
            "shadow_account": "Persistence",
            "mining_process": "Impact",
            "suspicious_connection": "Command and Control",
            "malicious_cron": "Persistence",
            "failed_login_bruteforce": "Initial Access",
            "successful_login": "Initial Access",
            "privilege_escalation": "Privilege Escalation",
            "suspicious_process": "Execution",
            "high_cpu_process": "Impact",
            "suspicious_file": "Discovery",
            "service_activity": "Defense Evasion",
            # Windows 专有类型
            "rdp_enabled": "Initial Access",
            "rdp_nla_disabled": "Initial Access",
            "uac_disabled": "Defense Evasion",
            "smb1_enabled": "Lateral Movement",
            "password_never_expires": "Credential Access",
            "wmi_persistence": "Persistence",
            "malicious_powershell": "Execution",
            "ntfs_ads": "Defense Evasion",
            "bits_job": "Command and Control",
            "powershell_profile": "Persistence",
        }
        return mapping.get(threat_type, "Unknown")

    def _generate_recommendations(self, threats: List[Dict]) -> List[Dict]:
        """生成安全建议"""
        recs = []
        types = set(t.get("type") for t in threats)
        severities = [t.get("severity") for t in threats]

        if "critical" in severities:
            recs.append({
                "priority": "紧急",
                "action": "立即隔离受影响系统",
                "details": "检测到严重威胁，需立即断开网络",
                "timeline": "立即",
            })

        if "shadow_account" in types:
            recs.append({
                "priority": "紧急",
                "action": "禁用影子账户",
                "details": "删除或锁定所有 UID=0 的非 root 账户",
                "timeline": "立即",
            })

        if "mining_process" in types:
            recs.append({
                "priority": "高",
                "action": "终止挖矿进程",
                "details": "终止所有挖矿相关进程，检查启动项和计划任务",
                "timeline": "1 小时内",
            })

        if "malicious_cron" in types:
            recs.append({
                "priority": "高",
                "action": "清除恶意计划任务",
                "details": "检查并清除所有可疑 crontab 条目和 cron.d 文件",
                "timeline": "1 小时内",
            })

        if "failed_login_bruteforce" in types:
            recs.append({
                "priority": "高",
                "action": "封禁攻击 IP",
                "details": "在防火墙中封禁暴力破解来源 IP",
                "timeline": "2 小时内",
            })

        recs.append({
            "priority": "中",
            "action": "完整取证分析",
            "details": "保存日志、内存镜像和系统状态进行深入分析",
            "timeline": "24 小时内",
        })

        recs.append({
            "priority": "低",
            "action": "安全加固",
            "details": "更新系统补丁、加强访问控制、部署入侵检测系统",
            "timeline": "1 周内",
        })

        return recs

    # ==================================================================
    #  攻击者画像
    # ==================================================================

    def _build_attacker_profile(self, threats: List[Dict], evidence: Dict) -> Dict[str, Any]:
        """生成攻击者画像"""
        # 收集攻击源 IP
        attacker_ips = {}
        for t in threats:
            details = t.get("details", {})
            if isinstance(details, dict):
                ip = details.get("source_ip") or details.get("ip")
                if ip and ip not in ("local", "localhost", "127.0.0.1", "Unknown", ""):
                    attacker_ips[ip] = attacker_ips.get(ip, 0) + 1

        characteristics = {}
        if attacker_ips:
            primary = max(attacker_ips.items(), key=lambda x: x[1])
            characteristics = {
                "primary_source_ip": primary[0],
                "attack_frequency": primary[1],
                "unique_sources": len(attacker_ips),
                "attack_distribution": attacker_ips,
            }

        # 攻击模式统计
        attack_types = {}
        for t in threats:
            tp = t.get("type", "unknown")
            attack_types[tp] = attack_types.get(tp, 0) + 1

        patterns = [
            {"pattern": tp, "count": c}
            for tp, c in sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
        ]

        # 威胁评估
        critical = sum(1 for t in threats if t.get("severity") == "critical")
        high = sum(1 for t in threats if t.get("severity") == "high")

        advanced_types = {"privilege_escalation", "shadow_account", "malicious_cron",
                          "wmi_persistence", "malicious_powershell", "ntfs_ads"}
        sophistication = "advanced" if any(tp in attack_types for tp in advanced_types) else "basic"

        assessment = {
            "overall_threat_level": "critical" if critical > 0 else ("high" if high > 0 else "medium"),
            "critical_findings": critical,
            "high_findings": high,
            "attack_sophistication": sophistication,
            "persistence_indicators": [
                tp for tp in attack_types if tp in (
                    "shadow_account", "malicious_cron", "successful_login",
                    "wmi_persistence", "powershell_profile"
                )
            ],
        }

        return {
            "attacker_characteristics": characteristics,
            "attack_patterns": patterns,
            "threat_assessment": assessment,
        }

    # ==================================================================
    #  LLM 深度分析
    # ==================================================================

    async def _run_llm_analysis(
        self,
        threats: List[Dict],
        evidence: Dict,
        analysis_result: Dict,
        _progress: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """调用 LLM 对各维度进行深度分析"""
        llm_analysis = {}

        def _p(step, detail, percent):
            if _progress:
                _progress(step, detail, percent)

        # 1) 整体威胁分析
        try:
            _p("llm_threats", "LLM: 正在分析威胁数据...", 67)
            self.logger.info("  LLM: 分析威胁数据...")
            threats_json = json.dumps(threats[:30], ensure_ascii=False, indent=2)
            llm_analysis["threat_analysis"] = await self.llm.analyze_threats(threats_json)
        except Exception as e:
            self.logger.warning(f"  LLM 威胁分析失败: {e}")
            llm_analysis["threat_analysis"] = None

        # 2) 可疑进程分析
        mining = [t for t in threats if t.get("type") in ("mining_process", "suspicious_process", "high_cpu_process")]
        if mining:
            try:
                _p("llm_process", "LLM: 正在分析可疑进程...", 72)
                self.logger.info("  LLM: 分析可疑进程...")
                llm_analysis["process_analysis"] = await self.llm.analyze_process(
                    json.dumps(mining, ensure_ascii=False, indent=2)
                )
            except Exception as e:
                self.logger.warning(f"  LLM 进程分析失败: {e}")

        # 3) 恶意计划任务分析
        crons = [t for t in threats if t.get("type") == "malicious_cron"]
        if crons:
            try:
                _p("llm_cron", "LLM: 正在分析恶意计划任务...", 76)
                self.logger.info("  LLM: 分析恶意计划任务...")
                llm_analysis["cron_analysis"] = await self.llm.analyze_cron_entry(
                    json.dumps(crons, ensure_ascii=False, indent=2)
                )
            except Exception as e:
                self.logger.warning(f"  LLM 计划任务分析失败: {e}")

        # 4) 登录活动分析
        logins = [t for t in threats if t.get("type") in ("successful_login", "failed_login_bruteforce")]
        if logins:
            try:
                _p("llm_login", "LLM: 正在分析登录活动...", 80)
                self.logger.info("  LLM: 分析登录活动...")
                llm_analysis["login_analysis"] = await self.llm.analyze_login_activity(
                    json.dumps(logins[:20], ensure_ascii=False, indent=2)
                )
            except Exception as e:
                self.logger.warning(f"  LLM 登录分析失败: {e}")

        # 5) 攻击链深度分析
        chain = analysis_result.get("attack_chain", {})
        profile = analysis_result.get("attacker_profile", {})
        if chain.get("timeline"):
            try:
                _p("llm_chain", "LLM: 正在进行攻击链深度还原...", 84)
                self.logger.info("  LLM: 攻击链深度还原...")
                llm_analysis["chain_analysis"] = await self.llm.analyze_attack_chain(
                    json.dumps(chain.get("timeline", [])[:20], ensure_ascii=False, indent=2),
                    json.dumps(profile, ensure_ascii=False, indent=2),
                )
            except Exception as e:
                self.logger.warning(f"  LLM 攻击链分析失败: {e}")

        return llm_analysis


__all__ = ["EvidenceAnalyzer"]
