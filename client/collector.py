"""
轻量级终端取证采集器

在受害终端上运行，收集安全相关信息并打包为 JSON 证据包。
零依赖设计：仅使用 Python 标准库，无需 pip install。
跨平台支持：自动识别 Linux / Windows 系统并使用对应采集策略。

用法：
    python -m client.collector                # 采集并保存到本地文件
    python -m client.collector --upload http://server:8080   # 采集并上传到分析服务端
    python -m client.collector --output /tmp/evidence.json   # 指定输出路径
"""

import os
import re
import json
import socket
import hashlib
import platform
import subprocess
import logging
import argparse
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

# 仅在上传模式下需要 urllib（标准库，无需额外安装）
import urllib.request
import urllib.error

# Windows 专用模块（条件导入，标准库）
IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import winreg
    except ImportError:
        winreg = None


class ForensicCollector:
    """轻量级取证采集器 — 收集受害终端上的安全信息（支持 Linux / Windows）"""

    VERSION = "2.0.0"

    def __init__(self, log_lines: int = 500, verbose: bool = False):
        """
        Args:
            log_lines: 读取日志文件的尾部行数（Linux）/ 事件日志条数（Windows）
            verbose: 是否输出详细日志
        """
        self.log_lines = log_lines
        self.is_windows = IS_WINDOWS
        self.logger = logging.getLogger("collector")
        if verbose:
            logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
        else:
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

        # 证据容器
        self.evidence: Dict[str, Any] = {
            "collector_version": self.VERSION,
            "collection_time": None,
            "platform": "windows" if self.is_windows else "linux",
            "host_info": {},
            "accounts": {},
            "processes": {},
            "network": {},
            "cron_jobs": {},           # Linux: cron / Windows: scheduled tasks
            "log_analysis": {},
            "file_indicators": {},
            "windows_specific": {},     # Windows 专有数据
            "summary": {},
        }

    # ==================================================================
    #  对外接口
    # ==================================================================

    def collect_all(self) -> Dict[str, Any]:
        """执行完整采集，返回证据字典"""
        start = datetime.now()
        self.evidence["collection_time"] = start.isoformat()

        os_name = "Windows" if self.is_windows else "Linux"
        self.logger.info(f"===== 开始取证采集（{os_name}）=====")

        self.logger.info("[1/9] 采集主机基础信息...")
        self.evidence["host_info"] = self._collect_host_info()

        self.logger.info("[2/9] 采集用户账户信息...")
        self.evidence["accounts"] = self._collect_accounts()

        self.logger.info("[3/9] 采集进程信息...")
        self.evidence["processes"] = self._collect_processes()

        self.logger.info("[4/9] 采集网络连接信息...")
        self.evidence["network"] = self._collect_network()

        self.logger.info("[5/9] 采集计划任务...")
        self.evidence["cron_jobs"] = self._collect_cron_jobs()

        self.logger.info("[6/9] 采集系统日志...")
        self.evidence["log_analysis"] = self._collect_logs()

        self.logger.info("[7/9] 采集文件系统指标...")
        self.evidence["file_indicators"] = self._collect_file_indicators()

        if self.is_windows:
            self.logger.info("[8/9] 采集 Windows 专有安全信息...")
            self.evidence["windows_specific"] = self._collect_windows_specific()
        else:
            self.logger.info("[8/9] 跳过 Windows 专有采集（当前为 Linux）")

        self.logger.info("[9/9] 生成采集摘要...")
        elapsed = (datetime.now() - start).total_seconds()
        self.evidence["summary"] = self._generate_summary(elapsed)

        self.logger.info(f"===== 采集完成，耗时 {elapsed:.2f}s =====")
        return self.evidence

    def save_to_file(self, output_path: Optional[str] = None) -> str:
        """保存证据到 JSON 文件"""
        if output_path is None:
            hostname = self.evidence.get("host_info", {}).get("hostname", "unknown")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"evidence_{hostname}_{ts}.json"

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.evidence, f, ensure_ascii=False, indent=2)

        self.logger.info(f"证据已保存: {path.resolve()}")
        return str(path.resolve())

    def upload_to_server(self, server_url: str) -> Dict[str, Any]:
        """将证据上传到分析服务端"""
        url = server_url.rstrip("/") + "/api/v1/evidence"
        data = json.dumps(self.evidence, ensure_ascii=False).encode("utf-8")

        self.logger.info(f"正在上传证据到 {url} ({len(data)} bytes)...")

        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                self.logger.info(f"上传成功: task_id={resp_data.get('task_id', 'N/A')}")
                return resp_data
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            self.logger.error(f"上传失败 HTTP {e.code}: {body[:300]}")
            raise
        except urllib.error.URLError as e:
            self.logger.error(f"无法连接服务端: {e.reason}")
            raise

    # ==================================================================
    #  采集模块
    # ==================================================================

    def _collect_host_info(self) -> Dict[str, Any]:
        """采集主机基础信息（跨平台）"""
        if self.is_windows:
            return self._collect_host_info_windows()
        return self._collect_host_info_linux()

    def _collect_host_info_linux(self) -> Dict[str, Any]:
        """采集 Linux 主机基础信息"""
        info = {
            "hostname": self._cmd("hostname") or socket.gethostname(),
            "ip_addresses": self._get_ip_addresses(),
            "os_release": self._cmd("cat /etc/os-release 2>/dev/null") or platform.platform(),
            "kernel": self._cmd("uname -r") or platform.release(),
            "arch": platform.machine(),
            "uptime": self._cmd("uptime -p 2>/dev/null || uptime"),
            "current_time": datetime.now().isoformat(),
            "timezone": self._cmd("timedatectl 2>/dev/null | grep 'Time zone'") or "",
            "last_reboot": self._cmd("who -b 2>/dev/null") or "",
        }
        return info

    def _collect_host_info_windows(self) -> Dict[str, Any]:
        """采集 Windows 主机基础信息"""
        info = {
            "hostname": socket.gethostname(),
            "ip_addresses": self._get_ip_addresses(),
            "os_release": platform.platform(),
            "os_version": self._ps("(Get-CimInstance Win32_OperatingSystem).Caption"),
            "os_build": self._ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber"),
            "kernel": platform.version(),
            "arch": platform.machine(),
            "uptime": self._ps(
                "$os = Get-CimInstance Win32_OperatingSystem; "
                "(New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).ToString()"
            ),
            "current_time": datetime.now().isoformat(),
            "timezone": self._ps("[System.TimeZone]::CurrentTimeZone.StandardName"),
            "last_reboot": self._ps(
                "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')"
            ),
            "domain": self._ps("(Get-CimInstance Win32_ComputerSystem).Domain"),
            "is_domain_joined": self._ps(
                "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
            ),
        }
        return info

    def _collect_accounts(self) -> Dict[str, Any]:
        """采集用户账户信息（跨平台）"""
        if self.is_windows:
            return self._collect_accounts_windows()
        return self._collect_accounts_linux()

    def _collect_accounts_linux(self) -> Dict[str, Any]:
        """采集 Linux 用户账户信息"""
        accounts = {
            "passwd_entries": [],
            "shadow_accessible": False,
            "uid0_accounts": [],
            "login_shells": [],
            "recently_modified_users": [],
            "sudoers_info": "",
            "logged_in_users": "",
        }

        # /etc/passwd
        passwd = self._cmd("cat /etc/passwd 2>/dev/null")
        if passwd:
            for line in passwd.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split(":")
                if len(parts) >= 7:
                    entry = {
                        "username": parts[0],
                        "uid": parts[2],
                        "gid": parts[3],
                        "home": parts[5],
                        "shell": parts[6],
                    }
                    accounts["passwd_entries"].append(entry)

                    if parts[2] == "0" and parts[0] != "root":
                        accounts["uid0_accounts"].append(entry)

                    if parts[6] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                        accounts["login_shells"].append(entry)

        # /etc/shadow 可读性检测
        shadow_test = self._cmd("test -r /etc/shadow && echo readable || echo nope")
        accounts["shadow_accessible"] = shadow_test.strip() == "readable"

        # 最近修改的用户文件
        accounts["recently_modified_users"] = self._cmd(
            "find /home -maxdepth 2 -name '.bash_history' -mtime -7 -ls 2>/dev/null | head -20"
        )

        # sudoers
        accounts["sudoers_info"] = self._cmd("cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -30")

        # 当前登录用户
        accounts["logged_in_users"] = self._cmd("w 2>/dev/null || who 2>/dev/null")

        return accounts

    def _collect_accounts_windows(self) -> Dict[str, Any]:
        """采集 Windows 用户账户信息"""
        accounts = {
            "passwd_entries": [],
            "shadow_accessible": False,
            "uid0_accounts": [],        # Windows: 管理员组成员
            "login_shells": [],
            "recently_modified_users": [],
            "sudoers_info": "",
            "logged_in_users": "",
            # Windows 专有字段
            "local_users": "",
            "admin_group_members": "",
            "rdp_group_members": "",
            "disabled_accounts": "",
            "password_never_expires": "",
            "last_password_set": "",
        }

        # 本地用户列表
        users_raw = self._ps(
            "Get-LocalUser | Select-Object Name, Enabled, LastLogon, "
            "PasswordLastSet, PasswordExpires, Description | Format-List"
        )
        accounts["local_users"] = users_raw

        # 解析用户列表为 passwd_entries 兼容格式
        user_names = self._ps("(Get-LocalUser).Name -join ','")
        if user_names:
            for name in user_names.split(","):
                name = name.strip()
                if name:
                    accounts["passwd_entries"].append({
                        "username": name,
                        "uid": "N/A",
                        "gid": "N/A",
                        "home": f"C:\\Users\\{name}",
                        "shell": "N/A",
                    })

        # 管理员组成员（等同于 uid0_accounts）
        admin_members = self._ps(
            "try { (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop).Name -join ',' } "
            "catch { (Get-LocalGroupMember -Group (Get-LocalGroup | Where-Object {$_.SID -like 'S-1-5-32-544'}).Name).Name -join ',' }"
        )
        accounts["admin_group_members"] = admin_members
        if admin_members:
            for member in admin_members.split(","):
                member = member.strip()
                if member:
                    accounts["uid0_accounts"].append({
                        "username": member,
                        "uid": "0 (Administrator)",
                        "gid": "544",
                        "home": "",
                        "shell": "",
                    })

        # RDP 远程桌面用户组
        accounts["rdp_group_members"] = self._ps(
            "try { (Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop).Name -join ',' } catch { '' }"
        )

        # 禁用的账户
        accounts["disabled_accounts"] = self._ps(
            "(Get-LocalUser | Where-Object {$_.Enabled -eq $false}).Name -join ','"
        )

        # 密码永不过期的账户
        accounts["password_never_expires"] = self._ps(
            "(Get-LocalUser | Where-Object {$_.PasswordExpires -eq $null -and $_.Enabled -eq $true}).Name -join ','"
        )

        # 当前登录用户
        accounts["logged_in_users"] = self._cmd("query user 2>nul") or self._ps(
            "(Get-CimInstance Win32_LogonSession | "
            "Where-Object {$_.LogonType -eq 2 -or $_.LogonType -eq 10}).LogonId -join ','"
        )

        return accounts

    def _collect_processes(self) -> Dict[str, Any]:
        """采集进程信息（跨平台）"""
        if self.is_windows:
            return self._collect_processes_windows()
        return self._collect_processes_linux()

    def _collect_processes_linux(self) -> Dict[str, Any]:
        """采集 Linux 进程信息"""
        processes = {
            "top_cpu": [],
            "top_memory": [],
            "all_processes_raw": "",
            "suspicious_indicators": [],
        }

        # 全量进程快照
        ps_all = self._cmd("ps auxww --sort=-%cpu 2>/dev/null | head -100")
        processes["all_processes_raw"] = ps_all

        if ps_all:
            lines = [l.strip() for l in ps_all.split("\n")[1:] if l.strip()]
            for line in lines:
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue
                try:
                    proc = {
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": float(parts[2]),
                        "mem": float(parts[3]),
                        "vsz": parts[4],
                        "rss": parts[5],
                        "stat": parts[7],
                        "start": parts[8],
                        "time": parts[9],
                        "command": parts[10],
                    }
                    if proc["cpu"] > 0.1:
                        processes["top_cpu"].append(proc)
                    if proc["mem"] > 1.0:
                        processes["top_memory"].append(proc)

                    # 标记可疑进程指标
                    cmd_lower = proc["command"].lower()
                    suspicious_keywords = [
                        "xmrig", "minerd", "cpuminer", "ethminer", "cgminer",
                        "stratum", "pool.", "nohup", "/tmp/", "/dev/shm/",
                        "nc -e", "nc -l", "mkfifo", "base64",
                        ".hidden", "kworkerds", "kdevtmpfs",
                    ]
                    for kw in suspicious_keywords:
                        if kw in cmd_lower:
                            processes["suspicious_indicators"].append({
                                "pid": proc["pid"],
                                "keyword": kw,
                                "command": proc["command"][:200],
                                "cpu": proc["cpu"],
                                "user": proc["user"],
                            })
                except (ValueError, IndexError):
                    continue

        # 限制 top_cpu/top_memory 各 30 条
        processes["top_cpu"] = sorted(processes["top_cpu"], key=lambda x: x["cpu"], reverse=True)[:30]
        processes["top_memory"] = sorted(processes["top_memory"], key=lambda x: x["mem"], reverse=True)[:30]

        return processes

    def _collect_processes_windows(self) -> Dict[str, Any]:
        """采集 Windows 进程信息"""
        processes = {
            "top_cpu": [],
            "top_memory": [],
            "all_processes_raw": "",
            "suspicious_indicators": [],
        }

        # 全量进程快照（PowerShell JSON 输出）
        ps_json = self._ps(
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First 100 "
            "Id, ProcessName, CPU, @{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, "
            "Path, @{N='CmdLine';E={(Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\").CommandLine}} "
            "| ConvertTo-Json -Depth 2"
        )
        processes["all_processes_raw"] = ps_json

        try:
            proc_list = json.loads(ps_json) if ps_json else []
            if isinstance(proc_list, dict):
                proc_list = [proc_list]  # 单个进程时 PS 返回 dict 而非 list
        except (json.JSONDecodeError, ValueError):
            proc_list = []

        # Windows 可疑进程关键词
        win_suspicious_keywords = [
            "xmrig", "minerd", "cpuminer", "ethminer", "cgminer",
            "stratum", "pool.", "mimikatz", "lazagne", "procdump",
            "psexec", "cobalt", "beacon", "meterpreter", "nc.exe",
            "ncat", "powercat", "certutil", "bitsadmin",
            "regsvr32", "mshta", "wscript", "cscript",
            "\\temp\\", "\\tmp\\", "appdata\\local\\temp",
        ]

        for p in proc_list:
            try:
                pid = str(p.get("Id", ""))
                name = p.get("ProcessName", "")
                cpu = float(p.get("CPU", 0) or 0)
                mem_mb = float(p.get("MemMB", 0) or 0)
                cmd_line = p.get("CmdLine", "") or p.get("Path", "") or name
                exe_path = p.get("Path", "") or ""

                proc_entry = {
                    "user": "N/A",
                    "pid": pid,
                    "cpu": round(cpu, 1),
                    "mem": mem_mb,
                    "vsz": "N/A",
                    "rss": f"{mem_mb}MB",
                    "stat": "N/A",
                    "start": "N/A",
                    "time": "N/A",
                    "command": cmd_line[:200] if cmd_line else name,
                    "process_name": name,
                    "exe_path": exe_path,
                }

                if cpu > 0.1:
                    processes["top_cpu"].append(proc_entry)
                if mem_mb > 50:
                    processes["top_memory"].append(proc_entry)

                # 可疑进程检测
                check_str = f"{name} {cmd_line} {exe_path}".lower()
                for kw in win_suspicious_keywords:
                    if kw in check_str:
                        processes["suspicious_indicators"].append({
                            "pid": pid,
                            "keyword": kw,
                            "command": cmd_line[:200] if cmd_line else name,
                            "cpu": round(cpu, 1),
                            "user": "N/A",
                            "process_name": name,
                            "exe_path": exe_path,
                        })
                        break  # 每个进程只记录第一个匹配

            except (ValueError, TypeError, KeyError):
                continue

        processes["top_cpu"] = sorted(processes["top_cpu"], key=lambda x: x["cpu"], reverse=True)[:30]
        processes["top_memory"] = sorted(processes["top_memory"], key=lambda x: x["mem"], reverse=True)[:30]

        return processes

    def _collect_network(self) -> Dict[str, Any]:
        """采集网络信息（跨平台）"""
        if self.is_windows:
            return self._collect_network_windows()
        return self._collect_network_linux()

    def _collect_network_linux(self) -> Dict[str, Any]:
        """采集 Linux 网络信息"""
        network = {
            "listening_ports": "",
            "established_connections": "",
            "all_connections_raw": "",
            "iptables_rules": "",
            "routing_table": "",
            "dns_config": "",
            "suspicious_ports": [],
        }

        network["all_connections_raw"] = self._cmd("ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null")
        network["listening_ports"] = self._cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        network["established_connections"] = self._cmd("ss -tnp state established 2>/dev/null | head -50")
        network["iptables_rules"] = self._cmd("iptables -L -n 2>/dev/null | head -50")
        network["routing_table"] = self._cmd("ip route 2>/dev/null || route -n 2>/dev/null")
        network["dns_config"] = self._cmd("cat /etc/resolv.conf 2>/dev/null")

        suspicious_ports = [4444, 5555, 6666, 31337, 1337, 9999, 12345, 65535]
        conn_raw = network["all_connections_raw"]
        for port in suspicious_ports:
            if f":{port} " in conn_raw or f":{port}\t" in conn_raw or f":{port}\n" in conn_raw:
                network["suspicious_ports"].append(port)

        return network

    def _collect_network_windows(self) -> Dict[str, Any]:
        """采集 Windows 网络信息"""
        network = {
            "listening_ports": "",
            "established_connections": "",
            "all_connections_raw": "",
            "iptables_rules": "",      # Windows: 防火墙规则
            "routing_table": "",
            "dns_config": "",
            "suspicious_ports": [],
            # Windows 额外字段
            "shares": "",
            "arp_table": "",
        }

        # 网络连接（netstat 在 Windows 上也可用）
        network["all_connections_raw"] = self._cmd("netstat -ano")
        network["listening_ports"] = self._cmd("netstat -ano | findstr LISTENING")
        network["established_connections"] = self._cmd("netstat -ano | findstr ESTABLISHED")

        # Windows 防火墙规则
        network["iptables_rules"] = self._ps(
            "Get-NetFirewallRule -Enabled True -Direction Inbound | "
            "Select-Object -First 30 DisplayName, Action, Profile | Format-Table -AutoSize | Out-String"
        )

        # 路由表
        network["routing_table"] = self._cmd("route print")

        # DNS 配置
        network["dns_config"] = self._ps(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Where-Object {$_.ServerAddresses} | "
            "Select-Object InterfaceAlias, ServerAddresses | Format-List | Out-String"
        )

        # 网络共享
        network["shares"] = self._cmd("net share")

        # ARP 表
        network["arp_table"] = self._cmd("arp -a")

        # 可疑端口检测
        suspicious_ports = [4444, 5555, 6666, 31337, 1337, 9999, 12345, 65535]
        conn_raw = network["all_connections_raw"]
        for port in suspicious_ports:
            if f":{port} " in conn_raw or f":{port}\t" in conn_raw or f":{port}\n" in conn_raw:
                network["suspicious_ports"].append(port)

        return network

    def _collect_cron_jobs(self) -> Dict[str, Any]:
        """采集计划任务（跨平台）"""
        if self.is_windows:
            return self._collect_scheduled_tasks_windows()
        return self._collect_cron_jobs_linux()

    def _collect_cron_jobs_linux(self) -> Dict[str, Any]:
        """采集 Linux 计划任务"""
        cron = {
            "system_crontab": "",
            "user_crontabs": "",
            "cron_d_listing": "",
            "cron_d_contents": {},
            "anacrontab": "",
            "at_jobs": "",
            "systemd_timers": "",
        }

        cron["system_crontab"] = self._cmd("cat /etc/crontab 2>/dev/null")
        cron["user_crontabs"] = self._cmd("cat /var/spool/cron/crontabs/* 2>/dev/null; cat /var/spool/cron/* 2>/dev/null")
        cron["cron_d_listing"] = self._cmd("ls -la /etc/cron.d/ 2>/dev/null")
        cron["anacrontab"] = self._cmd("cat /etc/anacrontab 2>/dev/null")
        cron["at_jobs"] = self._cmd("atq 2>/dev/null")
        cron["systemd_timers"] = self._cmd("systemctl list-timers --all --no-pager 2>/dev/null | head -30")

        cron_d_list = self._cmd("ls /etc/cron.d/ 2>/dev/null")
        if cron_d_list:
            for fname in cron_d_list.strip().split("\n"):
                fname = fname.strip()
                if fname:
                    content = self._cmd(f"cat /etc/cron.d/{fname} 2>/dev/null")
                    if content:
                        cron["cron_d_contents"][fname] = content

        return cron

    def _collect_scheduled_tasks_windows(self) -> Dict[str, Any]:
        """采集 Windows 计划任务"""
        tasks = {
            "system_crontab": "",      # 兼容字段：存放 schtasks 汇总
            "user_crontabs": "",
            "cron_d_listing": "",
            "cron_d_contents": {},
            "anacrontab": "",
            "at_jobs": "",
            "systemd_timers": "",
            # Windows 专有字段
            "scheduled_tasks_detail": "",
            "startup_programs": "",
        }

        # 计划任务列表（schtasks 可在任何 Windows 上运行）
        tasks["system_crontab"] = self._cmd("schtasks /query /fo LIST /v 2>nul")

        # PowerShell 获取更详细的计划任务信息
        tasks["scheduled_tasks_detail"] = self._ps(
            "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
            "Select-Object -First 50 TaskName, TaskPath, State, "
            "@{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join '; '}} "
            "| Format-List | Out-String"
        )

        # 启动项（注册表 Run 键）
        tasks["startup_programs"] = self._ps(
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
            "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
            "); foreach ($p in $paths) { if (Test-Path $p) { "
            "Write-Output \"=== $p ===\"; Get-ItemProperty $p | Format-List | Out-String } }"
        )

        return tasks

    def _collect_logs(self) -> Dict[str, Any]:
        """采集系统日志（跨平台）"""
        if self.is_windows:
            return self._collect_logs_windows()
        return self._collect_logs_linux()

    def _collect_logs_linux(self) -> Dict[str, Any]:
        """采集 Linux 系统日志"""
        logs = {
            "auth_log": "",
            "secure_log": "",
            "syslog": "",
            "messages": "",
            "kern_log": "",
            "last_logins": "",
            "last_failed": "",
            "journal_recent": "",
            "dmesg_recent": "",
        }

        log_files = {
            "auth_log": "/var/log/auth.log",
            "secure_log": "/var/log/secure",
            "syslog": "/var/log/syslog",
            "messages": "/var/log/messages",
            "kern_log": "/var/log/kern.log",
        }

        for key, path in log_files.items():
            logs[key] = self._cmd(f"tail -n {self.log_lines} {path} 2>/dev/null")

        logs["last_logins"] = self._cmd("last -n 50 2>/dev/null")
        logs["last_failed"] = self._cmd("lastb -n 50 2>/dev/null")
        logs["journal_recent"] = self._cmd("journalctl --since '24 hours ago' --no-pager -n 200 2>/dev/null")
        logs["dmesg_recent"] = self._cmd("dmesg --time-format iso 2>/dev/null | tail -50 || dmesg | tail -50")

        return logs

    def _collect_logs_windows(self) -> Dict[str, Any]:
        """采集 Windows 事件日志"""
        max_events = min(self.log_lines, 200)
        logs = {
            "auth_log": "",       # 兼容字段：存放安全登录事件
            "secure_log": "",
            "syslog": "",         # 兼容字段：存放系统事件
            "messages": "",
            "kern_log": "",
            "last_logins": "",
            "last_failed": "",
            "journal_recent": "",
            "dmesg_recent": "",
            # Windows 专有字段
            "security_events": "",
            "system_events": "",
            "application_events": "",
            "powershell_events": "",
        }

        # 安全日志 - 登录成功事件（EventID 4624）
        logs["auth_log"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"ForEach-Object {{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' ' + $_.Message.Split([Environment]::NewLine)[0] }} "
            f"| Out-String",
            timeout=30
        )

        # 安全日志 - 登录失败事件（EventID 4625）
        logs["last_failed"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4625}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"ForEach-Object {{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' ' + $_.Message.Split([Environment]::NewLine)[0] }} "
            f"| Out-String",
            timeout=30
        )

        # 安全日志 - 更详细的安全事件（包含提权、账户变更等）
        logs["security_events"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624,4625,4648,4672,4720,4722,4723,4724,4725,4726,4738,4740}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, "
            f"@{{N='Msg';E={{$_.Message.Split([Environment]::NewLine)[0].Substring(0, [Math]::Min(150, $_.Message.Split([Environment]::NewLine)[0].Length))}}}} "
            f"| Format-Table -AutoSize | Out-String",
            timeout=30
        )

        # 系统事件日志
        logs["system_events"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='System';Level=1,2,3}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, "
            f"@{{N='Msg';E={{$_.Message.Split([Environment]::NewLine)[0].Substring(0, [Math]::Min(120, $_.Message.Split([Environment]::NewLine)[0].Length))}}}} "
            f"| Format-Table -AutoSize | Out-String",
            timeout=30
        )
        logs["syslog"] = logs["system_events"]

        # 应用程序事件日志
        logs["application_events"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Application';Level=1,2,3}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, "
            f"@{{N='Msg';E={{$_.Message.Split([Environment]::NewLine)[0].Substring(0, [Math]::Min(120, $_.Message.Split([Environment]::NewLine)[0].Length))}}}} "
            f"| Format-Table -AutoSize | Out-String",
            timeout=30
        )

        # PowerShell 脚本块日志（EventID 4104）—— 攻击者常用
        logs["powershell_events"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104}} "
            f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
            f"ForEach-Object {{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' | ' + "
            f"$_.Properties[2].Value.Substring(0, [Math]::Min(200, $_.Properties[2].Value.Length)) }} "
            f"| Out-String",
            timeout=30
        )

        # 最近登录用户
        logs["last_logins"] = self._ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624}} "
            f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
            f"ForEach-Object {{ "
            f"$xml = [xml]$_.ToXml(); "
            f"$data = $xml.Event.EventData.Data; "
            f"$logonType = ($data | Where-Object {{$_.Name -eq 'LogonType'}}).'#text'; "
            f"$user = ($data | Where-Object {{$_.Name -eq 'TargetUserName'}}).'#text'; "
            f"$ip = ($data | Where-Object {{$_.Name -eq 'IpAddress'}}).'#text'; "
            f"if ($logonType -in @('2','3','10','11')) {{ "
            f"'Accepted logon for ' + $user + ' from ' + $ip + ' LogonType=' + $logonType "
            f"}} }} | Out-String",
            timeout=30
        )

        return logs

    def _collect_file_indicators(self) -> Dict[str, Any]:
        """采集文件系统安全指标（跨平台）"""
        if self.is_windows:
            return self._collect_file_indicators_windows()
        return self._collect_file_indicators_linux()

    def _collect_file_indicators_linux(self) -> Dict[str, Any]:
        """采集 Linux 文件系统安全指标"""
        indicators = {
            "tmp_executables": "",
            "devshm_files": "",
            "suid_files": "",
            "world_writable_files": "",
            "recently_modified_etc": "",
            "hidden_in_tmp": "",
            "authorized_keys": "",
            "ssh_config": "",
            "hosts_file": "",
            "environment_files": "",
        }

        indicators["tmp_executables"] = self._cmd("find /tmp -type f -executable -ls 2>/dev/null | head -30")
        indicators["devshm_files"] = self._cmd("ls -la /dev/shm/ 2>/dev/null")
        indicators["suid_files"] = self._cmd("find / -perm -4000 -type f -ls 2>/dev/null | head -30")
        indicators["recently_modified_etc"] = self._cmd(
            "find /etc -type f -mtime -7 -ls 2>/dev/null | head -30"
        )
        indicators["hidden_in_tmp"] = self._cmd("find /tmp -name '.*' -ls 2>/dev/null | head -20")
        indicators["authorized_keys"] = self._cmd(
            "find /root /home -name authorized_keys -ls 2>/dev/null; "
            "cat /root/.ssh/authorized_keys 2>/dev/null | head -20"
        )
        indicators["ssh_config"] = self._cmd("cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'")
        indicators["hosts_file"] = self._cmd("cat /etc/hosts 2>/dev/null")
        indicators["environment_files"] = self._cmd(
            "cat /etc/environment 2>/dev/null; cat /etc/profile.d/*.sh 2>/dev/null | head -50"
        )

        return indicators

    def _collect_file_indicators_windows(self) -> Dict[str, Any]:
        """采集 Windows 文件系统安全指标"""
        indicators = {
            "tmp_executables": "",
            "devshm_files": "",          # Windows 无此概念，留空
            "suid_files": "",            # Windows 无此概念，留空
            "world_writable_files": "",
            "recently_modified_etc": "",
            "hidden_in_tmp": "",
            "authorized_keys": "",
            "ssh_config": "",
            "hosts_file": "",
            "environment_files": "",
            # Windows 专有字段
            "temp_executables": "",
            "recent_exe_in_downloads": "",
            "alternate_data_streams": "",
        }

        # Temp 目录可执行文件
        temp_dir = os.environ.get("TEMP", "C:\\Windows\\Temp")
        indicators["tmp_executables"] = self._ps(
            f"Get-ChildItem -Path '{temp_dir}', 'C:\\Windows\\Temp' -Recurse -Include *.exe,*.bat,*.ps1,*.vbs,*.cmd,*.scr "
            f"-ErrorAction SilentlyContinue | Select-Object -First 30 FullName, Length, LastWriteTime "
            f"| Format-Table -AutoSize | Out-String"
        )
        indicators["temp_executables"] = indicators["tmp_executables"]

        # Downloads 目录最近的可执行文件
        indicators["recent_exe_in_downloads"] = self._ps(
            "Get-ChildItem -Path $env:USERPROFILE\\Downloads -Recurse -Include *.exe,*.msi,*.bat,*.ps1,*.vbs "
            "-ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} "
            "| Select-Object -First 20 FullName, Length, LastWriteTime "
            "| Format-Table -AutoSize | Out-String"
        )

        # hosts 文件
        indicators["hosts_file"] = self._cmd("type C:\\Windows\\System32\\drivers\\etc\\hosts 2>nul")

        # SSH 配置（Windows 10+ 内置 OpenSSH）
        indicators["ssh_config"] = self._ps(
            "if (Test-Path $env:ProgramData\\ssh\\sshd_config) { "
            "Get-Content $env:ProgramData\\ssh\\sshd_config | Where-Object {$_ -notmatch '^\\s*#' -and $_ -match '\\S'} "
            "| Out-String } else { 'OpenSSH Server not installed' }"
        )
        indicators["authorized_keys"] = self._ps(
            "$paths = @("
            "\"$env:USERPROFILE\\.ssh\\authorized_keys\", "
            "\"$env:ProgramData\\ssh\\administrators_authorized_keys\""
            "); foreach ($p in $paths) { if (Test-Path $p) { Write-Output \"=== $p ===\"; Get-Content $p | Select-Object -First 20 } }"
        )

        # 环境变量
        indicators["environment_files"] = self._ps(
            "Get-ChildItem Env: | Format-Table Name, Value -AutoSize | Out-String"
        )

        # Alternate Data Streams（NTFS ADS，常被恶意软件利用隐藏数据）
        indicators["alternate_data_streams"] = self._ps(
            f"Get-ChildItem -Path '{temp_dir}' -Recurse -ErrorAction SilentlyContinue | "
            f"ForEach-Object {{ Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue }} | "
            f"Where-Object {{ $_.Stream -ne ':$DATA' }} | Select-Object -First 20 FileName, Stream, Length "
            f"| Format-Table -AutoSize | Out-String"
        )

        return indicators

    # ==================================================================
    #  Windows 专有采集
    # ==================================================================

    def _collect_windows_specific(self) -> Dict[str, Any]:
        """采集 Windows 专有安全信息"""
        win = {
            "services": "",
            "drivers_unsigned": "",
            "installed_software": "",
            "rdp_settings": "",
            "audit_policy": "",
            "antivirus_status": "",
            "uac_settings": "",
            "smb_config": "",
            "wmi_subscriptions": "",
            "powershell_profile": "",
            "bits_jobs": "",
        }

        # 可疑服务（非 Microsoft 签名的自动启动服务）
        win["services"] = self._ps(
            "Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.State -eq 'Running'} | "
            "Select-Object -First 50 Name, DisplayName, PathName, StartMode, State "
            "| Format-Table -AutoSize | Out-String"
        )

        # 已安装软件
        win["installed_software"] = self._ps(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Where-Object {$_.DisplayName} | Select-Object -First 50 DisplayName, Publisher, InstallDate, DisplayVersion "
            "| Sort-Object InstallDate -Descending | Format-Table -AutoSize | Out-String"
        )

        # RDP 配置
        win["rdp_settings"] = self._ps(
            "$rdp = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue; "
            "\"fDenyTSConnections = $($rdp.fDenyTSConnections)\"; "
            "$nla = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue; "
            "\"UserAuthentication (NLA) = $($nla.UserAuthentication)\"; "
            "\"PortNumber = $($nla.PortNumber)\""
        )

        # 审计策略
        win["audit_policy"] = self._cmd("auditpol /get /category:* 2>nul")

        # 防病毒状态
        win["antivirus_status"] = self._ps(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | "
            "Select-Object displayName, productState, pathToSignedProductExe | Format-List | Out-String"
        )

        # UAC 设置
        win["uac_settings"] = self._ps(
            "$uac = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue; "
            "\"EnableLUA = $($uac.EnableLUA)\"; "
            "\"ConsentPromptBehaviorAdmin = $($uac.ConsentPromptBehaviorAdmin)\"; "
            "\"ConsentPromptBehaviorUser = $($uac.ConsentPromptBehaviorUser)\""
        )

        # SMB 配置
        win["smb_config"] = self._ps(
            "Get-SmbServerConfiguration -ErrorAction SilentlyContinue | "
            "Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RequireSecuritySignature "
            "| Format-List | Out-String"
        )

        # WMI 事件订阅（持久化机制）
        win["wmi_subscriptions"] = self._ps(
            "Get-WMIObject -Namespace root\\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | "
            "Select-Object Name, Query | Format-List | Out-String; "
            "Get-WMIObject -Namespace root\\Subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | "
            "Select-Object Name, CommandLineTemplate | Format-List | Out-String"
        )

        # PowerShell Profile 检查（可被植入恶意代码）
        win["powershell_profile"] = self._ps(
            "$profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, "
            "$PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost); "
            "foreach ($p in $profiles) { if (Test-Path $p) { "
            "Write-Output \"=== $p ===\"; Get-Content $p | Select-Object -First 20 | Out-String } }"
        )

        # BITS 传输任务（可被恶意利用）
        win["bits_jobs"] = self._ps(
            "Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | "
            "Select-Object DisplayName, TransferType, JobState, FileList | Format-List | Out-String"
        )

        return win

    # ==================================================================
    #  辅助方法
    # ==================================================================

    def _decode_output(self, raw: bytes) -> str:
        """安全解码子进程输出（处理 Windows GBK / Linux UTF-8 混合编码）"""
        if not raw:
            return ""
        # 优先 UTF-8，失败后尝试 GBK（Windows 中文系统默认编码），最终 latin-1 兜底
        for encoding in ("utf-8", "gbk", "latin-1"):
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")

    def _cmd(self, command: str, timeout: int = 15) -> str:
        """安全执行 shell 命令"""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, timeout=timeout
            )
            return self._decode_output(result.stdout).strip()
        except subprocess.TimeoutExpired:
            self.logger.debug(f"命令超时: {command[:60]}")
            return ""
        except Exception as e:
            self.logger.debug(f"命令失败: {command[:60]} -> {e}")
            return ""

    def _ps(self, script: str, timeout: int = 20) -> str:
        """安全执行 PowerShell 命令（Windows 专用）"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, timeout=timeout
            )
            return self._decode_output(result.stdout).strip()
        except subprocess.TimeoutExpired:
            self.logger.debug(f"PowerShell 超时: {script[:60]}")
            return ""
        except FileNotFoundError:
            self.logger.debug("PowerShell 不可用")
            return ""
        except Exception as e:
            self.logger.debug(f"PowerShell 失败: {script[:60]} -> {e}")
            return ""

    def _get_ip_addresses(self) -> List[str]:
        """获取本机 IP 列表（跨平台）"""
        ips = []

        if self.is_windows:
            # Windows: 使用 PowerShell 获取 IP
            output = self._ps(
                "(Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object {$_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown'}).IPAddress -join ','"
            )
            if output:
                ips = [ip.strip() for ip in output.split(",") if ip.strip()]
            # 备选：ipconfig
            if not ips:
                output = self._cmd("ipconfig")
                for match in re.finditer(r'IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)', output):
                    ip = match.group(1)
                    if ip != "127.0.0.1":
                        ips.append(ip)
        else:
            # Linux
            try:
                output = self._cmd("ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null")
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output):
                    ip = match.group(1)
                    if ip != "127.0.0.1":
                        ips.append(ip)
            except Exception:
                pass

        if not ips:
            try:
                ips.append(socket.gethostbyname(socket.gethostname()))
            except Exception:
                pass
        return ips

    def _generate_summary(self, elapsed: float) -> Dict[str, Any]:
        """生成采集摘要"""
        accounts = self.evidence.get("accounts", {})
        processes = self.evidence.get("processes", {})
        network = self.evidence.get("network", {})

        summary = {
            "platform": self.evidence.get("platform", "unknown"),
            "collection_duration_seconds": round(elapsed, 2),
            "total_accounts": len(accounts.get("passwd_entries", [])),
            "uid0_accounts": len(accounts.get("uid0_accounts", [])),
            "login_shell_accounts": len(accounts.get("login_shells", [])),
            "total_processes_collected": len(processes.get("top_cpu", [])),
            "suspicious_process_indicators": len(processes.get("suspicious_indicators", [])),
            "suspicious_ports_found": len(network.get("suspicious_ports", [])),
            "evidence_hash": "",  # 后面计算
        }

        # Windows 额外统计
        if self.is_windows:
            summary["admin_accounts"] = len(accounts.get("uid0_accounts", []))

        return summary


# ==================================================================
#  CLI 入口
# ==================================================================

def main():
    parser = argparse.ArgumentParser(
        description="应急响应客户端 - 轻量级取证采集器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m client.collector                          # 采集并保存到当前目录
  python -m client.collector -o /tmp/evidence.json    # 指定输出路径
  python -m client.collector -u http://10.0.0.1:8080  # 采集并上传到服务端
  python -m client.collector -u http://10.0.0.1:8080 --save  # 上传并保存本地副本
        """,
    )
    parser.add_argument("-o", "--output", help="证据输出文件路径")
    parser.add_argument("-u", "--upload", metavar="URL", help="分析服务端地址（如 http://10.0.0.1:8080）")
    parser.add_argument("--save", action="store_true", help="上传模式下同时保存本地副本")
    parser.add_argument("-n", "--log-lines", type=int, default=500, help="日志采集行数（默认 500）")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  应急响应客户端 - 轻量级取证采集器 v2.0")
    print(f"  平台: {platform.system()} {platform.release()}")
    print("=" * 60 + "\n")

    collector = ForensicCollector(log_lines=args.log_lines, verbose=args.verbose)
    evidence = collector.collect_all()

    # 计算证据哈希
    evidence_json = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    evidence["summary"]["evidence_hash"] = hashlib.sha256(evidence_json.encode()).hexdigest()[:16]

    # 保存或上传
    if args.upload:
        try:
            resp = collector.upload_to_server(args.upload)
            print(f"\n[OK] 证据已上传到服务端")
            print(f"     Task ID: {resp.get('task_id', 'N/A')}")
            print(f"     Status:  {resp.get('status', 'N/A')}")
        except Exception as e:
            print(f"\n[ERROR] 上传失败: {e}")
            print("        正在保存本地副本...")
            args.save = True

        if args.save:
            path = collector.save_to_file(args.output)
            print(f"     本地副本: {path}")
    else:
        path = collector.save_to_file(args.output)
        print(f"\n[OK] 证据已保存: {path}")

    # 打印摘要
    s = evidence["summary"]
    print(f"\n{'─' * 40}")
    print(f"  采集耗时:     {s['collection_duration_seconds']}s")
    print(f"  账户总数:     {s['total_accounts']}")
    print(f"  UID=0 账户:   {s['uid0_accounts']}")
    print(f"  可疑进程指标: {s['suspicious_process_indicators']}")
    print(f"  可疑端口:     {s['suspicious_ports_found']}")
    print(f"  证据哈希:     {s['evidence_hash']}")
    print(f"{'─' * 40}\n")


if __name__ == "__main__":
    main()
