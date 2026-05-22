"""
服务端报告构建器 — 基于证据分析结果生成 Markdown 应急响应报告

支持：
    - LLM 深度分析模式（调用 LLM 生成综合分析）
    - 本地规则模式（无 LLM 时的纯数据报告）
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from server.llm_client import LLMClient


class ServerReportBuilder:
    """服务端报告构建器"""

    # 严重程度中文映射
    SEVERITY_CN = {
        "critical": "严重",
        "high": "高危",
        "medium": "中等",
        "low": "低危",
    }

    # 威胁类型中文映射
    THREAT_TYPE_CN = {
        "shadow_account": "影子账户",
        "mining_process": "挖矿进程",
        "suspicious_process": "可疑进程",
        "high_cpu_process": "高 CPU 进程",
        "malicious_cron": "恶意计划任务",
        "suspicious_connection": "可疑网络连接",
        "successful_login": "登录记录",
        "failed_login_bruteforce": "暴力破解",
        "privilege_escalation": "权限提升",
        "service_activity": "服务变更",
        "suspicious_file": "可疑文件",
        "rdp_enabled": "RDP 已启用",
        "rdp_nla_disabled": "RDP NLA 未启用",
        "uac_disabled": "UAC 已禁用",
        "smb1_enabled": "SMBv1 已启用",
        "password_never_expires": "密码永不过期",
        "wmi_persistence": "WMI 持久化",
        "malicious_powershell": "恶意 PowerShell",
        "ntfs_ads": "NTFS 替代数据流",
        "bits_job": "BITS 传输任务",
        "powershell_profile": "PowerShell Profile 篡改",
    }

    # 攻击阶段中文映射（MITRE ATT&CK 阶段名保留英文，增加中文注释）
    PHASE_CN = {
        "Initial Access": "初始访问",
        "Execution": "执行",
        "Persistence": "持久化",
        "Privilege Escalation": "权限提升",
        "Defense Evasion": "防御规避",
        "Credential Access": "凭据访问",
        "Discovery": "侦察发现",
        "Lateral Movement": "横向移动",
        "Command and Control": "命令控制",
        "Impact": "影响破坏",
        "Unknown": "未知",
    }

    # 攻击复杂度中文映射
    SOPHISTICATION_CN = {
        "advanced": "高级",
        "basic": "基础",
    }

    # 优先级中文映射
    PRIORITY_CN = {
        "CRITICAL": "紧急",
        "HIGH": "高",
        "MEDIUM": "中",
        "LOW": "低",
    }

    # details 字段名中文映射
    DETAIL_KEY_CN = {
        "username": "用户名",
        "source_ip": "来源 IP",
        "method": "方式",
        "logon_type": "登录类型",
        "pid": "进程 ID",
        "keyword": "关键字",
        "command": "命令",
        "cpu": "CPU 占用",
        "port": "端口",
        "matched_pattern": "匹配模式",
        "matched_text": "匹配内容",
        "count": "数量",
        "files": "文件列表",
        "pattern": "模式",
        "original_user": "原始用户",
        "target_user": "目标用户",
        "is_suspicious": "是否可疑",
        "service_name": "服务名",
        "activity": "活动",
        "rdp_settings": "RDP 配置",
        "uac_settings": "UAC 配置",
        "smb_config": "SMB 配置",
        "accounts": "账户列表",
        "wmi_subscriptions": "WMI 订阅",
        "log_snippet": "日志片段",
        "ads_info": "ADS 信息",
        "bits_jobs": "BITS 任务",
        "profile_content": "配置内容",
        "attempt_count": "尝试次数",
        "attack_frequency": "攻击频率",
        "unique_sources": "唯一攻击源数",
    }

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.logger = logging.getLogger("report_builder")
        self.llm = llm_client

    def _cn_severity(self, sev: str) -> str:
        """将英文严重程度转为中文"""
        return self.SEVERITY_CN.get(sev, sev)

    def _cn_type(self, tp: str) -> str:
        """将威胁类型转为中文"""
        return self.THREAT_TYPE_CN.get(tp, tp)

    def _cn_phase(self, phase: str) -> str:
        """将攻击阶段转为中文（保留英文原名 + 中文注释）"""
        cn = self.PHASE_CN.get(phase)
        if cn:
            return f"{phase}（{cn}）"
        return phase

    def _cn_sophistication(self, s: str) -> str:
        """将攻击复杂度转为中文"""
        return self.SOPHISTICATION_CN.get(s, s)

    def _cn_priority(self, p: str) -> str:
        """将优先级转为中文"""
        return self.PRIORITY_CN.get(p, p)

    def _cn_detail_key(self, key: str) -> str:
        """将 details 字段名转为中文"""
        return self.DETAIL_KEY_CN.get(key, key)

    async def build_report(
        self,
        evidence: Dict[str, Any],
        analysis_result: Dict[str, Any],
    ) -> str:
        """
        基于证据和分析结果生成完整的 Markdown 报告。

        Args:
            evidence: 客户端提交的原始证据
            analysis_result: EvidenceAnalyzer 的分析结果

        Returns:
            Markdown 格式的报告文本
        """
        now = datetime.now()
        host_info = evidence.get("host_info", {})
        summary = analysis_result.get("summary", {})
        threats = analysis_result.get("threats", [])
        attack_chain = analysis_result.get("attack_chain", {})
        attacker_profile = analysis_result.get("attacker_profile", {})
        llm_analysis = analysis_result.get("llm_analysis", {})
        total = sum(summary.values())

        # ── 调用 LLM 生成综合分析（如果可用）──
        executive_summary = ""
        if self.llm and threats:
            try:
                scan_data = json.dumps({
                    "hostname": host_info.get("hostname", "未知"),
                    "os_release": host_info.get("os_release", "未知")[:100],
                    "ip_addresses": host_info.get("ip_addresses", []),
                    "summary": summary,
                    "total_threats": total,
                    "threat_types": self._count_types(threats),
                    "attacker_profile": attacker_profile,
                    "attack_phases": attack_chain.get("attack_phases", []),
                }, ensure_ascii=False, indent=2)
                executive_summary = await self.llm.generate_report_analysis(scan_data)
            except Exception as e:
                self.logger.warning(f"LLM 综合分析失败: {e}")
                executive_summary = "*LLM 综合分析不可用*"
        else:
            executive_summary = "*未启用 LLM 分析或未发现威胁*"

        # ── 组装报告各节 ──
        sections = []

        sections.append(self._header(now, host_info, evidence, summary, total))
        sections.append(self._executive_summary(executive_summary))
        sections.append(self._host_overview(host_info, evidence))
        sections.append(self._threat_details(threats, summary))
        sections.append(self._llm_analysis_section(llm_analysis))
        sections.append(self._attack_chain_section(attack_chain))
        sections.append(self._attacker_profile_section(attacker_profile))
        sections.append(self._ioc_section(threats, attacker_profile))
        sections.append(self._recommendations_section(attack_chain))
        sections.append(self._appendix(now, evidence))

        return "\n".join(s for s in sections if s)

    # ==================================================================
    #  报告各节段
    # ==================================================================

    def _header(self, now, host_info, evidence, summary, total) -> str:
        overall = "严重" if summary.get("critical", 0) > 0 else (
            "高危" if summary.get("high", 0) > 0 else ("中等" if total > 0 else "低危")
        )
        mode = "LLM 深度分析" if self.llm else "本地规则分析"
        return f"""# 应急响应报告

---

## 报告基本信息

| 项目 | 内容 |
|------|------|
| **生成时间** | {now.strftime('%Y-%m-%d %H:%M:%S')} |
| **报告类型** | 远程取证分析（客户端-服务端模式） |
| **目标主机** | {host_info.get('hostname', '未知')} |
| **主机 IP** | {', '.join(host_info.get('ip_addresses', ['未知']))} |
| **操作系统** | {str(host_info.get('os_release', '未知'))[:80]} |
| **内核版本** | {host_info.get('kernel', '未知')} |
| **威胁等级** | **{overall}** |
| **发现总数** | {total} |
| **分析模式** | {mode} |
| **采集时间** | {evidence.get('collection_time', '未知')} |

---
"""

    def _executive_summary(self, llm_summary: str) -> str:
        return f"""## 1. 综合安全态势分析

> 以下分析由大模型基于采集证据自动生成

{llm_summary}

---
"""

    def _host_overview(self, host_info: Dict, evidence: Dict) -> str:
        accounts = evidence.get("accounts", {})
        collection_summary = evidence.get("summary", {})

        lines = [
            "## 2. 主机概况",
            "",
            "### 2.1 系统信息",
            "",
            "| 项目 | 值 |",
            "|------|-----|",
            f"| 主机名 | `{host_info.get('hostname', '未知')}` |",
            f"| IP 地址 | {', '.join(f'`{ip}`' for ip in host_info.get('ip_addresses', []))} |",
            f"| 系统运行时间 | {host_info.get('uptime', '未知')} |",
            f"| 上次重启 | {host_info.get('last_reboot', '未知')} |",
            "",
            "### 2.2 账户概况",
            "",
            "| 项目 | 值 |",
            "|------|-----|",
            f"| 账户总数 | {collection_summary.get('total_accounts', '?')} |",
            f"| UID=0 账户 | {collection_summary.get('uid0_accounts', 0)} |",
            f"| 可登录账户 | {collection_summary.get('login_shell_accounts', '?')} |",
            f"| shadow 可读 | {'是' if accounts.get('shadow_accessible') else '否'} |",
            "",
        ]

        # 当前登录用户
        logged_in = accounts.get("logged_in_users", "")
        if logged_in:
            lines.extend([
                "### 2.3 当前登录用户",
                "",
                "```",
                logged_in[:500],
                "```",
                "",
            ])

        lines.append("---")
        return "\n".join(lines)

    def _threat_details(self, threats: List[Dict], summary: Dict) -> str:
        lines = [
            "## 3. 威胁发现详情",
            "",
            "### 3.1 威胁统计",
            "",
            "| 威胁等级 | 数量 |",
            "|----------|------|",
            f"| 严重 | {summary.get('critical', 0)} |",
            f"| 高危 | {summary.get('high', 0)} |",
            f"| 中等 | {summary.get('medium', 0)} |",
            f"| 低危 | {summary.get('low', 0)} |",
            "",
            "### 3.2 威胁清单",
            "",
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_threats = sorted(threats, key=lambda t: severity_order.get(t.get("severity", "low"), 9))

        for i, t in enumerate(sorted_threats[:40], 1):
            sev = self._cn_severity(t.get("severity", "low"))
            tp_cn = self._cn_type(t.get("type", ""))
            lines.append(f"**{i}. [{sev}] {t.get('title', '')}**")
            lines.append("")
            lines.append(f"- 类型: `{tp_cn}`")
            lines.append(f"- 描述: {t.get('description', '')}")
            details = t.get("details", {})
            if isinstance(details, dict):
                for k, v in list(details.items())[:5]:
                    v_str = str(v)[:150]
                    k_cn = self._cn_detail_key(k)
                    lines.append(f"- {k_cn}: `{v_str}`")
            lines.append(f"- 建议: {t.get('recommendation', '')}")
            lines.append("")

        if len(threats) > 40:
            lines.append(f"*（共 {len(threats)} 条威胁，此处展示前 40 条）*")
            lines.append("")

        lines.append("---")
        return "\n".join(lines)

    def _llm_analysis_section(self, llm_analysis: Dict) -> str:
        if not llm_analysis or not any(v for v in llm_analysis.values()):
            return ""

        lines = ["## 4. AI 深度分析", ""]

        section_map = {
            "threat_analysis": "4.1 威胁综合分析",
            "process_analysis": "4.2 可疑进程分析",
            "cron_analysis": "4.3 恶意计划任务分析",
            "login_analysis": "4.4 登录活动分析",
            "chain_analysis": "4.5 攻击链深度还原",
        }

        for key, title in section_map.items():
            content = llm_analysis.get(key)
            if content:
                lines.extend([f"### {title}", "", content, ""])

        lines.append("---")
        return "\n".join(lines)

    def _attack_chain_section(self, attack_chain: Dict) -> str:
        phases = attack_chain.get("attack_phases", [])
        timeline = attack_chain.get("timeline", [])

        if not phases and not timeline:
            return ""

        lines = ["## 5. 攻击链分析", ""]

        if phases:
            lines.extend([
                "### 5.1 攻击阶段映射（MITRE ATT&CK）",
                "",
                "| 攻击阶段 | 名称 | 描述 | MITRE 技术 |",
                "|----------|------|------|------------|",
            ])
            for p in phases:
                phase_cn = self._cn_phase(p.get('phase', ''))
                lines.append(
                    f"| {phase_cn} | {p.get('name', '')} | "
                    f"{p.get('description', '')[:60]} | {p.get('mitre_technique', '')} |"
                )
            lines.append("")

        if timeline:
            lines.extend([
                "### 5.2 攻击时间线",
                "",
                "| 阶段 | 类型 | 严重程度 | 描述 |",
                "|------|------|----------|------|",
            ])
            for event in timeline[:30]:
                phase_cn = self._cn_phase(event.get('phase', ''))
                sev_cn = self._cn_severity(event.get('severity', ''))
                type_cn = self._cn_type(event.get('type', ''))
                lines.append(
                    f"| {phase_cn} | `{type_cn}` | "
                    f"{sev_cn} | {str(event.get('description', ''))[:50]} |"
                )
            lines.append("")

        lines.append("---")
        return "\n".join(lines)

    def _attacker_profile_section(self, profile: Dict) -> str:
        if not profile:
            return ""

        chars = profile.get("attacker_characteristics", {})
        assessment = profile.get("threat_assessment", {})
        patterns = profile.get("attack_patterns", [])

        lines = ["## 6. 攻击者画像", ""]

        if chars:
            lines.extend([
                "### 6.1 攻击源信息",
                "",
                "| 属性 | 值 |",
                "|------|-----|",
                f"| 主要攻击源 IP | `{chars.get('primary_source_ip', '无')}` |",
                f"| 攻击频率 | {chars.get('attack_frequency', 0)} 次 |",
                f"| 唯一攻击源数 | {chars.get('unique_sources', 0)} |",
                "",
            ])

            dist = chars.get("attack_distribution", {})
            if dist:
                lines.extend([
                    "**IP 分布:**",
                    "",
                    "| IP | 活动次数 |",
                    "|----|----------|",
                ])
                for ip, count in sorted(dist.items(), key=lambda x: x[1], reverse=True)[:10]:
                    lines.append(f"| `{ip}` | {count} |")
                lines.append("")

        if assessment:
            threat_level = assessment.get('overall_threat_level', '未知')
            threat_level_cn = self._cn_severity(threat_level)
            sophistication = assessment.get('attack_sophistication', '未知')
            sophistication_cn = self._cn_sophistication(sophistication)
            persistence = assessment.get('persistence_indicators', [])
            persistence_cn = ', '.join(self._cn_type(p) for p in persistence) if persistence else '无'

            lines.extend([
                "### 6.2 威胁评估",
                "",
                "| 属性 | 值 |",
                "|------|-----|",
                f"| 威胁等级 | **{threat_level_cn}** |",
                f"| 严重发现 | {assessment.get('critical_findings', 0)} |",
                f"| 高危发现 | {assessment.get('high_findings', 0)} |",
                f"| 攻击复杂度 | {sophistication_cn} |",
                f"| 持久化迹象 | {persistence_cn} |",
                "",
            ])

        if patterns:
            lines.extend([
                "### 6.3 攻击模式",
                "",
                "| 模式 | 次数 |",
                "|------|------|",
            ])
            for p in patterns[:10]:
                pattern_cn = self._cn_type(p.get('pattern', ''))
                lines.append(f"| `{pattern_cn}` | {p.get('count', 0)} |")
            lines.append("")

        lines.append("---")
        return "\n".join(lines)

    def _ioc_section(self, threats: List[Dict], profile: Dict) -> str:
        lines = ["## 7. IOC（攻击指标）", ""]

        # 提取 IP
        ips = set()
        for t in threats:
            details = t.get("details", {})
            if isinstance(details, dict):
                for key in ("source_ip", "ip"):
                    ip = details.get(key)
                    if ip and ip not in ("local", "localhost", "127.0.0.1", "Unknown", "未知", ""):
                        ips.add(ip)

        if ips:
            lines.extend([
                "### 网络指标",
                "",
                "| 类型 | 值 |",
                "|------|-----|",
            ])
            for ip in sorted(ips):
                lines.append(f"| IP 地址 | `{ip}` |")
            lines.append("")

        # 可疑进程
        procs = [t for t in threats if t.get("type") in ("mining_process", "suspicious_process")]
        if procs:
            lines.extend([
                "### 主机指标 - 可疑进程",
                "",
                "| 进程 ID | 关键字 | 命令 |",
                "|---------|--------|------|",
            ])
            for p in procs:
                d = p.get("details", {})
                lines.append(
                    f"| {d.get('pid', '?')} | `{d.get('keyword', '')}` | `{str(d.get('command', ''))[:60]}` |"
                )
            lines.append("")

        # 恶意计划任务
        crons = [t for t in threats if t.get("type") == "malicious_cron"]
        if crons:
            lines.extend([
                "### 主机指标 - 恶意计划任务",
                "",
                "| 匹配模式 | 匹配内容 |",
                "|----------|----------|",
            ])
            for c in crons:
                d = c.get("details", {})
                lines.append(f"| `{d.get('matched_pattern', '')}` | `{str(d.get('matched_text', ''))[:80]}` |")
            lines.append("")

        # 可疑端口
        ports = [t for t in threats if t.get("type") == "suspicious_connection"]
        if ports:
            lines.extend([
                "### 网络指标 - 可疑端口",
                "",
                "| 端口 |",
                "|------|",
            ])
            for p in ports:
                lines.append(f"| {p.get('details', {}).get('port', '?')} |")
            lines.append("")

        lines.append("---")
        return "\n".join(lines)

    def _recommendations_section(self, attack_chain: Dict) -> str:
        recs = attack_chain.get("recommendations", [])
        if not recs:
            return ""

        lines = [
            "## 8. 安全建议",
            "",
            "| 优先级 | 行动 | 详情 | 时限 |",
            "|--------|------|------|------|",
        ]
        for r in recs:
            priority_cn = self._cn_priority(r.get('priority', ''))
            lines.append(
                f"| **{priority_cn}** | {r.get('action', '')} | "
                f"{r.get('details', '')} | {r.get('timeline', '')} |"
            )
        lines.append("")
        lines.append("---")
        return "\n".join(lines)

    def _appendix(self, now, evidence: Dict) -> str:
        collection_summary = evidence.get("summary", {})
        mode = "LLM 深度分析" if self.llm else "本地规则分析"
        return f"""
## 附录

### 采集信息

| 项目 | 值 |
|------|-----|
| 采集器版本 | {evidence.get('collector_version', '?')} |
| 采集耗时 | {collection_summary.get('collection_duration_seconds', '?')}秒 |
| 证据哈希 | `{collection_summary.get('evidence_hash', '无')}` |
| 采集时间 | {evidence.get('collection_time', '?')} |

### 免责声明

- 本报告基于采集时间点的系统状态快照生成
- 深度分析部分由大模型自动生成，建议结合人工研判
- 分析结果受限于采集数据的完整性和覆盖范围

---

> **报告生成工具**: 应急响应智能体 - 服务端分析引擎 v1.0
> **分析模式**: {mode}
> **生成时间**: {now.strftime('%Y-%m-%d %H:%M:%S')}
"""

    # ==================================================================
    #  工具方法
    # ==================================================================

    @staticmethod
    def _count_types(threats: List[Dict]) -> Dict[str, int]:
        types = {}
        for t in threats:
            tp = t.get("type", "unknown")
            types[tp] = types.get(tp, 0) + 1
        return types


__all__ = ["ServerReportBuilder"]
