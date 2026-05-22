"""
配置管理 - 支持多协议大模型 API 和便捷配置
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from pathlib import Path

# 默认系统提示词 - 适用于所有大模型的安全分析角色定义
DEFAULT_SYSTEM_PROMPT = """你是一名高级网络安全应急响应分析师，负责对安全事件进行专业分析和研判。

## 行为准则
1. 所有分析结论必须基于提供的证据数据，禁止臆测或编造不存在的事实
2. 明确区分"已确认事实"与"推测判断"，推测内容必须标注"推测"字样
3. 风险等级统一使用四级制：【严重】【高危】【中危】【低危】
4. 所有输出使用中文，使用 Markdown 格式，段落之间用空行分隔
5. 不要在输出中包含与分析无关的寒暄、免责声明或元信息（如"以下是分析结果"）
6. 直接输出分析内容，以 Markdown 标题开头"""

# 预定义的大模型 API 协议配置
LLM_PROTOCOLS = {
    "openai-completions": {
        "name": "OpenAI Completions",
        "default_url": "https://api.openai.com/v1/chat/completions",
        "supported_models": ["gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
        "headers_template": {"Authorization": "Bearer {api_key}", "Content-Type": "application/json"}
    },
    "azure-openai": {
        "name": "Azure OpenAI",
        "default_url": "{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=2024-02-01",
        "supported_models": ["gpt-4o", "gpt-4-turbo", "gpt-35-turbo"],
        "requires_extra": ["azure_endpoint", "azure_deployment"]
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "default_url": "https://api.anthropic.com/v1/messages",
        "supported_models": ["claude-3-opus", "claude-3 sonnet", "claude-3-haiku", "claude-2.1"],
        "headers_template": {"x-api-key": "{api_key}", "Content-Type": "application/json", "anthropic-version": "2023-06-01"}
    },
    "gemini": {
        "name": "Google Gemini",
        "default_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "supported_models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.0-pro"],
        "url_params": {"key": "{api_key}"}
    },
    "ollama": {
        "name": "Ollama Local",
        "default_url": "http://localhost:11434/api/chat",
        "supported_models": ["llama3", "mistral", "gemma", "vicuna"],
        "headers_template": {"Content-Type": "application/json"}
    },
    "qwen": {
        "name": "阿里云通义千问 (DashScope)",
        "default_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "supported_models": ["qwen-max", "qwen-plus", "qwen-turbo", "qwen-long"],
        "headers_template": {"Authorization": "Bearer {api_key}", "Content-Type": "application/json"}
    },
    "deepseek": {
        "name": "DeepSeek",
        "default_url": "https://api.deepseek.com/chat/completions",
        "supported_models": ["deepseek-chat", "deepseek-coder"],
        "headers_template": {"Authorization": "Bearer {api_key}", "Content-Type": "application/json"}
    }
}

DEFAULT_CONFIG_PATH = Path.home() / ".emergency_response_agent" / "config.json"

class Settings:
    """应用配置类 - 支持自动配置和协议切换"""

    def __init__(self, config_file: Optional[Path] = None):
        self.logger = logging.getLogger(__name__)
        self.config_file = config_file or DEFAULT_CONFIG_PATH
        self._ensure_config_dir()
        
        # 从配置文件或环境变量加载配置
        self._load_config()
        
        # 验证配置
        self._validate()
    
    def _ensure_config_dir(self):
        """确保配置目录存在"""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self):
        """加载配置：优先使用配置文件，其次项目目录 config.json，最后环境变量"""
        # 查找配置文件：用户目录 > 项目根目录 config.json
        config_path = self.config_file
        if not config_path.exists():
            project_config = Path(__file__).resolve().parent.parent / "config.json"
            if project_config.exists():
                config_path = project_config

        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    
                # 合并配置
                self.llm_protocol = saved_config.get('llm_protocol', 'openai-completions')
                self.llm_api_url = saved_config.get('llm_api_url') or LLM_PROTOCOLS[self.llm_protocol]['default_url']
                self.llm_api_key = saved_config.get('llm_api_key', '')
                self.llm_model = saved_config.get('llm_model', 'gpt-3.5-turbo')
                self.llm_system_prompt = saved_config.get('llm_system_prompt',
                    DEFAULT_SYSTEM_PROMPT)
                
                # 协议特定参数
                if self.llm_protocol == 'azure-openai':
                    self.azure_endpoint = saved_config.get('azure_endpoint', '')
                    self.azure_deployment = saved_config.get('azure_deployment', '')
                    
            except (json.JSONDecodeError, KeyError) as e:
                print(f"警告：配置文件读取失败 ({e})，将使用环境变量")
                self._load_from_env()
        else:
            # 无配置文件，使用环境变量
            self._load_from_env()
            
            # 提示用户首次配置
            if not self.llm_api_key:
                print("\n" + "="*60)
                print("⚠️  首次运行检测！检测到未配置 API Key。")
                print("请使用以下命令进行一次性配置：")
                print("请编辑 config.json 或设置环境变量 LLM_API_KEY")
                print("="*60 + "\n")
    
    def _load_from_env(self):
        """从环境变量加载配置"""
        self.llm_protocol = os.getenv('LLM_PROTOCOL', 'openai-completions')
        self.llm_api_url = os.getenv('LLM_API_URL', LLM_PROTOCOLS[self.llm_protocol]['default_url'])
        self.llm_api_key = os.getenv('LLM_API_KEY', '')
        self.llm_model = os.getenv('LLM_MODEL', 'gpt-3.5-turbo')
        self.llm_system_prompt = os.getenv('LLM_SYSTEM_PROMPT', 
            '你是一个专业的网络安全分析师，专门分析安全威胁并提供建议。')
        
        if self.llm_protocol == 'azure-openai':
            self.azure_endpoint = os.getenv('AZURE_ENDPOINT', '')
            self.azure_deployment = os.getenv('AZURE_DEPLOYMENT', '')
    
    def save_config(self):
        """保存配置到文件"""
        config = {
            'llm_protocol': self.llm_protocol,
            'llm_api_url': self.llm_api_url,
            'llm_api_key': self.llm_api_key,
            'llm_model': self.llm_model,
            'llm_system_prompt': self.llm_system_prompt,
        }
        
        if self.llm_protocol == 'azure-openai':
            config.update({
                'azure_endpoint': getattr(self, 'azure_endpoint', ''),
                'azure_deployment': getattr(self, 'azure_deployment', '')
            })
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 配置已保存到：{self.config_file}")
    
    def _validate(self):
        """验证配置"""
        if not self.llm_api_key and self.llm_protocol != 'ollama':
            self.logger.warning("缺少大模型 API 密钥，LLM 分析功能将不可用。请编辑 config.json 或设置环境变量。")

        if self.llm_protocol not in LLM_PROTOCOLS:
            raise ValueError(f"不支持的大模型协议：{self.llm_protocol}")
    
    @property
    def has_llm(self) -> bool:
        """判断是否配置了可用的 LLM"""
        if self.llm_protocol == 'ollama':
            return True
        return bool(self.llm_api_key)

    def get_protocol_info(self) -> Dict[str, Any]:
        """获取当前协议的详细信息"""
        return LLM_PROTOCOLS.get(self.llm_protocol, {})
    
    def get_available_protocols(self) -> list:
        """获取所有可用的协议列表"""
        return list(LLM_PROTOCOLS.keys())
    
    @staticmethod
    def list_protocols():
        """列出所有可用的大模型协议"""
        print("\n可用的大模型 API 协议:")
        print("-" * 60)
        for protocol_id, info in LLM_PROTOCOLS.items():
            models = ", ".join(info['supported_models'][:3])
            if len(info['supported_models']) > 3:
                models += " ..."
            print(f"  • {protocol_id}: {info['name']}")
            print(f"    支持模型：{models}")
        print("-" * 60 + "\n")
