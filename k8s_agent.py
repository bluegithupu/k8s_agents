#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
K8s Agent - 智能化的Kubernetes问题排查助手

一个基于自然语言处理的工具，帮助用户快速排查和解决Kubernetes集群中的问题。
"""

import os
import sys
import json
import click
import logging
import subprocess
from typing import Optional

# 导入LLM工具
from llm_tools import generate_kubectl_commands
# 导入结果分析模块
from result_analyzer import ResultAnalyzer, analyze_kubectl_result, extract_key_info

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('k8s_agent')

# 默认配置
DEFAULT_CONFIG = {
    
    "openai_api_key": "sk-cdjsim5KBne5thQJ2bF279E94fEa487aA347A7D85747Af10",
    "model": "gpt-4o-mini",
    "kubectl_path": "kubectl",
    "openai_base_url": "https://api.rcouyi.com/v1"
}


class K8sAgent:
    """K8s Agent 核心类，处理自然语言查询并执行相应的kubectl命令"""
    
    def __init__(self, config=None):
        """初始化K8s Agent
        
        Args:
            config: 配置字典，包含OpenAI API密钥等信息
        """
        self.config = config or DEFAULT_CONFIG
        
        # 检查OpenAI API密钥
        if not self.config.get("openai_api_key"):
            self.config["openai_api_key"] = os.environ.get("OPENAI_API_KEY", "")
            if not self.config["openai_api_key"]:
                logger.warning("未设置OpenAI API密钥，请通过环境变量OPENAI_API_KEY设置或在配置文件中指定")
    
    def execute_command(self, cmd):
        """执行kubectl命令
        
        Args:
            cmd: 要执行的命令
            
        Returns:
            命令执行结果字典，包含命令、输出和成功状态
        """
        try:
            logger.info(f"执行命令: {cmd}")
            # 在实际版本中执行命令并获取输出
            if self.config.get("execute_commands", False):
                result = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
                output = result.stdout if result.returncode == 0 else f"错误: {result.stderr}"
                success = result.returncode == 0
            else:
                # 在MVP版本中，只模拟输出
                output = f"[模拟输出] 执行 {cmd} 的结果将显示在这里"
                success = True
                
            return {
                "command": cmd,
                "output": output,
                "success": success
            }
        except Exception as e:
            logger.error(f"执行命令失败: {str(e)}")
            return {
                "command": cmd,
                "output": str(e),
                "success": False
            }
    
    def process_query(self, query_text: str, namespace: Optional[str] = None):
        """处理用户查询
        
        Args:
            query_text: 用户的自然语言查询
            namespace: Kubernetes命名空间
            
        Returns:
            查询结果字典
        """
        logger.info(f"处理查询: {query_text}")
        
        # 使用LLM将自然语言转换为kubectl命令
        try:
            # 获取API密钥和基础URL
            api_key = self.config.get("openai_api_key")
            base_url = self.config.get("openai_base_url")
            model = self.config.get("model", "gpt-3.5-turbo")
            
            # 使用LLM生成kubectl命令
            commands = generate_kubectl_commands(
                query_text=query_text,
                namespace=namespace,
                model=model,
                api_key=api_key,
                base_url=base_url
            )
            
            # 如果没有生成命令，使用默认命令
            if not commands:
                logger.warning("LLM未能生成有效命令，使用默认命令")
                commands = self._get_default_commands(query_text, namespace)
        except Exception as e:
            logger.error(f"使用LLM生成命令失败: {str(e)}")
            # 出错时使用默认命令
            commands = self._get_default_commands(query_text, namespace)
        
        # 初始化结果分析器
        analyzer = ResultAnalyzer()
        
        # 执行命令并收集结果
        results = []
        analyses = []
        for cmd in commands:
            result = self.execute_command(cmd)
            results.append(result)
            
            # 分析命令执行结果
            analysis = analyzer.analyze(result)
            analyses.append(analysis)
        
        # 返回查询结果
        query_record = {
            "query": query_text,
            "namespace": namespace,
            "commands": commands,
            "results": results,
            "analyses": analyses
        }
        
        return query_record
        
    def _get_default_commands(self, query_text: str, namespace: Optional[str] = None):
        """获取默认的kubectl命令
        
        当LLM无法生成命令时使用简单的规则匹配
        
        Args:
            query_text: 用户的自然语言查询
            namespace: Kubernetes命名空间
            
        Returns:
            命令列表
        """
        commands = []
        
        if "pod" in query_text.lower() and "列表" in query_text:
            cmd = f"kubectl get pods"
            if namespace:
                cmd += f" -n {namespace}"
            commands.append(cmd)
        elif "pod" in query_text.lower() and "无法启动" in query_text:
            # 查询失败的Pod
            cmd1 = f"kubectl get pods"
            if namespace:
                cmd1 += f" -n {namespace}"
            commands.append(cmd1)
            
            # 查看Pod详情
            cmd2 = f"kubectl describe pods"
            if namespace:
                cmd2 += f" -n {namespace}"
            commands.append(cmd2)
        elif "服务" in query_text.lower() or "service" in query_text.lower():
            cmd = f"kubectl get services"
            if namespace:
                cmd += f" -n {namespace}"
            commands.append(cmd)
        else:
            # 默认返回集群状态
            commands.append("kubectl cluster-info")
            commands.append("kubectl get nodes")
            
        return commands


@click.command()
@click.argument('query_text')
@click.option('-n', '--namespace', help='Kubernetes命名空间')
@click.option('--debug', is_flag=True, help='启用调试模式')
def query(query_text, namespace, debug):
    """执行自然语言查询"""
    if debug:
        logging.getLogger('k8s_agent').setLevel(logging.DEBUG)
    
    agent = K8sAgent()
    result = agent.process_query(query_text, namespace)
    
    # 打印结果
    click.echo(f"\n查询: {query_text}")
    if namespace:
        click.echo(f"命名空间: {namespace}")
    
    click.echo("\n执行的命令:")
    for cmd in result["commands"]:
        click.echo(f"  {cmd}")
    
    click.echo("\n结果:")
    for i, res in enumerate(result["results"]):
        click.echo(f"\n命令: {res['command']}")
        click.echo("-" * 40)
        click.echo(res["output"])
        click.echo("-" * 40)
        
        # 打印分析结果
        if i < len(result.get("analyses", [])):
            analysis = result["analyses"][i]
            click.echo("分析:")
            
            # 打印潜在问题
            if analysis.get("potential_issues"):
                click.echo("\n潜在问题:")
                for issue in analysis["potential_issues"]:
                    click.echo(f"  - {issue}")
            
            # 打印建议
            if analysis.get("suggestions"):
                click.echo("\n建议:")
                for suggestion in analysis["suggestions"]:
                    click.echo(f"  - {suggestion}")
            
            # 打印提取的关键信息
            if analysis.get("extracted_info"):
                click.echo("\n提取的关键信息:")
                # 简化输出，只显示最重要的信息
                key_info = extract_key_info(analysis)
                for key, value in key_info.items():
                    if key not in ["success", "issues", "suggestions"]:
                        click.echo(f"  {key}: {value}")
    
    click.echo("\n注意: 这是MVP版本，命令未实际执行。在完整版本中将执行实际命令并分析结果。")


if __name__ == '__main__':
    query()