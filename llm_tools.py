#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM工具模块 - 提供与大语言模型交互的功能

为K8s Agent提供自然语言处理能力，将用户查询转换为Kubernetes命令。
"""

import json
import os
import logging
from openai import OpenAI

logger = logging.getLogger('k8s_agent.llm_tools')


def init_openai_client(api_key=None, base_url=None):
    """
    初始化OpenAI客户端
    
    Args:
        api_key: OpenAI API密钥，如果为None则尝试从环境变量获取
        base_url: OpenAI API基础URL，可选
        
    Returns:
        OpenAI客户端实例
    """
    # 如果未提供API密钥，尝试从环境变量获取
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            logger.error("未设置OpenAI API密钥，请通过参数提供或设置环境变量OPENAI_API_KEY")
            raise ValueError("未设置OpenAI API密钥")
    
    # 创建客户端配置
    client_kwargs = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    
    # 初始化客户端
    try:
        client = OpenAI(**client_kwargs)
        return client
    except Exception as e:
        logger.error(f"初始化OpenAI客户端失败: {str(e)}")
        raise


def get_llm_response(prompt, model="gpt-3.5-turbo", api_key=None, base_url=None, system_prompt=None):
    """
    获取LLM对提示的响应
    
    Args:
        prompt: 用户提示文本
        model: 使用的模型名称，默认为gpt-3.5-turbo
        api_key: OpenAI API密钥，如果为None则尝试从环境变量获取
        base_url: OpenAI API基础URL，可选
        system_prompt: 系统提示，可选
        
    Returns:
        LLM的响应文本
    """
    try:
        # 初始化客户端
        client = init_openai_client(api_key, base_url)
        
        # 准备消息
        messages = [
            {"role": "system", "content": system_prompt or "You are a helpful Kubernetes assistant."},
            {"role": "user", "content": prompt}
        ]
        
        logger.debug(f"向LLM发送请求，模型: {model}, 提示: {prompt[:100]}...")
        
        # 发送请求
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            stream=False
        )
        
        # 返回响应文本
        return response.choices[0].message.content
    
    except Exception as e:
        logger.error(f"获取LLM响应失败: {str(e)}")
        return f"获取LLM响应失败: {str(e)}"


def generate_kubectl_commands(query_text, namespace=None, model="gpt-3.5-turbo", api_key=None, base_url=None):
    """
    将自然语言查询转换为kubectl命令
    
    Args:
        query_text: 用户的自然语言查询
        namespace: Kubernetes命名空间，可选
        model: 使用的模型名称
        api_key: OpenAI API密钥，如果为None则尝试从环境变量获取
        base_url: OpenAI API基础URL，可选
        
    Returns:
        生成的kubectl命令列表
    """
    # 构建提示
    system_prompt = """
    你是一个Kubernetes专家助手。你的任务是将用户的自然语言查询转换为适当的kubectl命令。
    请遵循以下规则：
    1. 只返回kubectl命令，不要包含任何解释或额外文本
    2. 每行一个命令
    3. 如果提供了命名空间，请在命令中使用它
    4. 如果查询不明确，返回最可能有用的命令
    5. 命令应该是有效的kubectl命令，可以直接执行
    6. 返回的格式应该是JSON数组，每个元素是一个命令字符串
    """
    
    # 添加命名空间信息到查询
    if namespace:
        prompt = f"命名空间: {namespace}\n查询: {query_text}"
    else:
        prompt = f"查询: {query_text}"
    
    # 获取LLM响应
    response = get_llm_response(
        prompt=prompt,
        model=model,
        api_key=api_key,
        base_url=base_url,
        system_prompt=system_prompt
    )
    
    # 清理响应中的Markdown代码块标记
    cleaned_response = response.strip()
    if cleaned_response.startswith("```"):
        # 移除开头的```json或```等标记
        first_newline = cleaned_response.find('\n')
        if first_newline != -1:
            cleaned_response = cleaned_response[first_newline:].strip()
    
    if cleaned_response.endswith("```"):
        # 移除结尾的```标记
        cleaned_response = cleaned_response[:-3].strip()
    
    # 尝试解析JSON响应
    try:
        commands = json.loads(cleaned_response)
        if isinstance(commands, list):
            return commands
        else:
            logger.warning(f"LLM返回的不是命令列表: {cleaned_response}")
            return []
    except json.JSONDecodeError:
        # 如果不是JSON格式，尝试按行分割
        logger.warning(f"无法解析LLM响应为JSON: {cleaned_response}")
        commands = [cmd.strip() for cmd in cleaned_response.split('\n') if cmd.strip().startswith('kubectl')]
        return commands