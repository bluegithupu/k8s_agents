#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
结果分析模块 - 解析和分析Kubernetes命令执行结果

为K8s Agent提供结果分析能力，包括结构化数据解析、日志分析和错误模式识别。
"""

import json
import yaml
import re
import logging
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger('k8s_agent.result_analyzer')


class ResultAnalyzer:
    """Kubernetes命令结果分析器
    
    负责解析和分析kubectl命令的执行结果，提取关键信息，识别错误模式。
    """
    
    def __init__(self):
        """初始化结果分析器"""
        # 初始化错误模式库
        self.error_patterns = {
            # Pod相关错误
            "ImagePullBackOff": "镜像拉取失败，可能是镜像名称错误、私有仓库认证问题或网络问题",
            "CrashLoopBackOff": "容器反复崩溃，请检查容器日志以获取更多信息",
            "Error": "Pod出现错误状态，需要进一步分析",
            "Pending": "Pod处于等待状态，可能是资源不足或调度问题",
            "ContainerCreating": "容器正在创建中，如果长时间处于此状态可能存在问题",
            "ErrImagePull": "拉取镜像失败",
            
            # 服务相关错误
            "ServiceNotFound": "找不到指定的服务",
            "EndpointsNotFound": "服务没有可用的端点",
            
            # 权限相关错误
            "Forbidden": "权限不足，请检查RBAC设置",
            "Unauthorized": "未授权访问，请检查认证配置",
            
            # 网络相关错误
            "NetworkNotReady": "网络未就绪，可能是CNI插件问题",
            "DNSError": "DNS解析错误，请检查CoreDNS或kube-dns服务",
            
            # 资源相关错误
            "OutOfMemory": "内存不足，考虑增加资源限制或检查内存泄漏",
            "OutOfCpu": "CPU资源不足",
            "PersistentVolumeClaimNotFound": "找不到PVC，请检查存储配置"
        }
    
    def analyze(self, command_result: Dict[str, Any]) -> Dict[str, Any]:
        """分析命令执行结果
        
        Args:
            command_result: 命令执行结果字典，包含命令、输出和成功状态
            
        Returns:
            分析结果字典，包含提取的关键信息和可能的问题诊断
        """
        # 初始化分析结果
        analysis = {
            "command": command_result.get("command", ""),
            "success": command_result.get("success", False),
            "extracted_info": {},
            "potential_issues": [],
            "suggestions": []
        }
        
        # 如果命令执行失败，直接返回错误信息
        if not analysis["success"]:
            error_output = command_result.get("output", "")
            analysis["potential_issues"].append(f"命令执行失败: {error_output}")
            analysis["suggestions"].append("检查kubectl配置和集群连接状态")
            return analysis
        
        # 获取命令输出
        output = command_result.get("output", "")
        
        # 根据命令类型选择不同的解析方法
        command = analysis["command"]
        
        if "get" in command and ("-o json" in command or "--output=json" in command):
            # 解析JSON格式输出
            analysis["extracted_info"] = self._parse_json_output(output)
        elif "get" in command and ("-o yaml" in command or "--output=yaml" in command):
            # 解析YAML格式输出
            analysis["extracted_info"] = self._parse_yaml_output(output)
        elif "describe" in command:
            # 解析describe命令输出
            analysis["extracted_info"] = self._parse_describe_output(output)
        elif "logs" in command:
            # 解析日志输出
            analysis["extracted_info"] = self._parse_logs_output(output)
        elif "get pods" in command or "get pod" in command:
            # 解析Pod列表输出
            analysis["extracted_info"] = self._parse_pod_list_output(output)
        elif "get services" in command or "get svc" in command:
            # 解析Service列表输出
            analysis["extracted_info"] = self._parse_service_list_output(output)
        else:
            # 通用输出解析
            analysis["extracted_info"] = self._parse_general_output(output)
        
        # 识别潜在问题
        issues, suggestions = self._identify_issues(output, command)
        analysis["potential_issues"].extend(issues)
        analysis["suggestions"].extend(suggestions)
        
        return analysis
    
    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """解析JSON格式的命令输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            解析后的结构化数据
        """
        try:
            data = json.loads(output)
            # 提取关键信息
            extracted_info = {}
            
            # 处理不同类型的资源
            if isinstance(data, dict):
                # 单个资源对象
                kind = data.get("kind", "")
                if kind == "Pod":
                    extracted_info = self._extract_pod_info(data)
                elif kind == "Service":
                    extracted_info = self._extract_service_info(data)
                elif kind == "Deployment":
                    extracted_info = self._extract_deployment_info(data)
                else:
                    # 通用资源信息提取
                    extracted_info = {
                        "kind": kind,
                        "name": data.get("metadata", {}).get("name", ""),
                        "namespace": data.get("metadata", {}).get("namespace", "default"),
                        "creation_time": data.get("metadata", {}).get("creationTimestamp", "")
                    }
            elif isinstance(data, list):
                # 资源列表
                items = []
                for item in data:
                    if isinstance(item, dict):
                        items.append({
                            "kind": item.get("kind", ""),
                            "name": item.get("metadata", {}).get("name", ""),
                            "namespace": item.get("metadata", {}).get("namespace", "default")
                        })
                extracted_info = {"items": items}
            
            return extracted_info
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析错误: {str(e)}")
            return {"error": f"无法解析JSON输出: {str(e)}"}
    
    def _parse_yaml_output(self, output: str) -> Dict[str, Any]:
        """解析YAML格式的命令输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            解析后的结构化数据
        """
        try:
            data = yaml.safe_load(output)
            # 使用与JSON解析相同的逻辑处理数据
            return self._parse_json_output(json.dumps(data))
        except yaml.YAMLError as e:
            logger.error(f"YAML解析错误: {str(e)}")
            return {"error": f"无法解析YAML输出: {str(e)}"}
    
    def _parse_describe_output(self, output: str) -> Dict[str, Any]:
        """解析kubectl describe命令的输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            提取的关键信息
        """
        info = {}
        
        # 提取资源名称和类型
        name_match = re.search(r'^(\w+)\s+([\w\-\.]+)', output)
        if name_match:
            info["resource_type"] = name_match.group(1)
            info["name"] = name_match.group(2)
        
        # 提取命名空间
        namespace_match = re.search(r'Namespace:\s+(\S+)', output)
        if namespace_match:
            info["namespace"] = namespace_match.group(1)
        
        # 提取状态信息
        status_match = re.search(r'Status:\s+(\S+)', output)
        if status_match:
            info["status"] = status_match.group(1)
        
        # 提取IP信息
        ip_match = re.search(r'IP:\s+(\S+)', output)
        if ip_match:
            info["ip"] = ip_match.group(1)
        
        # 提取事件信息
        events = []
        events_section = re.search(r'Events:(.*?)(?:$|\n\n)', output, re.DOTALL)
        if events_section:
            events_text = events_section.group(1).strip()
            event_lines = events_text.split('\n')
            for line in event_lines:
                if line.strip() and not line.startswith('  '):
                    event_parts = re.split(r'\s{2,}', line.strip())
                    if len(event_parts) >= 3:
                        events.append({
                            "time": event_parts[0],
                            "type": event_parts[1],
                            "reason": event_parts[2],
                            "message": ' '.join(event_parts[3:]) if len(event_parts) > 3 else ""
                        })
        
        if events:
            info["events"] = events
        
        # 提取容器状态（针对Pod）
        containers = []
        container_sections = re.finditer(r'Container ID:\s+(\S+).*?State:\s+(\S+).*?Ready:\s+(\S+)', output, re.DOTALL)
        for match in container_sections:
            containers.append({
                "id": match.group(1),
                "state": match.group(2),
                "ready": match.group(3) == "True"
            })
        
        if containers:
            info["containers"] = containers
        
        return info
    
    def _parse_logs_output(self, output: str) -> Dict[str, Any]:
        """解析kubectl logs命令的输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            日志分析结果
        """
        # 初始化日志分析结果
        log_analysis = {
            "log_lines": output.split('\n'),
            "error_count": 0,
            "warning_count": 0,
            "error_samples": [],
            "warning_samples": []
        }
        
        # 分析日志行
        for line in log_analysis["log_lines"]:
            # 检测错误
            if re.search(r'error|exception|fail|fatal', line, re.IGNORECASE):
                log_analysis["error_count"] += 1
                if len(log_analysis["error_samples"]) < 5:  # 最多保存5个错误样本
                    log_analysis["error_samples"].append(line)
            
            # 检测警告
            elif re.search(r'warn|warning', line, re.IGNORECASE):
                log_analysis["warning_count"] += 1
                if len(log_analysis["warning_samples"]) < 5:  # 最多保存5个警告样本
                    log_analysis["warning_samples"].append(line)
        
        return log_analysis
    
    def _parse_pod_list_output(self, output: str) -> Dict[str, Any]:
        """解析kubectl get pods命令的输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            Pod列表信息
        """
        pods = []
        lines = output.strip().split('\n')
        
        # 跳过标题行
        if len(lines) > 1:
            for line in lines[1:]:
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 3:
                    pod_info = {
                        "name": parts[0],
                        "ready": parts[1],
                        "status": parts[2],
                        "restarts": parts[3] if len(parts) > 3 else "",
                        "age": parts[4] if len(parts) > 4 else ""
                    }
                    pods.append(pod_info)
        
        return {"pods": pods}
    
    def _parse_service_list_output(self, output: str) -> Dict[str, Any]:
        """解析kubectl get services命令的输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            Service列表信息
        """
        services = []
        lines = output.strip().split('\n')
        
        # 跳过标题行
        if len(lines) > 1:
            for line in lines[1:]:
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 3:
                    service_info = {
                        "name": parts[0],
                        "type": parts[1],
                        "cluster_ip": parts[2],
                        "external_ip": parts[3] if len(parts) > 3 else "",
                        "ports": parts[4] if len(parts) > 4 else "",
                        "age": parts[5] if len(parts) > 5 else ""
                    }
                    services.append(service_info)
        
        return {"services": services}
    
    def _extract_pod_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """从Pod资源JSON中提取关键信息
        
        Args:
            data: Pod资源的JSON数据
            
        Returns:
            提取的Pod信息
        """
        metadata = data.get("metadata", {})
        spec = data.get("spec", {})
        status = data.get("status", {})
        
        # 提取基本信息
        pod_info = {
            "kind": "Pod",
            "name": metadata.get("name", ""),
            "namespace": metadata.get("namespace", "default"),
            "creation_time": metadata.get("creationTimestamp", ""),
            "labels": metadata.get("labels", {}),
            "node": spec.get("nodeName", ""),
            "status": status.get("phase", ""),
            "pod_ip": status.get("podIP", ""),
            "host_ip": status.get("hostIP", "")
        }
        
        # 提取容器信息
        containers = []
        for container in spec.get("containers", []):
            container_info = {
                "name": container.get("name", ""),
                "image": container.get("image", ""),
                "ports": container.get("ports", []),
                "resources": container.get("resources", {})
            }
            containers.append(container_info)
        
        pod_info["containers"] = containers
        
        # 提取容器状态
        container_statuses = []
        for status_item in status.get("containerStatuses", []):
            status_info = {
                "name": status_item.get("name", ""),
                "ready": status_item.get("ready", False),
                "restart_count": status_item.get("restartCount", 0),
                "image": status_item.get("image", ""),
                "container_id": status_item.get("containerID", "")
            }
            
            # 提取详细状态
            state = status_item.get("state", {})
            if "running" in state:
                status_info["state"] = "running"
                status_info["started_at"] = state["running"].get("startedAt", "")
            elif "waiting" in state:
                status_info["state"] = "waiting"
                status_info["reason"] = state["waiting"].get("reason", "")
                status_info["message"] = state["waiting"].get("message", "")
            elif "terminated" in state:
                status_info["state"] = "terminated"
                status_info["reason"] = state["terminated"].get("reason", "")
                status_info["exit_code"] = state["terminated"].get("exitCode", 0)
            
            container_statuses.append(status_info)
        
        pod_info["container_statuses"] = container_statuses
        
        # 提取事件（如果有）
        conditions = []
        for condition in status.get("conditions", []):
            conditions.append({
                "type": condition.get("type", ""),
                "status": condition.get("status", ""),
                "reason": condition.get("reason", ""),
                "message": condition.get("message", "")
            })
        
        pod_info["conditions"] = conditions
        
        return pod_info
    
    def _extract_service_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """从Service资源JSON中提取关键信息
        
        Args:
            data: Service资源的JSON数据
            
        Returns:
            提取的Service信息
        """
        metadata = data.get("metadata", {})
        spec = data.get("spec", {})
        status = data.get("status", {})
        
        # 提取基本信息
        service_info = {
            "kind": "Service",
            "name": metadata.get("name", ""),
            "namespace": metadata.get("namespace", "default"),
            "creation_time": metadata.get("creationTimestamp", ""),
            "labels": metadata.get("labels", {}),
            "type": spec.get("type", "ClusterIP"),
            "cluster_ip": spec.get("clusterIP", ""),
            "selector": spec.get("selector", {})
        }
        
        # 提取端口信息
        ports = []
        for port in spec.get("ports", []):
            port_info = {
                "name": port.get("name", ""),
                "protocol": port.get("protocol", "TCP"),
                "port": port.get("port", 0),
                "target_port": port.get("targetPort", 0),
                "node_port": port.get("nodePort", 0) if service_info["type"] in ["NodePort", "LoadBalancer"] else None
            }
            ports.append(port_info)
        
        service_info["ports"] = ports
        
        # 提取外部IP（针对LoadBalancer类型）
        if service_info["type"] == "LoadBalancer":
            service_info["load_balancer_ip"] = spec.get("loadBalancerIP", "")
            service_info["external_ips"] = status.get("loadBalancer", {}).get("ingress", [])
        elif service_info["type"] == "ExternalName":
            service_info["external_name"] = spec.get("externalName", "")
        
        return service_info
    
    def _extract_deployment_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """从Deployment资源JSON中提取关键信息
        
        Args:
            data: Deployment资源的JSON数据
            
        Returns:
            提取的Deployment信息
        """
        metadata = data.get("metadata", {})
        spec = data.get("spec", {})
        status = data.get("status", {})
        
        # 提取基本信息
        deployment_info = {
            "kind": "Deployment",
            "name": metadata.get("name", ""),
            "namespace": metadata.get("namespace", "default"),
            "creation_time": metadata.get("creationTimestamp", ""),
            "labels": metadata.get("labels", {}),
            "replicas": spec.get("replicas", 0),
            "strategy": spec.get("strategy", {}).get("type", "RollingUpdate"),
            "selector": spec.get("selector", {}).get("matchLabels", {})
        }
        
        # 提取Pod模板信息
        template = spec.get("template", {})
        if template:
            deployment_info["pod_template"] = {
                "labels": template.get("metadata", {}).get("labels", {}),
                "containers": []
            }
            
            # 提取容器信息
            for container in template.get("spec", {}).get("containers", []):
                container_info = {
                    "name": container.get("name", ""),
                    "image": container.get("image", ""),
                    "ports": container.get("ports", []),
                    "resources": container.get("resources", {})
                }
                deployment_info["pod_template"]["containers"].append(container_info)
        
        # 提取状态信息
        deployment_info["status"] = {
            "replicas": status.get("replicas", 0),
            "ready_replicas": status.get("readyReplicas", 0),
            "updated_replicas": status.get("updatedReplicas", 0),
            "available_replicas": status.get("availableReplicas", 0),
            "unavailable_replicas": status.get("unavailableReplicas", 0),
            "conditions": status.get("conditions", [])
        }
        
        return deployment_info
    
    def _parse_general_output(self, output: str) -> Dict[str, Any]:
        """解析通用命令输出
        
        Args:
            output: 命令输出文本
            
        Returns:
            解析后的信息
        """
        # 对于无法特定解析的输出，提供基本处理
        lines = output.strip().split('\n')
        
        # 检查是否是表格输出
        if len(lines) > 1 and re.search(r'\s{2,}', lines[0]):
            # 可能是表格输出，尝试提取表头和数据
            header = re.split(r'\s{2,}', lines[0].strip())
            items = []
            
            for line in lines[1:]:
                if line.strip():
                    values = re.split(r'\s{2,}', line.strip())
                    item = {}
                    for i, value in enumerate(values):
                        if i < len(header):
                            item[header[i].lower()] = value
                        else:
                            # 处理超出表头的值
                            item[f"column_{i}"] = value
                    items.append(item)
            
            return {"items": items, "header": header}
        
        # 如果不是表格，返回原始文本和行数
        return {
            "raw_output": output,
            "line_count": len(lines),
            "first_line": lines[0] if lines else ""
        }
    
    def _identify_issues(self, output: str, command: str) -> Tuple[List[str], List[str]]:
        """识别输出中的潜在问题
        
        Args:
            output: 命令输出文本
            command: 执行的命令
            
        Returns:
            (问题列表, 建议列表)的元组
        """
        issues = []
        suggestions = []
        
        # 检查常见错误模式
        for pattern, description in self.error_patterns.items():
            if pattern in output:
                issues.append(f"{pattern}: {description}")
                
                # 根据错误类型提供建议
                if pattern == "ImagePullBackOff" or pattern == "ErrImagePull":
                    suggestions.append("检查镜像名称是否正确")
                    suggestions.append("确认是否有权限访问私有镜像仓库")
                    suggestions.append("检查网络连接是否正常")
                elif pattern == "CrashLoopBackOff":
                    suggestions.append("查看容器日志以获取更多信息: kubectl logs <pod-name>")
                    suggestions.append("检查容器的启动命令和参数是否正确")
                elif pattern == "Pending":
                    suggestions.append("检查集群资源是否充足: kubectl describe nodes")
                    suggestions.append("检查Pod的资源请求是否过高")
                elif pattern in ["Forbidden", "Unauthorized"]:
                    suggestions.append("检查RBAC权限设置")
                    suggestions.append("确认使用的ServiceAccount是否有足够权限")
        
        # 检查日志中的错误模式
        if "logs" in command:
            # 检查是否有错误信息
            if re.search(r'error|exception|fail|fatal', output, re.IGNORECASE):
                issues.append("日志中包含错误信息")
                suggestions.append("分析日志中的错误信息，查找根本原因")
            
            # 检查是否有OOM (Out of Memory)错误
            if re.search(r'out of memory|OOMKilled', output, re.IGNORECASE):
                issues.append("容器可能遇到内存不足问题")
                suggestions.append("增加容器的内存限制")
                suggestions.append("检查应用程序是否存在内存泄漏")
        
        # 检查节点状态（针对get nodes命令）
        if "get nodes" in command:
            if "NotReady" in output:
                issues.append("存在NotReady状态的节点")
                suggestions.append("检查节点的状态: kubectl describe node <node-name>")
                suggestions.append("查看节点上的kubelet日志")
        
        # 检查PVC状态（针对get pvc命令）
        if "get pvc" in command or "get persistentvolumeclaims" in command:
            if "Pending" in output:
                issues.append("存在Pending状态的PVC")
                suggestions.append("检查存储类是否可用: kubectl get storageclass")
                suggestions.append("确认是否有足够的存储资源")
        
        # 如果没有发现具体问题但命令成功执行
        if not issues and "No resources found" in output:
            issues.append("未找到资源")
            if "namespace" in command:
                suggestions.append("检查命名空间是否正确")
            suggestions.append("检查资源名称是否正确")
        
        return issues, suggestions


def analyze_kubectl_result(command_result, analyzer=None):
    """分析kubectl命令执行结果的便捷函数
    
    Args:
        command_result: 命令执行结果字典
        analyzer: 可选的ResultAnalyzer实例，如果为None则创建新实例
        
    Returns:
        分析结果字典
    """
    if analyzer is None:
        analyzer = ResultAnalyzer()
    
    return analyzer.analyze(command_result)


def extract_key_info(analysis_result):
    """从分析结果中提取关键信息的便捷函数
    
    Args:
        analysis_result: 分析结果字典
        
    Returns:
        关键信息摘要字典
    """
    summary = {
        "success": analysis_result.get("success", False),
        "issues": analysis_result.get("potential_issues", []),
        "suggestions": analysis_result.get("suggestions", [])
    }
    
    # 提取资源信息
    extracted_info = analysis_result.get("extracted_info", {})
    
    # 处理Pod信息
    if "pods" in extracted_info:
        pods_summary = []
        for pod in extracted_info["pods"]:
            pod_info = {
                "name": pod.get("name", ""),
                "status": pod.get("status", ""),
                "ready": pod.get("ready", "")
            }
            pods_summary.append(pod_info)
        summary["pods"] = pods_summary
    
    # 处理Service信息
    if "services" in extracted_info:
        services_summary = []
        for svc in extracted_info["services"]:
            svc_info = {
                "name": svc.get("name", ""),
                "type": svc.get("type", ""),
                "cluster_ip": svc.get("cluster_ip", ""),
                "external_ip": svc.get("external_ip", "")
            }
            services_summary.append(svc_info)
        summary["services"] = services_summary
    
    # 处理日志分析
    if "error_count" in extracted_info:
        summary["log_analysis"] = {
            "error_count": extracted_info.get("error_count", 0),
            "warning_count": extracted_info.get("warning_count", 0),
            "error_samples": extracted_info.get("error_samples", [])
        }
    
    return summary


if __name__ == "__main__":
    # 简单的测试代码
    test_output = """
    NAME                     READY   STATUS    RESTARTS   AGE
    nginx-6799fc88d8-8z4vk   1/1     Running   0          10h
    redis-78b66d9b99-vj9nx   0/1     CrashLoopBackOff   3          5m
    """
    
    test_result = {
        "command": "kubectl get pods",
        "output": test_output,
        "success": True
    }
    
    analyzer = ResultAnalyzer()
    analysis = analyzer.analyze(test_result)
    
    print(json.dumps(analysis, indent=2))