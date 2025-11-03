#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub CVE Monitor - Wiki统计数据生成脚本（优化版）"""

import os
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

def get_project_root():
    """
    获取项目根目录的绝对路径，处理嵌套目录情况
    解决GitHub Actions环境中的目录嵌套问题
    """
    # 获取当前文件所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 逐级向上查找，直到找到项目的标志性文件或目录
    test_dir = current_dir
    max_depth = 5  # 设置最大查找深度
    
    for _ in range(max_depth):
        # 检查是否存在项目标志性文件/目录
        if os.path.exists(os.path.join(test_dir, 'main.py')) and \
           os.path.exists(os.path.join(test_dir, 'docs')) and \
           os.path.exists(os.path.join(test_dir, 'db')):
            return test_dir
        
        # 向上一级目录
        parent_dir = os.path.dirname(test_dir)
        if parent_dir == test_dir:  # 到达文件系统根目录
            break
        test_dir = parent_dir
    
    # 如果没有找到，返回当前脚本所在目录的父目录（原始逻辑）
    return os.path.dirname(current_dir)

# API请求配置
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
API_TIMEOUT = 5  # 秒
API_RETRY_MAX = 3
API_RETRY_DELAY = 2  # 秒

def load_daily_summary(summary_path):
    """加载每日汇总数据"""
    try:
        with open(summary_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ 汇总文件未找到: {summary_path}")
        return None
    except json.JSONDecodeError:
        print(f"❌ 汇总文件格式错误: {summary_path}")
        return None

def load_daily_files(daily_dir, days=30):
    """加载最近N天的每日JSON文件 - 修改为读取目录中所有JSON文件"""
    daily_files = []
    
    # 首先尝试直接读取目录中的所有JSON文件
    try:
        for filename in os.listdir(daily_dir):
            if filename.endswith('.json') and filename != 'daily_summary.json':
                file_path = os.path.join(daily_dir, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # 确保数据包含必要的date字段
                        if 'date' in data and 'cves' in data:
                            daily_files.append(data)
                except Exception as e:
                    print(f"⚠️  无法读取文件 {file_path}: {e}")
        
        print(f"📁 直接读取到 {len(daily_files)} 个JSON文件")
        
        # 如果没有读取到文件，回退到原始的基于日期的方法
        if not daily_files:
            print("⚠️  未找到JSON文件，尝试基于当前日期查找")
            today = datetime.now().date()
            
            for i in range(days):
                target_date = today - timedelta(days=i)
                date_str = target_date.isoformat()
                file_path = os.path.join(daily_dir, f"{date_str}.json")
                
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            daily_files.append(data)
                    except Exception as e:
                        print(f"⚠️  无法读取文件 {file_path}: {e}")
    except Exception as e:
        print(f"⚠️  读取目录失败: {e}")
    
    # 按日期排序
    return sorted(daily_files, key=lambda x: x.get('date', ''))

def get_cve_details(cve_id):
    """跳过CVE API调用以提高性能"""
    return None

def analyze_cve_types(cve_data):
    """简化的CVE类型分析，仅使用关键词匹配"""
    # 简化的关键词分类
    type_patterns = {
        '远程代码执行': [r'RCE', r'remote code execution', r'远程代码执行'],
        '注入攻击': [r'injection', r'注入', r'SQL', r'XSS', r'CSRF'],
        '提权漏洞': [r'privilege escalation', r'提权', r'权限提升'],
        '信息泄露': [r'info disclosure', r'information disclosure', r'信息泄露'],
        '路径遍历': [r'path traversal', r'traversal', r'目录遍历'],
        '拒绝服务': [r'DoS', r'denial of service', r'拒绝服务'],
        '认证绕过': [r'bypass', r'authentication bypass', r'绕过'],
        '缓冲区溢出': [r'buffer overflow', r'缓冲区溢出'],
        '其他': []  # 默认分类
    }
    
    type_count = defaultdict(int)
    
    for day_data in cve_data:
        for cve in day_data.get('cves', []):
            description = cve.get('description', '').lower()
            classified = False
            
            # 仅使用关键词匹配
            for cve_type, patterns in type_patterns.items():
                if cve_type == '其他':
                    continue
                for pattern in patterns:
                    if re.search(pattern, description, re.IGNORECASE):
                        type_count[cve_type] += 1
                        classified = True
                        break
                if classified:
                    break
            
            if not classified:
                type_count['其他'] += 1
    
    # 转换为排序后的列表
    return sorted(type_count.items(), key=lambda x: x[1], reverse=True)

def analyze_poc_exp(cve_data):
    """简化的POC/EXP分析"""
    poc_keywords = ['poc', 'proof of concept', '验证']
    exp_keywords = ['exp', 'exploit', '漏洞利用', '利用代码']
    
    poc_count = 0
    exp_count = 0
    both_count = 0
    neither_count = 0
    
    for day_data in cve_data:
        for cve in day_data.get('cves', []):
            # 简化内容提取
            content = ' '.join([
                cve.get('repo_info', '').lower(),
                cve.get('description', '').lower(),
                cve.get('repo_name', '').lower()
            ])
            
            # 简单判断
            has_poc = any(keyword in content for keyword in poc_keywords)
            has_exp = any(keyword in content for keyword in exp_keywords)
            
            # 统计结果
            if has_poc and has_exp:
                both_count += 1
            elif has_poc:
                poc_count += 1
            elif has_exp:
                exp_count += 1
            else:
                neither_count += 1
    
    return {
        '仅POC': poc_count,
        '仅EXP': exp_count,
        'POC+EXP': both_count,
        '无POC/EXP': neither_count
    }

def calculate_trends(growth_stats, days=7):
    """计算趋势数据"""
    if len(growth_stats) < days:
        return growth_stats
    
    # 确保返回的数据结构一致，处理键名可能不匹配的情况
    result = []
    for item in growth_stats[-days:]:
        # 处理可能的键名差异
        formatted_item = {
            'date': item.get('date', ''),
            'daily_count': item.get('daily_count', item.get('count', 0)),
            'cumulative_total': item.get('cumulative_total', item.get('cumulative', 0)),
            'growth_rate': item.get('growth_rate', 0)
        }
        result.append(formatted_item)
    
    return result

def analyze_vendor_product_stats(cve_data):
    """跳过API调用，返回空统计"""
    return {
        'vendors': {},
        'products': {},
        'vendor_product_pairs': {}
    }

def analyze_fingerprint_stats(cve_data):
    """简化的技术栈统计"""
    # 简化的技术栈模式
    simple_patterns = {
        'Java': [r'java', r'spring'],
        'Python': [r'python', r'django', r'flask'],
        'PHP': [r'php', r'thinkphp'],
        'JavaScript': [r'javascript', r'js', r'node', r'react', r'vue'],
        'Windows': [r'windows'],
        'Linux': [r'linux'],
        '其他': []
    }
    
    fingerprint_count = defaultdict(int)
    
    for day_data in cve_data:
        for cve in day_data.get('cves', []):
            content = ' '.join([
                cve.get('description', '').lower(),
                cve.get('repo_name', '').lower()
            ])
            
            matched = False
            for tech, patterns in simple_patterns.items():
                if tech == '其他':
                    continue
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        fingerprint_count[tech] += 1
                        matched = True
                        break
                if matched:
                    break
            
            if not matched:
                fingerprint_count['其他'] += 1
    
    return sorted(fingerprint_count.items(), key=lambda x: x[1], reverse=True)

def generate_stats_file(summary, daily_files, output_path):
    """简化的统计数据生成"""
    # 获取基本统计信息
    cve_types = analyze_cve_types(daily_files)
    poc_exp_stats = analyze_poc_exp(daily_files)
    fingerprint_stats = analyze_fingerprint_stats(daily_files)
    
    # 计算简单趋势（从daily_files直接计算）
    trends = []
    cumulative = 0
    for day in sorted(daily_files[-7:], key=lambda x: x.get('date', '')):
        daily_count = len(day.get('cves', []))
        cumulative += daily_count
        trends.append({
            'date': day.get('date', ''),
            'daily_count': daily_count,
            'cumulative_total': cumulative,
            'growth_rate': 0  # 简化计算
        })
    
    # 准备简化的统计数据
    stats = {
        'generated_at': datetime.now().isoformat(),
        'summary': {
            'total_cves': summary.get('total_cves', 0),
            'date_range': summary.get('date_range', {})
        },
        'cve_types': dict(cve_types),
        'poc_exp_stats': poc_exp_stats,
        'fingerprint_stats': dict(fingerprint_stats[:10]),
        'trends': trends
    }
    
    # 保存统计文件（无缩进以提高速度）
    try:
        # 确保输出目录存在
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False)
        return stats
    except Exception:
        return None

def generate_wiki_md(stats, output_md_path):
    """简化的Markdown生成"""
    if not stats:
        return False
    
    # 提取基本数据
    summary = stats.get('summary', {})
    cve_types = stats.get('cve_types', {})
    poc_exp_stats = stats.get('poc_exp_stats', {})
    fingerprint_stats = stats.get('fingerprint_stats', {})
    trends = stats.get('trends', [])
    
    # 生成简化的Markdown内容
    md_content = f"""
# 统计数据

## 总体统计
- **总CVE记录数**: {summary.get('total_cves', 0):,}
- **监测周期**: {summary.get('date_range', {}).get('start', '暂无')} 至 {summary.get('date_range', {}).get('end', '暂无')}
- **数据更新时间**: {datetime.now().strftime('%Y-%m-%d')}

## 每日增长趋势

| 日期 | 每日新增 | 累计总数 |
|:---|:---|:---|
"""
    
    # 添加简单趋势表格
    for trend in reversed(trends[-7:]):  # 仅显示最近7天
        md_content += f"| {trend['date']} | {trend['daily_count']} | {trend['cumulative_total']:,} |\n"
    
    # 添加简化的CVE类型统计
    if cve_types:
        md_content += "\n## CVE分类统计\n\n| 类型 | 数量 |\n|:---|:---|\n"
        for cve_type, count in list(cve_types.items())[:8]:  # 仅显示前8个
            md_content += f"| {cve_type} | {count:,} |\n"
    
    # 保存Markdown文件
    try:
        output_dir = os.path.dirname(output_md_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        return True
    except Exception:
        return False

def main():
    # 获取项目根目录的绝对路径
    PROJECT_ROOT = get_project_root()
    
    # 设置默认路径为绝对路径
    default_summary = os.path.join(PROJECT_ROOT, 'docs', 'data', 'daily', 'daily_summary.json')
    default_daily_dir = os.path.join(PROJECT_ROOT, 'docs', 'data', 'daily')
    default_output_json = os.path.join(PROJECT_ROOT, 'docs', 'data', 'statistics', 'wiki_stats.json')
    default_output_md = os.path.join(PROJECT_ROOT, 'wiki_content', '统计数据.md')
    
    parser = argparse.ArgumentParser(description='Wiki统计数据生成器')
    parser.add_argument('--summary', '-s', default=default_summary)
    parser.add_argument('--daily-dir', '-d', default=default_daily_dir)
    parser.add_argument('--output-json', '-j', default=default_output_json)
    parser.add_argument('--output-md', '-m', default=default_output_md)
    parser.add_argument('--days', '-n', type=int, default=14)  # 减少默认统计天数
    
    args = parser.parse_args()
    
    # 加载汇总数据
    summary = load_daily_summary(args.summary)
    if not summary:
        return 1
    
    # 加载每日数据（减少加载天数）
    daily_files = load_daily_files(args.daily_dir, min(args.days, 14))
    
    # 生成统计数据
    stats = generate_stats_file(summary, daily_files, args.output_json)
    if not stats:
        return 1
    
    # 生成Wiki Markdown
    return 0 if generate_wiki_md(stats, args.output_md) else 1

if __name__ == '__main__':
    exit(main())