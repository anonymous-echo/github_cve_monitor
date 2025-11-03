#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub CVE Monitor - 增强版每日数据生成脚本

功能:
1. 从README.md解析CVE数据
2. 按日期分组生成完整的每日JSON文件
3. 填补缺失日期的空JSON文件
4. 生成详细的统计汇总
5. 修复增长率计算问题
"""

import os
import re
import json
import argparse
from datetime import datetime, date, timedelta
from collections import defaultdict

def parse_readme(readme_path):
    """解析README.md文件，提取CVE数据"""
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ README文件未找到: {readme_path}")
        return []
    
    # 查找表格数据开始位置
    table_start = content.find('| CVE | 相关仓库')
    if table_start == -1:
        print("❌ 未找到CVE表格数据")
        return []
    
    # 提取表格部分
    table_section = content[table_start:]
    lines = table_section.split('\n')[2:]  # 跳过表头
    
    cve_data = []
    print(f"📋 开始解析CVE数据...")
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or not line.startswith('|'):
            continue
            
        # 分割表格列
        cols = [col.strip() for col in line.split('|') if col.strip()]
        if len(cols) < 4:
            continue
            
        try:
            # 提取CVE ID - 支持多种格式
            cve_match = re.search(r'CVE[_-]?\d{4}[_-]?\d{4,7}', cols[0])
            if not cve_match:
                continue
            cve_id = cve_match.group().replace('_', '-')
            
            # 提取仓库信息
            repo_info = cols[1]
            
            # 提取描述
            description = cols[2]
            
            # 提取日期 - 支持多种格式
            date_str = cols[3].strip()
            date_patterns = [
                r'(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}Z',  # ISO格式
                r'(\d{4}-\d{2}-\d{2})',  # 简单日期格式
                r'(\d{4})/(\d{2})/(\d{2})',  # 斜杠格式
            ]
            
            parsed_date = None
            for pattern in date_patterns:
                date_match = re.search(pattern, date_str)
                if date_match:
                    try:
                        if '/' in pattern:
                            # 处理斜杠格式
                            year, month, day = date_match.groups()
                            parsed_date = date(int(year), int(month), int(day))
                        else:
                            parsed_date = datetime.strptime(date_match.group(1), '%Y-%m-%d').date()
                        break
                    except ValueError:
                        continue
            
            if not parsed_date:
                print(f"⚠️  第{line_num}行日期格式无法解析: {date_str}")
                continue
            
            cve_data.append({
                'cve_id': cve_id,
                'repo_info': repo_info,
                'description': description,
                'date': parsed_date.isoformat(),
                'raw_date': date_str
            })
            
            if line_num % 1000 == 0:
                print(f"📊 已处理 {line_num} 行，提取到 {len(cve_data)} 个CVE")
                
        except Exception as e:
            print(f"⚠️  第{line_num}行解析失败: {e}")
            continue
    
    print(f"✅ 解析完成！总计提取到 {len(cve_data)} 个CVE")
    return cve_data

def group_by_date(cve_data):
    """按日期分组CVE数据"""
    daily_data = defaultdict(list)
    
    for cve in cve_data:
        date_key = cve['date']
        daily_data[date_key].append(cve)
    
    # 转换为普通字典并排序
    sorted_daily = dict(sorted(daily_data.items()))
    
    print(f"📅 数据分组完成:")
    print(f"   - 日期范围: {min(sorted_daily.keys())} 到 {max(sorted_daily.keys())}")
    print(f"   - 总天数: {len(sorted_daily)} 天")
    
    return sorted_daily

def fill_missing_dates(daily_data, start_date=None, end_date=None):
    """填补缺失的日期，生成空的JSON文件"""
    if not daily_data:
        return daily_data
    
    # 确定日期范围
    existing_dates = list(daily_data.keys())
    if start_date is None:
        start_date = datetime.strptime(min(existing_dates), '%Y-%m-%d').date()
    if end_date is None:
        end_date = datetime.strptime(max(existing_dates), '%Y-%m-%d').date()
    
    print(f"🔍 填补缺失日期: {start_date} 到 {end_date}")
    
    filled_data = {}
    current_date = start_date
    added_count = 0
    
    while current_date <= end_date:
        date_str = current_date.isoformat()
        
        if date_str in daily_data:
            filled_data[date_str] = daily_data[date_str]
        else:
            # 创建空的日期数据
            filled_data[date_str] = []
            added_count += 1
        
        current_date += timedelta(days=1)
    
    print(f"✅ 填补了 {added_count} 个缺失日期")
    return filled_data

def generate_json_files(daily_data, output_dir):
    """生成每日JSON文件"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"📁 创建输出目录: {output_dir}")
    
    generated_files = []
    
    for date_str, cves in daily_data.items():
        # 文件名格式: YYYY-MM-DD.json
        filename = f"{date_str}.json"
        filepath = os.path.join(output_dir, filename)
        
        # 准备JSON数据
        json_data = {
            'date': date_str,
            'count': len(cves),
            'cves': cves,
            'generated_at': datetime.now().isoformat(),
            'metadata': {
                'total_cves': len(cves),
                'date_range': date_str,
                'source': 'README.md',
                'script_version': '2.0'
            }
        }
        
        # 写入JSON文件
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            
            generated_files.append({
                'file': filename,
                'date': date_str,
                'count': len(cves),
                'path': filepath
            })
            
        except Exception as e:
            print(f"❌ 生成文件失败 {filename}: {e}")
    
    return generated_files

def calculate_growth_stats(generated_files):
    """计算增长统计信息"""
    if len(generated_files) < 2:
        return []
    
    # 按日期排序
    sorted_files = sorted(generated_files, key=lambda x: x['date'])
    growth_stats = []
    cumulative_total = 0
    
    for i, file_data in enumerate(sorted_files):
        cumulative_total += file_data['count']
        
        # 计算增长率
        if i > 0:
            prev_count = sorted_files[i-1]['count']
            if prev_count > 0:
                growth_rate = ((file_data['count'] - prev_count) / prev_count) * 100
            else:
                growth_rate = 0 if file_data['count'] == 0 else 100
        else:
            growth_rate = 0
        
        growth_stats.append({
            'date': file_data['date'],
            'daily_count': file_data['count'],
            'cumulative_total': cumulative_total,
            'growth_rate': round(growth_rate, 2)
        })
    
    return growth_stats

def generate_summary(generated_files, output_dir):
    """生成详细的汇总信息"""
    # 计算增长统计
    growth_stats = calculate_growth_stats(generated_files)
    
    summary = {
        'generated_at': datetime.now().isoformat(),
        'script_version': '2.0',
        'total_files': len(generated_files),
        'total_cves': sum(f['count'] for f in generated_files),
        'date_range': {
            'start': min(f['date'] for f in generated_files) if generated_files else None,
            'end': max(f['date'] for f in generated_files) if generated_files else None
        },
        'statistics': {
            'avg_daily_cves': round(sum(f['count'] for f in generated_files) / len(generated_files), 2) if generated_files else 0,
            'max_daily_cves': max(f['count'] for f in generated_files) if generated_files else 0,
            'min_daily_cves': min(f['count'] for f in generated_files) if generated_files else 0,
            'empty_days': len([f for f in generated_files if f['count'] == 0]),
            'active_days': len([f for f in generated_files if f['count'] > 0])
        },
        'growth_analysis': growth_stats,
        'recent_7_days': growth_stats[-7:] if len(growth_stats) >= 7 else growth_stats,
        'recent_30_days': growth_stats[-30:] if len(growth_stats) >= 30 else growth_stats,
        'daily_stats': generated_files
    }
    
    # 保存汇总文件
    summary_path = os.path.join(output_dir, 'daily_summary.json')
    try:
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"📊 汇总文件已生成: {summary_path}")
    except Exception as e:
        print(f"❌ 生成汇总文件失败: {e}")
    
    return summary

def main():
    # 获取脚本所在目录的绝对路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    # 设置默认路径为绝对路径 - 使用小写的data目录保持一致性
    default_readme = os.path.join(project_root, 'docs', 'README.md')
    default_output = os.path.join(project_root, 'docs', 'data', 'daily')
    
    parser = argparse.ArgumentParser(description='增强版每日CVE数据生成器')
    parser.add_argument('--readme', '-r', 
                       default=default_readme,
                       help=f'README.md文件路径 (默认: {default_readme})')
    parser.add_argument('--output', '-o',
                       default=default_output,
                       help=f'输出目录 (默认: {default_output})')
    parser.add_argument('--fill-gaps', '-f',
                       action='store_true',
                       help='填补缺失的日期（生成空的JSON文件）')
    parser.add_argument('--start-date', '-s',
                       help='开始日期 (YYYY-MM-DD格式，仅在--fill-gaps时有效)')
    parser.add_argument('--end-date', '-e',
                       help='结束日期 (YYYY-MM-DD格式，仅在--fill-gaps时有效)')
    parser.add_argument('--verbose', '-v', 
                       action='store_true',
                       help='显示详细输出')
    
    args = parser.parse_args()
    
    print("🚀 GitHub CVE Monitor - 增强版每日数据生成器 v2.0")
    print("=" * 60)
    
    # 解析README
    print(f"📖 读取README文件: {args.readme}")
    cve_data = parse_readme(args.readme)
    
    if not cve_data:
        print("❌ 未提取到CVE数据，脚本退出")
        return 1
    
    # 按日期分组
    print("\n📅 按日期分组数据...")
    daily_data = group_by_date(cve_data)
    
    # 填补缺失日期（如果指定）
    if args.fill_gaps:
        print("\n🔧 填补缺失日期...")
        start_date = None
        end_date = None
        
        if args.start_date:
            try:
                start_date = datetime.strptime(args.start_date, '%Y-%m-%d').date()
            except ValueError:
                print(f"❌ 开始日期格式错误: {args.start_date}")
                return 1
        
        if args.end_date:
            try:
                end_date = datetime.strptime(args.end_date, '%Y-%m-%d').date()
            except ValueError:
                print(f"❌ 结束日期格式错误: {args.end_date}")
                return 1
        
        daily_data = fill_missing_dates(daily_data, start_date, end_date)
    
    # 生成JSON文件
    print(f"\n📝 生成JSON文件到: {args.output}")
    generated_files = generate_json_files(daily_data, args.output)
    
    # 生成汇总
    print("\n📊 生成详细汇总信息...")
    summary = generate_summary(generated_files, args.output)
    
    # 输出结果
    print("\n" + "=" * 60)
    print("✅ 处理完成！")
    print(f"📁 生成文件数: {len(generated_files)}")
    print(f"📊 总CVE数量: {summary['total_cves']}")
    print(f"📅 日期范围: {summary['date_range']['start']} 到 {summary['date_range']['end']}")
    print(f"📈 平均每日CVE: {summary['statistics']['avg_daily_cves']}")
    print(f"🎯 活跃天数: {summary['statistics']['active_days']}")
    print(f"💤 空白天数: {summary['statistics']['empty_days']}")
    
    if args.verbose and generated_files:
        print("\n📋 最近生成的文件:")
        for f in generated_files[-10:]:  # 显示最近10个文件
            print(f"   - {f['file']}: {f['count']} 个CVE")
        
        print("\n📈 最近7天增长趋势:")
        recent_growth = summary['recent_7_days']
        for day in recent_growth:
            growth_indicator = "📈" if day['growth_rate'] > 0 else "📉" if day['growth_rate'] < 0 else "➡️"
            print(f"   - {day['date']}: {day['daily_count']} 个CVE (增长率: {day['growth_rate']:+.1f}%) {growth_indicator}")
    
    return 0

if __name__ == '__main__':
    exit(main())