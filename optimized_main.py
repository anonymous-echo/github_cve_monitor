import os
import re
import sys
import time
import json
import datetime
import requests
import subprocess
import sqlite3
from datetime import datetime, date

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# 数据库初始化
def init_db():
    """快速初始化数据库"""
    global db
    db_path = os.path.join(PROJECT_ROOT, 'cve.db')
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS CVE_DB (
        id TEXT PRIMARY KEY,
        full_name TEXT,
        description TEXT,
        url TEXT,
        created_at TEXT,
        cve TEXT
    )
    ''')
    db.commit()

# 批量数据库操作
def db_match(items):
    """优化的数据库匹配函数，使用批量操作"""
    if not items:
        return []
    
    # 提取所有ID
    all_ids = [item['id'] for item in items]
    
    # 批量查询已存在的ID
    placeholders = ','.join(['?' for _ in all_ids])
    cur = db.cursor()
    cur.execute(f"SELECT id FROM CVE_DB WHERE id IN ({placeholders})", all_ids)
    existing_ids = {row[0] for row in cur.fetchall()}
    
    # 正则表达式用于提取CVE
    regex = r'CVE-\d{4}-\d+'
    
    # 准备返回列表和批量插入数据
    r_list = []
    to_insert = []
    
    for item in items:
        if item['id'] in existing_ids:
            continue
        
        # 提取CVE
        cve = "CVE Not Found"
        cve_match = re.search(regex, item.get('html_url', '') + item.get('description', ''))
        if cve_match:
            cve = cve_match.group().replace('_', '-')
        
        # 构建数据对象
        entry = {
            "id": item['id'],
            "full_name": item.get('full_name', ''),
            "description": item.get('description', '') or 'no description',
            "url": item.get('html_url', ''),
            "created_at": item.get('created_at', ''),
            "cve": cve
        }
        r_list.append(entry)
        
        # 准备插入数据库
        to_insert.append({
            'id': entry['id'],
            'full_name': entry['full_name'],
            'description': entry['description'],
            'url': entry['url'],
            'created_at': entry['created_at'],
            'cve': entry['cve'].upper()
        })
    
    # 批量插入
    if to_insert:
        try:
            cur = db.cursor()
            cur.executemany(
                "INSERT OR IGNORE INTO CVE_DB VALUES (?, ?, ?, ?, ?, ?)",
                [(d['id'], d['full_name'], d['description'], d['url'], d['created_at'], d['cve']) for d in to_insert]
            )
            db.commit()
        except Exception:
            pass
    
    return r_list

# 快速API获取函数
def get_info(year):
    """高度优化的GitHub API获取函数"""
    BASE_URL = "https://api.github.com/search/repositories"
    
    # 最小化参数
    params = {
        "q": f"CVE-{year} created:{year}-01-01..{year}-12-31 sort:updated-desc",
        "per_page": 100,
        "page": 1
    }
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "GitHub-CVE-Monitor"
    }
    
    # 添加token（如果存在）
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    
    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("items", [])[:30]  # 限制返回数量
    except Exception:
        pass
    
    return []

# 初始化每日文件
def init_daily_file(date_str):
    """简化的每日文件初始化"""
    daily_dir = os.path.join(PROJECT_ROOT, 'docs', 'data', 'daily')
    os.makedirs(daily_dir, exist_ok=True)
    
    file_path = os.path.join(daily_dir, f'{date_str}.md')
    
    # 快速写入头部
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(f"# 每日 CVE 情报速递 - {date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}\n\n")
        f.write("## 今日新增 CVE 漏洞信息\n\n")
        f.write("| CVE | 相关仓库（poc/exp） | 描述 | 日期 |\n")
        f.write("|:---|:---|:---|:---|\n")
    
    return file_path

# 更新索引
def update_daily_index():
    """简化的索引更新"""
    index_path = os.path.join(PROJECT_ROOT, 'docs', 'index.md')
    daily_dir = os.path.join(PROJECT_ROOT, 'docs', 'data', 'daily')
    
    # 快速列出所有文件
    try:
        files = [f for f in os.listdir(daily_dir) if f.endswith('.md')]
        files.sort(reverse=True)
        
        # 简单重写索引
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write("# GitHub CVE 情报速递\n\n")
            f.write("## 每日报告索引\n\n")
            for file in files[:30]:  # 限制数量
                date_str = file.replace('.md', '')
                display_date = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
                f.write(f"- [{display_date}](data/daily/{file})\n")
    except Exception:
        pass

# 主函数
def main():
    """高性能主函数"""
    # 快速初始化数据库
    init_db()
    
    # 获取当前日期
    today = datetime.now()
    date_str = today.strftime("%Y%m%d")
    today_str = today.strftime("%Y-%m-%d")
    year = today.year
    
    # 初始化每日文件
    daily_file_path = init_daily_file(date_str)
    
    # 仅获取当年数据，1页，快速返回
    items = get_info(year)
    today_list = []
    
    if items:
        # 批量处理数据库
        sorted_data = db_match(items)
        if sorted_data:
            # 快速筛选当日数据
            for entry in sorted_data:
                try:
                    created_date_str = entry["created_at"].split('T')[0] if "T" in entry["created_at"] else entry["created_at"].split()[0]
                    if created_date_str == today_str:
                        today_list.append(entry)
                except Exception:
                    pass
    
    # 如果没有当日数据，从数据库获取最近的记录
    if not today_list:
        try:
            cur = db.cursor()
            cur.execute("SELECT * FROM CVE_DB ORDER BY created_at DESC LIMIT 10;")
            recent_records = cur.fetchall()
            
            for row in recent_records:
                today_list.append({
                    "cve": row[5],
                    "full_name": row[1],
                    "description": row[2],
                    "url": row[3],
                    "created_at": row[4]
                })
        except Exception:
            pass
    
    # 批量写入每日报告
    if today_list:
        try:
            # 过滤并限制数量
            valid_entries = [e for e in today_list if e["cve"].upper() != "CVE NOT FOUND"][:5]
            
            # 批量构建内容
            lines = []
            for entry in valid_entries:
                cve = entry["cve"]
                full_name = entry["full_name"]
                description = entry["description"].replace('|','-')[:80]
                url = entry["url"]
                created_at = entry["created_at"]
                
                lines.append(f"| [{cve.upper()}](https://www.cve.org/CVERecord?id={cve.upper()}) | [{full_name}]({url}) | {description} | {created_at}|\n")
            
            # 一次性写入
            with open(daily_file_path, 'a', encoding='utf-8') as f:
                f.writelines(lines)
        except Exception:
            pass
    
    # 简化的统计生成 - 只运行统计脚本，使用7天参数
    try:
        stats_script = os.path.join(PROJECT_ROOT, 'scripts/generate_wiki_stats.py')
        subprocess.run(
            [sys.executable, stats_script, "--days", "7"],
            timeout=240,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        pass
    
    # 更新索引
    update_daily_index()
    
    # 关闭数据库连接
    db.close()
    return "success"

if __name__ == "__main__":
    main()