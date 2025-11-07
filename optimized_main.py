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
from pathlib import Path

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
        # 确保所有值都是字符串类型
        html_url = str(item.get('html_url', ''))
        description = str(item.get('description', ''))
        cve_match = re.search(regex, html_url + description)
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
    """初始化每日报告文件，与main.py保持一致的路径结构"""
    # 创建日期目录
    today = datetime.now()
    year = today.year
    week_number = today.strftime("%W")
    month = today.strftime("%m")
    day = today.strftime("%d")
    
    # 创建目录结构 /reports/weekly/YYYY-W-mm-dd
    dir_path = os.path.join(PROJECT_ROOT, f"docs/reports/weekly/{year}-W{week_number}-{month}-{day}")
    Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    # 创建每日报告文件
    file_path = os.path.join(dir_path, f"daily_{date_str}.md")
    
    # 写入头部
    newline = f"""# 每日 情报速递 报告 ({date_str})

> Automatic monitor Github CVE using Github Actions 

## 报告信息
- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **数据来源**: GitHub CVE 数据库

## 今日 情报速递

| CVE | 相关仓库（poc/exp） | 描述 | 日期 |
|:---|:---|:---|:---|
"""
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(newline)
    
    return file_path

# 更新索引
def update_daily_index():
    """更新每日 情报速递 报告索引文件，与main.py保持一致"""
    data_dir = Path(os.path.join(PROJECT_ROOT, "docs/reports/weekly"))
    if not data_dir.exists():
        return
    
    # 创建索引文件
    index_path = data_dir / "index.md"
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write("# 每日 情报速递 报告索引\n\n")
        f.write("> Automatic monitor Github CVE using Github Actions\n\n")
        f.write("## 可用报告\n\n")
    
    # 遍历所有日期目录
    date_dirs = sorted([d for d in data_dir.glob("*-W*-*-*")], reverse=True)
    
    for date_dir in date_dirs:
        dir_name = date_dir.name
        with open(index_path, 'a', encoding='utf-8') as f:
            f.write(f"### {dir_name}\n\n")
        
        # 遍历该目录下的所有daily报告
        daily_files = sorted([f for f in date_dir.glob("daily_*.md")], reverse=True)
        
        for daily_file in daily_files:
            file_name = daily_file.name
            relative_path = f"data/{date_dir.name}/{file_name}"
            date_str = file_name.replace("daily_", "").replace(".md", "")
            
            # 格式化日期显示
            try:
                formatted_date = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}"
            except:
                formatted_date = date_str
            
            # 使用markdown-viewer.html来渲染Markdown文件
            viewer_link = f"../../markdown-viewer.html?file=../{date_dir.name}/{file_name}"
            with open(index_path, 'a', encoding='utf-8') as f:
                f.write(f"- [{formatted_date} 每日报告]({viewer_link})\n")
        
        with open(index_path, 'a', encoding='utf-8') as f:
            f.write("\n")
    
    # 更新侧边栏，添加每日报告链接
    update_sidebar()

def update_sidebar():
    """更新侧边栏，添加每日报告链接"""
    sidebar_path = Path(os.path.join(PROJECT_ROOT, "docs/_sidebar.md"))
    if not sidebar_path.exists():
        return
    
    # 读取现有侧边栏内容
    with open(sidebar_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 检查是否已有每日报告链接
    daily_report_exists = False
    for line in lines:
        if "每日报告" in line:
            daily_report_exists = True
            break
    
    # 如果没有每日报告链接，添加到侧边栏
    if not daily_report_exists:
        # 找到合适的位置插入链接
        new_lines = []
        for line in lines:
            new_lines.append(line)
            # 在主页链接后添加每日报告链接
            if "- [主页](README.md)" in line or "- [Home](README.md)" in line:
                new_lines.append("- [每日报告](markdown-viewer.html?file=reports/weekly/index.md)\n")
        
        # 写回文件
        with open(sidebar_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

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
    original_today_list_len = 0  # 初始化原始长度计数器
    
    if items:
        # 批量处理数据库
        sorted_data = db_match(items)
        if sorted_data:
            # 快速筛选当日数据
            for entry in sorted_data:
                try:
                    created_at = entry.get("created_at", "")
                    if created_at:
                        created_date_str = created_at.split('T')[0] if "T" in created_at else created_at.split()[0]
                        if created_date_str == today_str:
                            today_list.append(entry)
                            original_today_list_len += 1  # 增加原始长度计数
                except Exception:
                    pass
    
    # 如果没有当日数据，从数据库获取最近的记录
    if not today_list:
        try:
            cur = db.cursor()
            cur.execute("SELECT * FROM CVE_DB ORDER BY created_at DESC LIMIT 10;")
            recent_records = cur.fetchall()
            
            for row in recent_records:
                # 确保所有字段都是字符串类型
                today_list.append({
                    "cve": str(row[5]) if row[5] else "CVE Not Found",
                    "full_name": str(row[1]) if row[1] else "",
                    "description": str(row[2]) if row[2] else "",
                    "url": str(row[3]) if row[3] else "",
                    "created_at": str(row[4]) if row[4] else ""
                })
        except Exception:
            pass
    
    # 写入每日报告
    if today_list:
        # 记录原始today_list长度
        original_today_list_len = len(today_list)
        print(f"生成当日 情报速递 报告，共 {len(today_list)} 条记录")
        
        # 写入每日报告（过滤掉CVE NOT FOUND的记录）
        valid_today_list = []
        for entry in today_list:
            cve = str(entry.get('cve', '')).upper()
            if cve != "CVE NOT FOUND":
                valid_today_list.append(entry)
        
        for entry in valid_today_list:
            cve = str(entry.get('cve', '')).upper()
            full_name = str(entry.get('full_name', ''))
            description = str(entry.get('description', '')).replace('|', '-')
            url = str(entry.get('url', ''))
            created_at = str(entry.get('created_at', ''))

            newline = f"| [{cve}](https://www.cve.org/CVERecord?id={cve}) | [{full_name}]({url}) | {description} | {created_at}|\n"

            # 写入每日报告文件
            try:
                with open(daily_file_path, 'a', encoding='utf-8') as f:
                    f.write(newline)
            except Exception:
                pass  # 静默失败
        
        # 如果是使用最近记录，则在报告中增加说明
        if original_today_list_len == 0:
            try:
                with open(daily_file_path, 'a', encoding='utf-8') as f:
                    f.write("\n\n> 由于没有获取到当日数据，使用近7天记录\n\n")
            except Exception:
                pass  # 静默失败
    
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