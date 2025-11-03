from functools import total_ordering
import requests
from peewee import *
from datetime import datetime
import html
import time
import random
import math
import re
import os
import locale
from pathlib import Path
import json
# 导入dotenv库以支持从.env文件读取环境变量
try:
    from dotenv import load_dotenv
    load_dotenv()  # 加载.env文件中的环境变量
    print("DEBUG: 已加载dotenv库并从.env文件读取环境变量")
except ImportError:
    print("DEBUG: 未安装dotenv库，跳过从.env文件读取环境变量")

# 确定项目根目录
def get_project_root():
    """
    获取项目根目录的绝对路径，处理嵌套目录情况
    解决GitHub Actions环境中的目录嵌套问题
    """
    # 获取当前文件所在目录（包含main.py的目录）
    current_file_path = os.path.abspath(__file__)
    current_dir = os.path.dirname(current_file_path)
    print(f"DEBUG: 当前文件路径: {current_file_path}")
    print(f"DEBUG: 当前目录: {current_dir}")
    
    # 情况1: 检查当前目录是否已经包含所有必要文件/目录
    if os.path.exists(os.path.join(current_dir, 'main.py')) and \
       os.path.exists(os.path.join(current_dir, 'docs')) and \
       os.path.exists(os.path.join(current_dir, 'db')):
        print(f"DEBUG: 当前目录已包含所有必要文件/目录")
        return current_dir
    
    # 情况2: 检查GitHub Actions典型嵌套结构
    # 在GitHub Actions中，代码通常在 /home/runner/work/repo_name/repo_name 中
    if 'runner' in current_dir and 'work' in current_dir:
        # 查找最后一个项目目录名
        parts = current_dir.split(os.path.sep)
        # 检查是否存在嵌套的项目目录
        for i, part in enumerate(parts):
            if part and i < len(parts) - 1 and parts[i] == parts[i+1]:
                # 找到嵌套目录，返回完整路径
                nested_path = os.path.sep.join(parts[:i+2])
                if os.path.exists(os.path.join(nested_path, 'main.py')):
                    print(f"DEBUG: 检测到GitHub Actions嵌套目录结构: {nested_path}")
                    return nested_path
    
    # 情况3: 尝试向下查找（针对GitHub Actions环境，可能当前在work目录而不是实际代码目录）
    # 检查当前目录下是否有名为github_cve_monitor的子目录
    possible_nested_dir = os.path.join(current_dir, 'github_cve_monitor')
    if os.path.exists(possible_nested_dir) and \
       os.path.exists(os.path.join(possible_nested_dir, 'main.py')) and \
       os.path.exists(os.path.join(possible_nested_dir, 'docs')) and \
       os.path.exists(os.path.join(possible_nested_dir, 'db')):
        print(f"DEBUG: 检测到向下嵌套的项目目录: {possible_nested_dir}")
        return possible_nested_dir
    
    # 情况4: 逐级向上查找
    test_dir = current_dir
    max_depth = 5  # 设置最大查找深度
    
    for depth in range(max_depth):
        # 向上一级目录
        parent_dir = os.path.dirname(test_dir)
        if parent_dir == test_dir:  # 到达文件系统根目录
            print(f"DEBUG: 到达文件系统根目录")
            break
        
        print(f"DEBUG: 向上查找层级 {depth+1}: {parent_dir}")
        
        # 检查父目录是否包含所有必要文件/目录
        if os.path.exists(os.path.join(parent_dir, 'main.py')) and \
           os.path.exists(os.path.join(parent_dir, 'docs')) and \
           os.path.exists(os.path.join(parent_dir, 'db')):
            print(f"DEBUG: 在父目录找到项目根目录: {parent_dir}")
            return parent_dir
        
        test_dir = parent_dir
    
    # 如果所有方法都失败，返回当前目录作为最后手段
    print(f"DEBUG: 无法确定项目根目录，返回当前目录作为默认值")
    return current_dir

# 获取项目根目录
PROJECT_ROOT = get_project_root()
print(f"DEBUG: 项目根目录: {PROJECT_ROOT}")


# 设置中文环境
try:
    locale.setlocale(locale.LC_ALL, 'zh_CN.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_ALL, 'Chinese_China.936')
    except:
        pass  # 如果设置失败，使用系统默认

db = SqliteDatabase(os.path.join(PROJECT_ROOT, "db/cve.sqlite"))

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)
    cve = CharField(max_length=64)

    class Meta:
        database = db

db.connect()
db.create_tables([CVE_DB])

def init_file():
    newline = "# Github CVE Monitor\n\n> Automatic monitor github cve using Github Actions \n\n Last generated : {}\n\n| CVE | 相关仓库（poc/exp） | 描述 | 日期 |\n|---|---|---|---|\n".format(datetime.now())
    with open(os.path.join(PROJECT_ROOT, 'docs/README.md'),'w', encoding='utf-8') as f:
        f.write(newline) 
    f.close()

def write_file(new_contents, overwrite=False):
    """优化的文件写入函数，减少I/O操作"""
    mode = 'w' if overwrite else 'a'
    # 使用with语句自动处理文件关闭，避免显式调用f.close()
    with open(os.path.join(PROJECT_ROOT, 'docs/README.md'), mode, encoding='utf-8') as f:
        f.write(new_contents)

def init_daily_file(date_str):
    """初始化每日报告文件"""
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

def write_daily_file(file_path, new_contents):
    """优化的每日报告写入函数，减少I/O操作"""
    # 确保文件路径正确
    if not os.path.isabs(file_path):
        file_path = os.path.join(PROJECT_ROOT, file_path)
    # 使用with语句自动处理文件关闭
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(new_contents)

def update_daily_index():
    """更新每日 情报速递 报告索引文件"""
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
            
            with open(index_path, 'a', encoding='utf-8') as f:
                f.write(f"- [{formatted_date} 每日报告]({relative_path})\n")
        
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
                new_lines.append("- [每日报告](/data/index.md)\n")
        
        # 写回文件
        with open(sidebar_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

def load_config():
    """从配置文件加载配置信息"""
    config_paths = [
        os.path.join(PROJECT_ROOT, "docs/config/config.json"),
        os.path.join(PROJECT_ROOT, "docs/data/config.json"),
        os.path.join(PROJECT_ROOT, "docs/config.json"),
        os.path.join(PROJECT_ROOT, "config.json")
    ]
    
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    return config
            except Exception as e:
                print(f"警告: 无法读取配置文件 {config_path}: {e}")
    
    return {}

def get_github_token():
    """获取GitHub Token，优先级：环境变量(.env或系统环境变量) > 配置文件"""
    # 首先检查环境变量（会自动包括从.env文件加载的变量）
    github_token = os.environ.get('GITHUB_TOKEN')
    if github_token:
        print(f"DEBUG: 从环境变量获取到GITHUB_TOKEN")
        print(f"DEBUG: Token长度: {len(github_token)}")
        # 不要打印完整的token，但可以打印前几个字符来确认
        if len(github_token) > 5:
            print(f"DEBUG: Token前缀: {github_token[:5]}...")
        return github_token
    
    # 然后检查配置文件
    config = load_config()
    github_token = config.get('github_token')
    if github_token and github_token != "your_token_here":
        print(f"DEBUG: 从配置文件获取到github_token")
        print(f"DEBUG: Token长度: {len(github_token)}")
        if len(github_token) > 5:
            print(f"DEBUG: Token前缀: {github_token[:5]}...")
        return github_token
    
    print("DEBUG: 未找到有效的GitHub Token")
    print("DEBUG: 您可以在项目根目录创建.env文件，并添加GITHUB_TOKEN=your_token_here")
    return None

def get_info(year):
    """
    获取指定年份的CVE相关GitHub仓库信息
    优化版本 - 减少API调用等待时间和不必要的处理
    """
    try:
        all_items = []
        page = 1
        # 增加无token时的批量大小
        per_page = 100 if os.environ.get("GITHUB_TOKEN") else 50
        github_token = get_github_token()
        headers = {
            'User-Agent': 'CVE-Monitor-App/1.0 (+https://github.com/adminlove520/github_cve_monitor)', 
            'Accept': 'application/vnd.github.v3+json'
        }

        if github_token:
            headers['Authorization'] = f'token {github_token}'
        
        # 进一步减少最大页数
        max_pages = 5
        max_retries = 1  # 减少重试次数
        
        # 使用更高效的查询语法
        query = f"CVE-{year} created:{year}-01-01..{year}-12-31 sort:updated-desc"
        
        while page <= max_pages:
            api = f"https://api.github.com/search/repositories?q={query}&page={page}&per_page={per_page}"
            
            # 简单延迟 - 最小化等待时间
            if page > 1:
                wait_time = 0.5 if github_token else 1
                time.sleep(wait_time)
            
            # 使用简化的请求处理
            retry_count = 0
            while retry_count < max_retries:
                try:
                    response = requests.get(api, headers=headers, timeout=10)
                    
                    # 处理响应
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'items' in data:
                                items = data['items']
                                if items:
                                    all_items.extend(items)
                                    
                                    # 检查是否有下一页
                                    if len(items) < per_page:
                                        return all_items
                                    
                                    # 继续下一页
                                    page += 1
                                    break
                                else:
                                    return all_items
                        except json.JSONDecodeError:
                            retry_count += 1
                    
                    # 快速失败处理其他状态码
                    else:
                        break
                
                except Exception:
                    retry_count += 1
            
            # 快速跳过失败的页面
            if retry_count >= max_retries or response.status_code != 200:
                page += 1
        
        # 去重处理
        seen = set()
        unique_items = []
        for item in all_items:
            if item['id'] not in seen:
                seen.add(item['id'])
                unique_items.append(item)
                
        return unique_items
    
    except Exception as e:
        return []  # 静默失败，返回空列表


def db_match(items):
    """优化的数据库匹配函数，使用批量操作提高性能"""
    if not items:
        return []
        
    r_list = []
    regex = r"[Cc][Vv][Ee][-_]\d{4}[-_]\d{4,7}"
    
    # 批量获取现有ID以避免重复插入
    all_ids = [item["id"] for item in items]
    existing_ids = set(
        row.id for row in CVE_DB.select(CVE_DB.id).where(CVE_DB.id.in_(all_ids))
    )
    
    # 准备批量插入的数据
    to_insert = []
    
    for item in items:
        id = item["id"]
        # 跳过已存在的记录
        if id in existing_ids:
            continue
            
        # 处理数据
        full_name = html.escape(item["full_name"])
        description = item["description"]
        description = html.escape(description.strip()) if description and description.strip() else 'no description'
        url = item["html_url"]
        created_at = item["created_at"]
        
        # 提取CVE编号（简化正则处理）
        cve_match = re.search(regex, url)
        if not cve_match:
            cve_match = re.search(regex, description)
        
        cve = cve_match.group() if cve_match else "CVE Not Found"
        cve = cve.replace('_', '-')
        
        # 添加到返回列表
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at,
            "cve": cve
        })
        
        # 准备插入数据库
        to_insert.append({
            'id': id,
            'full_name': full_name,
            'description': description,
            'url': url,
            'created_at': created_at,
            'cve': cve.upper()
        })
    
    # 批量插入数据库（如果有新数据）
    if to_insert:
        # 使用事务和批量插入
        try:
            with CVE_DB._meta.database.atomic():
                CVE_DB.insert_many(to_insert).execute()
        except Exception:
            # 如果批量插入失败，尝试单条插入（但这不是理想情况）
            for data in to_insert:
                try:
                    CVE_DB.create(**data)
                except Exception:
                    pass
    
    # 按创建时间排序
    return sorted(r_list, key=lambda e: e['created_at'])

def init_others_file():
    """初始化others.md文件"""
    newline = f"""# 其他未识别CVE编号的仓库报告

> Automatic monitor Github CVE using Github Actions 

## 报告信息
- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **数据来源**: GitHub仓库（未识别CVE编号）
- **说明**: 本报告包含在GitHub上找到但未能提取有效CVE编号的仓库信息

## 仓库列表

| 状态 | 相关仓库 | 描述 | 日期 |
|:---|:---|:---|:---|
"""
    with open(os.path.join(PROJECT_ROOT, 'docs/others.md'), 'w', encoding='utf-8') as f:
        f.write(newline)
    f.close()

def write_others_file(new_contents):
    """优化的others文件写入函数，减少I/O操作"""
    # 使用with语句自动处理文件关闭
    with open(os.path.join(PROJECT_ROOT, 'docs/others.md'), 'a', encoding='utf-8') as f:
        f.write(new_contents)

def main():
    # 获取当前日期
    today = datetime.now()
    date_str = today.strftime("%Y%m%d")
    year = today.year
    
    # 初始化全量数据文件
    init_file()

    # 初始化每日报告文件
    daily_file_path = init_daily_file(date_str)
    
    # 初始化others文件
    init_others_file()

    # 收集数据
    sorted_list = []
    today_list = []  # 存储当日数据
    others_list = []  # 存储CVE编号为空的数据
    
    # 初始化失败计数
    consecutive_failures = 0
    
    # 首先获取当年的数据（当日数据）
    item = get_info(year)
    if item and len(item) > 0:
        sorted_data = db_match(item)
        if sorted_data:
            # 筛选当日数据
            for entry in sorted_data:
                try:
                    created_date = datetime.fromisoformat(entry["created_at"].replace("Z", "+00:00"))
                    created_date_str = created_date.strftime("%Y-%m-%d")
                    today_str = today.strftime("%Y-%m-%d")
                    if created_date_str == today_str:
                        today_list.append(entry)
                except Exception:
                    pass
            
            sorted_list.extend(sorted_data)
        
        # 最小化等待时间
        time.sleep(0.5)
    
    # 减少历史数据获取，仅获取2年前的数据
    start_year = max(2020, year-1)
    end_year = max(2020, year-2)  # 减少为2年
    
    # 快速获取历史数据
    for i in range(start_year, end_year-1, -1):
        # 最小化等待时间
        time.sleep(0.3)
        
        item = get_info(i)
        if item and len(item) > 0:
            sorted_data = db_match(item)
            if sorted_data:
                sorted_list.extend(sorted_data)
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                if consecutive_failures >= 1:  # 更快放弃失败的请求
                    break
        else:
            consecutive_failures += 1
            if consecutive_failures >= 1:
                break
    
    print(f"✅ 历史数据获取完成")
    
    # 生成全量数据报告
    cur = db.cursor()
    cur.execute("SELECT * FROM CVE_DB ORDER BY cve DESC;")
    result = cur.fetchall()
    
    # 分离有CVE编号和无CVE编号的数据
    valid_cve_records = []
    others_records = []
    
    for row in result:
        if row[5].upper() == "CVE NOT FOUND":
            others_records.append(row)
        else:
            valid_cve_records.append(row)
    
    # 写入报告头部
    newline = f"""# 全量 情报速递 数据报告

> Automatic monitor Github CVE using Github Actions 

## 报告信息
- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **数据来源**: GitHub CVE 数据库
- **总记录数**: {len(valid_cve_records)}
- **其他记录数**: {len(others_records)} (详见 [others.md](./others.md))

## 全量数据报告

| CVE | 相关仓库（poc/exp） | 描述 | 日期 |
|:---|:---|:---|:---|
"""
    write_file(newline, overwrite=True) # 首次写入时覆盖文件

    # 写入有效的CVE记录
    for row in valid_cve_records:
        Publish_Date = row[4]
        Description = row[2].replace('|','-')
        newline = "| [" + row[5].upper() + "](https://www.cve.org/CVERecord?id=" + row[5].upper() + ") | [" + row[1] + "](" + row[3] + ") | " + Description + " | " + Publish_Date + "|\n"
        write_file(newline)
    
    # 生成others.md报告
    if len(others_records) > 0:
        for row in others_records:
            Publish_Date = row[4]
            Description = row[2].replace('|','-')
            newline = "| 🚫 未识别 | [" + row[1] + "](" + row[3] + ") | " + Description + " | " + Publish_Date + "|\n"
            write_others_file(newline)
        
        # 添加报告尾部
        footer = f"\n\n---\n\n**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n**总记录数**: {len(others_records)}\n"
        write_others_file(footer)
    
    # 生成当日报告
    
    # 记录原始today_list长度
    original_today_list_len = len(today_list)
    print(f"生成当日 情报速递 报告，共 {len(today_list)} 条记录")
    
    # 如果当日没有数据，使用最近的数据
    if len(today_list) == 0:
        print("当日无数据，尝试获取最近7天的数据...")
        # 先尝试获取最近7天的数据
        cur = db.cursor()
        # 获取7天内的数据
        from datetime import timedelta
        seven_days_ago = (today - timedelta(days=7)).strftime("%Y-%m-%d")
        cur.execute(f"SELECT * FROM CVE_DB WHERE created_at >= '{seven_days_ago}' ORDER BY created_at DESC;")
        recent_records = cur.fetchall()
        
        # 如果7天内没有数据，则获取最近的10条记录
        if len(recent_records) == 0:
            print("最近7天无数据，获取最近10条记录...")
            cur.execute("SELECT * FROM CVE_DB ORDER BY created_at DESC LIMIT 10;")
            recent_records = cur.fetchall()
        
        # 转换为与today_list相同的格式
        for row in recent_records:
            today_list.append({
                "cve": row[5],
                "full_name": row[1],
                "description": row[2],
                "url": row[3],
                "created_at": row[4]
            })
        
        print(f"当日无数据，使用最近 {len(today_list)} 条记录")
    
    # 写入每日报告文件
    if len(today_list) > 0:
        print(f"成功写入 {len(today_list)} 条记录到每日 情报速递 报告")

    # 写入每日报告（过滤掉CVE NOT FOUND的记录）
    valid_today_list = [entry for entry in today_list if entry["cve"].upper() != "CVE NOT FOUND"]
    
    for entry in valid_today_list:
        cve = entry["cve"]
        full_name = entry["full_name"]
        description = entry["description"].replace('|','-')
        url = entry["url"]
        created_at = entry["created_at"]

        newline = f"| [{cve.upper()}](https://www.cve.org/CVERecord?id={cve.upper()}) | [{full_name}]({url}) | {description} | {created_at}|\n"

        # 写入每日报告文件
        write_daily_file(daily_file_path, newline)

    # 如果是使用最近记录，则在报告中增加说明 (移动到此处)
    if original_today_list_len == 0:
        with open(daily_file_path, 'a', encoding='utf-8') as f:
            f.write("\n\n> 由于没有获取到当日数据，使用近7天记录\n\n")

    # 更新索引文件，列出所有每日报告
    update_daily_index()

    # Statistics
    print("\n📊 生成统计数据...")
    try:
        import sys
        # 获取脚本所在目录的绝对路径
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 确保目录存在 - 使用小写的data目录
        daily_dir = os.path.join(PROJECT_ROOT, 'docs', 'data', 'daily')
        stats_dir = os.path.join(PROJECT_ROOT, 'docs', 'data', 'statistics')
        os.makedirs(daily_dir, exist_ok=True)
        os.makedirs(stats_dir, exist_ok=True)
        
        # 先运行数据生成脚本创建汇总文件
        import subprocess
        print("📊 正在生成汇总数据...")
        
        # 构建命令参数
        script_path = os.path.join(PROJECT_ROOT, 'scripts/enhanced_daily_data_generator.py')
        
        # 尝试使用不同的Python解释器路径
        python_executables = [sys.executable, 'python', 'python3']
        success = False
        
        for python_exe in python_executables:
            try:
                # 直接调用Python解释器运行脚本，减少调试输出
                subprocess.run([python_exe, script_path],  # 移除--fill-gaps参数以提高性能
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=(os.name == 'nt'))
                success = True
                print("数据汇总文件已生成")
                break
            except Exception as e:
                # 如果不是最后一个尝试，继续尝试下一个
                if python_exe != python_executables[-1]:
                    continue
                else:
                    # 只在所有尝试都失败时打印错误
                    print(f"数据汇总失败: {e}")
                    raise
        
        # 再运行统计生成脚本
        print("📈 正在生成Wiki统计数据...")
        stats_script_path = os.path.join(PROJECT_ROOT, 'scripts/generate_wiki_stats.py')
        
        for python_exe in python_executables:
            try:
                # 直接调用Python解释器运行统计脚本，减少调试输出
                subprocess.run([python_exe, stats_script_path],
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=(os.name == 'nt'))
                print("Wiki统计数据已生成")
                break
            except Exception as e:
                # 如果不是最后一个尝试，继续尝试下一个
                if python_exe != python_executables[-1]:
                    continue
                else:
                    # 只在所有尝试都失败时打印错误
                    print(f"统计数据生成失败: {e}")
                    raise
    except Exception as e:
        print(f"⚠️  统计数据生成过程中出现错误: {e}")
        # 继续执行，不中断主流程

if __name__ == "__main__":
    # init_file() # 移除此行，因为全量报告的写入会覆盖文件
    main()
