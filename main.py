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
    mode = 'w' if overwrite else 'a'
    with open(os.path.join(PROJECT_ROOT, 'docs/README.md'), mode, encoding='utf-8') as f:
        f.write(new_contents)
    f.close()

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
    """写入每日 情报速递 报告文件"""
    # 确保文件路径正确
    if not os.path.isabs(file_path):
        file_path = os.path.join(PROJECT_ROOT, file_path)
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(new_contents)
    f.close()

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
    基于原始代码的简化版本，保留基本功能但减少复杂性
    """
    try:
        all_items = []
        page = 1
        per_page = 100  # 默认每页100条，有token时使用
        github_token = get_github_token()
        headers = {'User-Agent': 'CVE-Monitor-App/1.0 (+https://github.com/adminlove520/github_cve_monitor)', 'Accept': 'application/json'}

        if github_token:
            print(f"DEBUG: GITHUB_TOKEN is set. Value: {github_token[:5]}...")
            headers['Authorization'] = f'token {github_token}'
            print(f"Using GitHub Token for authentication (Year: {year})")
        else:
            print("DEBUG: GITHUB_TOKEN is NOT set.")
            per_page = 30  # 无token时每页30条
            print(f"No GitHub Token found, using unauthenticated request (Year: {year})")

        max_pages = 10  # 限制最大页数
        max_retries = 2  # 减少重试次数，避免长时间等待
        
        while page <= max_pages:
            api = f"https://api.github.com/search/repositories?q=CVE-{year}&sort=updated&page={page}&per_page={per_page}"
            print(f"DEBUG: 正在获取年份 {year} 的第 {page}/{max_pages} 页数据")
            
            # 如果已经达到最大页数，直接返回结果
            if page > max_pages:
                print(f"⚠️ 已达到最大页数限制 ({max_pages})，结束请求")
                print(f"总共获取到 {len(all_items)} 条数据")
                return all_items
                
            # 简单延迟 - 优化等待时间，有token时减少等待
            if page > 1:
                wait_time = 2 if github_token else 4
                print(f"DEBUG: 等待 {wait_time} 秒后请求下一页")
                time.sleep(wait_time)
            
            # 使用简单的请求方式
            retry_count = 0
            while retry_count < max_retries:
                try:
                    print(f"DEBUG: 尝试请求第 {page} 页 (尝试 {retry_count+1}/{max_retries})")
                    response = requests.get(api, headers=headers, timeout=15)
                    
                    # 打印响应状态和速率限制信息
                    print(f"DEBUG: API请求状态码: {response.status_code}")
                    if 'X-RateLimit-Remaining' in response.headers:
                        remaining = response.headers.get('X-RateLimit-Remaining')
                        limit = response.headers.get('X-RateLimit-Limit')
                        print(f"API Rate Limit: {remaining}/{limit}")
                    
                    # 处理响应
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'items' in data:
                                items = data['items']
                                if items:
                                    all_items.extend(items)
                                    print(f"✅ 成功获取第 {page} 页数据，共 {len(items)} 条")
                                    
                                    # 检查是否达到GitHub API的1000条结果限制
                                    if len(all_items) >= 1000:
                                        print(f"✅ 已达到GitHub Search API的1000条结果限制")
                                        print(f"总共获取到 {len(all_items)} 条数据")
                                        return all_items  # 确保返回并退出函数
                                        
                                    # 检查是否有下一页
                                    if len(items) < per_page:
                                        print(f"✅ 已获取所有数据，没有更多页面")
                                        return all_items
                                    
                                    # 继续下一页
                                    page += 1
                                    break  # 成功获取数据，跳出重试循环
                                else:
                                    print(f"⚠️ 第 {page} 页没有数据，结束请求")
                                    return all_items
                            else:
                                print(f"⚠️ 警告: 响应中没有 'items' 字段")
                                retry_count += 1
                                time.sleep(3)
                        except json.JSONDecodeError:
                            print(f"❌ 错误: 无法解析JSON响应")
                            retry_count += 1
                            time.sleep(3)
                    
                    # 处理速率限制
                    elif response.status_code == 403:
                        print(f"⚠️ 警告: 请求被拒绝 (403)，可能是速率限制")
                        if 'X-RateLimit-Reset' in response.headers:
                            reset_time = response.headers.get('X-RateLimit-Reset')
                            reset_seconds = int(reset_time) - int(time.time())
                            if reset_seconds > 0 and reset_seconds < 60:
                                print(f"等待 {reset_seconds} 秒后继续...")
                                time.sleep(reset_seconds + 2)
                                retry_count += 1
                            else:
                                print(f"❌ 错误: 速率限制重置时间过长，跳过此页")
                                page += 1  # 跳过当前页
                                break
                        else:
                            time.sleep(10)
                            retry_count += 1
                    
                    # 其他错误
                    else:
                        print(f"❌ 错误: 请求失败，状态码: {response.status_code}")
                        retry_count += 1
                        time.sleep(3)
                
                except requests.exceptions.Timeout:
                    print(f"❌ 错误: 请求超时，尝试重试")
                    retry_count += 1
                    time.sleep(3)
                
                except requests.exceptions.ConnectionError:
                    print(f"❌ 错误: 连接错误，请检查网络连接")
                    retry_count += 1
                    time.sleep(5)
                
                except Exception as e:
                    print(f"❌ 错误: 请求发生异常: {e}")
                    retry_count += 1
                    time.sleep(3)
            
            # 如果重试次数达到上限仍未成功，跳过当前页
            if retry_count >= max_retries:
                print(f"⚠️ 警告: 第 {page} 页多次尝试失败，跳过此页")
                page += 1
        
        print(f"总共获取到 {len(all_items)} 条数据")
        return all_items
    
    except Exception as e:
        print(f"❌ 错误: get_info 函数发生异常: {e}")
        return []  # 返回空列表而不是None，避免后续处理出错


def db_match(items):
    r_list = []
    regex = r"[Cc][Vv][Ee][-_]\d{4}[-_]\d{4,7}"
    cve = ''
    for item in items:
        id = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id).count() != 0:
            continue
        full_name = html.escape(item["full_name"])
        description = item["description"]
        if description == "" or description == None:
            description = 'no description'
        else:
            description = html.escape(description.strip())
        url = item["html_url"]
### EXTRACT CVE 
        matches = re.finditer(regex, url, re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            cve = match.group()
        if not cve:
            matches = re.finditer(regex, description, re.MULTILINE)
            cve = "CVE Not Found"
            for matchNum, match in enumerate(matches, start=1):
                cve = match.group()
### 
        created_at = item["created_at"]
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at,
            "cve": cve.replace('_','-')
        })
        CVE_DB.create(id=id,
                      full_name=full_name,
                      description=description,
                      url=url,
                      created_at=created_at,
                      cve=cve.upper().replace('_','-'))

    return sorted(r_list, key=lambda e: e.__getitem__('created_at'))

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
    """写入others.md文件"""
    with open(os.path.join(PROJECT_ROOT, 'docs/others.md'), 'a', encoding='utf-8') as f:
        f.write(new_contents)
    f.close()

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
    
    # 首先获取当年的数据（当日数据）
    print(f"获取当年 ({year}) 的CVE数据...")
    item = get_info(year)
    if item is not None and len(item) > 0:
        print(f"年份: {year} : 获取到 {len(item)} 条原始数据")
        sorted_data = db_match(item)
        if len(sorted_data) != 0:
            print(f"年份 {year} : 更新 {len(sorted_data)} 条记录")
            
            # 筛选当日数据
            for entry in sorted_data:
                try:
                    created_date = datetime.fromisoformat(entry["created_at"].replace("Z", "+00:00"))
                    # 判断是否为当日数据（使用日期字符串比较，考虑到2025-09-22T13:53:14Z这样的格式）
                    # 注意：这里需要使用created_date的日期，不转换为本地时间
                    created_date_str = created_date.strftime("%Y-%m-%d")
                    today_str = today.strftime("%Y-%m-%d")
                    if created_date_str == today_str:
                        today_list.append(entry)
                except Exception as e:
                    print(f"日期解析错误: {e}")
            
            sorted_list.extend(sorted_data)
        
        # 随机等待以避免API限制 - 优化等待时间
        count = random.randint(2, 8)  # 减少等待时间
        time.sleep(count)
    
    # 获取历史数据
    # 限制年份范围到2020-2025，因为之前的数据价值较小
    start_year = max(2020, year-1)  # 不早于2020年
    end_year = max(2020, year-5)    # 最多获取5年前的数据，但不早于2020年
    
    print(f"🔍 开始获取历史数据（{start_year}年 到 {end_year}年）")
    
    # 跟踪连续失败次数，避免无限重试
    consecutive_failures = 0
    max_consecutive_failures = 2
    
    for i in range(start_year, end_year-1, -1):
        print(f"📅 正在处理年份: {i}")
        
        try:
            # 添加用户友好的进度指示
            year_progress = (start_year - i + 1) / (start_year - end_year + 1)
            print(f"📊 进度: {year_progress:.1%}")
            
            # 优化：增加API调用的用户代理标识
            headers['User-Agent'] = 'CVE-Monitor-App/1.0 (+https://github.com/adminlove520/github_cve_monitor)'
            
            item = get_info(i)
            
            # 检查数据获取结果
            if item is None:
                print(f"❌ 年份 {i} 获取数据失败，跳过")
                consecutive_failures += 1
                # 如果连续失败次数过多，可能是API问题，暂停更长时间
                if consecutive_failures >= max_consecutive_failures:
                    print(f"⚠️  连续 {consecutive_failures} 个年份获取失败，休息更长时间...")
                    time.sleep(random.randint(30, 60))
                else:
                    time.sleep(random.randint(5, 10))
                continue
            
            consecutive_failures = 0  # 重置失败计数
            
            if len(item) == 0:
                print(f"📭 年份 {i} 没有获取到新数据")
                time.sleep(random.randint(3, 5))
                continue
            
            print(f"✅ 年份: {i} : 获取到 {len(item)} 条原始数据")
            
            # 处理数据匹配
            sorted_data = db_match(item)
            if len(sorted_data) != 0:
                print(f"📋 年份 {i} : 更新 {len(sorted_data)} 条记录")
                sorted_list.extend(sorted_data)
            else:
                print(f"📝 年份 {i} : 没有需要更新的新记录")
            
            # 根据获取到的数据量调整等待时间 - 优化等待时间
            if len(item) > 50:
                wait_time = random.randint(4, 8)  # 减少等待时间
                print(f"📊 数据量较大，等待 {wait_time} 秒...")
            else:
                wait_time = random.randint(2, 5)  # 减少等待时间
                print(f"📊 数据量适中，等待 {wait_time} 秒...")
            
            time.sleep(wait_time)
            
        except Exception as e:
            print(f"❌ 处理年份 {i} 时发生错误: {e}")
            import traceback
            print(f"错误详情: {traceback.format_exc()}")
            consecutive_failures += 1
            
            # 出错后等待更长时间再继续 - 优化等待时间
            error_wait_time = random.randint(5, 10)  # 减少等待时间
            print(f"⏱️  出错后等待 {error_wait_time} 秒再继续...")
            time.sleep(error_wait_time)
            
            # 如果连续失败次数过多，终止历史数据获取
            if consecutive_failures >= max_consecutive_failures:
                print(f"❌ 已连续 {consecutive_failures} 个年份处理失败，终止历史数据获取")
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
                print(f"DEBUG: 尝试使用Python解释器: {python_exe}")
                # 使用shell=True在Windows上更可靠，特别是当路径包含空格时
                subprocess.run([python_exe, script_path, '--fill-gaps'],
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=(os.name == 'nt'))
                success = True
                print("✅ 数据汇总文件已生成")
                break
            except Exception as e:
                print(f"DEBUG: 使用 {python_exe} 失败: {e}")
                # 如果不是最后一个尝试，继续尝试下一个
                if python_exe != python_executables[-1]:
                    print(f"DEBUG: 尝试使用下一个Python解释器...")
                    continue
                else:
                    raise
        
        # 再运行统计生成脚本
        print("📈 正在生成Wiki统计数据...")
        stats_script_path = os.path.join(PROJECT_ROOT, 'scripts/generate_wiki_stats.py')
        
        for python_exe in python_executables:
            try:
                print(f"DEBUG: 尝试使用Python解释器: {python_exe}")
                subprocess.run([python_exe, stats_script_path],
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=(os.name == 'nt'))
                print("✅ Wiki统计数据已生成")
                break
            except Exception as e:
                print(f"DEBUG: 使用 {python_exe} 失败: {e}")
                if python_exe != python_executables[-1]:
                    print(f"DEBUG: 尝试使用下一个Python解释器...")
                    continue
                else:
                    raise
    except Exception as e:
        print(f"⚠️  统计数据生成过程中出现错误: {e}")
        # 继续执行，不中断主流程

if __name__ == "__main__":
    # init_file() # 移除此行，因为全量报告的写入会覆盖文件
    main()
