import sys
import os
import re
import sqlite3
import threading
import time
import socket
import socks
import requests
import concurrent.futures
import warnings
from queue import Queue
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QListWidget, QPushButton, QLabel, QMessageBox, QMenu, QAction,
                            QProgressBar, QComboBox, QTabWidget, QTextEdit, QSplitter, QSpinBox, QLineEdit, QDialog, QDialogButtonBox, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QMetaObject, Q_ARG
from PyQt5.QtGui import QCursor, QColor
import winreg
import ctypes

# 抑制 PyQt5 的弃用警告
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 数据库操作类
class DatabaseManager:
    def __init__(self, db_path="proxies.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'socks5',
            response_time REAL,
            last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_valid INTEGER DEFAULT 1
        )
        ''')
        conn.commit()
        conn.close()
    
    def add_proxy(self, ip, port, protocol="socks5", response_time=None):
        """添加代理到数据库，如果已存在则返回False，成功插入返回True"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # 检查是否已存在相同的IP和端口
            cursor.execute('''
            SELECT id FROM proxies 
            WHERE ip = ? AND port = ? AND protocol = ?
            ''', (ip, port, protocol))
            
            if cursor.fetchone():
                # 如果已存在，返回False
                return False
            else:
                # 如果不存在，则插入
                cursor.execute('''
                INSERT INTO proxies (ip, port, protocol, response_time, last_checked)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (ip, port, protocol, response_time))
                conn.commit()
                return True
        finally:
            conn.close()
    
    def deduplicate_proxies(self):
        """删除数据库中的重复代理"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 获取原始记录数
        cursor.execute('SELECT COUNT(*) FROM proxies')
        original_count = cursor.fetchone()[0]
        
        # 创建临时表
        cursor.execute('''
        CREATE TEMPORARY TABLE temp_proxies AS
        SELECT MIN(id) as id, ip, port, protocol, MAX(response_time) as response_time,
               MAX(last_checked) as last_checked, MAX(is_valid) as is_valid
        FROM proxies
        GROUP BY ip, port, protocol
        ''')
        
        # 清空原表
        cursor.execute('DELETE FROM proxies')
        
        # 从临时表恢复数据
        cursor.execute('''
        INSERT INTO proxies (id, ip, port, protocol, response_time, last_checked, is_valid)
        SELECT id, ip, port, protocol, response_time, last_checked, is_valid
        FROM temp_proxies
        ''')
        
        # 获取新的记录数
        cursor.execute('SELECT COUNT(*) FROM proxies')
        new_count = cursor.fetchone()[0]
        
        # 计算删除的记录数
        removed_count = original_count - new_count
        
        conn.commit()
        conn.close()
        
        return removed_count
    
    def get_all_proxies(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT ip, port, protocol, response_time FROM proxies WHERE is_valid = 1')
        proxies = cursor.fetchall()
        conn.close()
        return proxies
    
    def get_proxies_by_type(self, protocol):
        """获取指定类型的代理"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT ip, port, protocol, response_time FROM proxies WHERE is_valid = 1 AND protocol = ?', (protocol,))
        proxies = cursor.fetchall()
        conn.close()
        return proxies
    
    def clear_all_proxies(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM proxies')
        conn.commit()
        conn.close()
    
    def update_proxy_status(self, ip, port, is_valid, response_time=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE proxies 
        SET is_valid = ?, response_time = ?, last_checked = CURRENT_TIMESTAMP
        WHERE ip = ? AND port = ?
        ''', (is_valid, response_time, ip, port))
        conn.commit()
        conn.close()

# 代理验证线程
class ProxyVerifier(QThread):
    update_signal = pyqtSignal(str, int, bool, float)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()
    log_signal = pyqtSignal(str)
    
    def __init__(self, proxy_list, max_workers=10, proxy_type="socks5"):
        super().__init__()
        self.proxy_list = proxy_list
        self.max_workers = max_workers
        self.proxy_type = proxy_type
        self.is_running = True
        self.verified_count = 0
        self.total_count = len(proxy_list)
        self.lock = threading.Lock()
    
    def run(self):
        self.log_signal.emit(f"开始多线程验证代理，使用 {self.max_workers} 个线程，代理类型: {self.proxy_type}")
        
        # 使用线程池进行并发验证
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有验证任务，处理可能包含三个值的代理元组
            future_to_proxy = {executor.submit(self.verify_proxy, proxy[0], proxy[1]): proxy[:2] 
                             for proxy in self.proxy_list}
            
            # 处理完成的任务
            for future in concurrent.futures.as_completed(future_to_proxy):
                if not self.is_running:
                    executor.shutdown(wait=False)
                    break
                
                ip, port = future_to_proxy[future]
                try:
                    is_valid, response_time = future.result()
                    
                    # 确保response_time是有效的浮点数
                    if response_time is None:
                        response_time = 0.0
                    
                    self.update_signal.emit(ip, port, is_valid, response_time)
                    
                    # 更新进度
                    with self.lock:
                        self.verified_count += 1
                        progress = int(self.verified_count / self.total_count * 100)
                        self.progress_signal.emit(progress)
                        
                except Exception as e:
                    self.log_signal.emit(f"验证代理 {ip}:{port} 时出错: {str(e)}")
        
        self.finished_signal.emit()
    
    def verify_proxy(self, ip, port):
        try:
            start_time = time.time()
            
            # 设置超时时间
            socket.setdefaulttimeout(5)
            
            # 使用requests的代理功能
            proxies = {
                'http': f'{self.proxy_type}://{ip}:{port}',
                'https': f'{self.proxy_type}://{ip}:{port}'
            }
            
            # 测试连接多个网站，确保代理真正可用
            test_urls = [
                "http://www.baidu.com",
                "http://www.qq.com",
                "http://www.163.com",
                "http://www.sohu.com",
                "http://www.sina.com.cn"
            ]
            
            success_count = 0
            for url in test_urls:
                try:
                    response = requests.get(url, proxies=proxies, timeout=5)
                    if response.status_code == 200:
                        success_count += 1
                except Exception:
                    pass
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 只有当至少有2个网站能成功访问时，才认为代理有效
            if success_count >= 2:
                self.log_signal.emit(f"代理 {ip}:{port} ({self.proxy_type}) 验证有效，响应时间: {response_time:.2f}秒，成功率: {success_count}/{len(test_urls)}")
                return True, response_time
            
            self.log_signal.emit(f"代理 {ip}:{port} ({self.proxy_type}) 验证无效，成功率: {success_count}/{len(test_urls)}")
            return False, 0.0
        except Exception as e:
            self.log_signal.emit(f"代理 {ip}:{port} ({self.proxy_type}) 验证失败: {str(e)}")
            return False, 0.0
    
    def stop(self):
        self.is_running = False

# 代理爬虫线程
class ProxyCrawler(QThread):
    update_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)
    
    def __init__(self, source_type, proxy_type="socks5"):
        super().__init__()
        self.source_type = source_type
        self.proxy_type = proxy_type
    
    def run(self):
        proxies = []
        
        if self.source_type == "proxy-list-org":
            self.log_signal.emit(f"正在从 proxy-list.org 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxy_list_org())
        elif self.source_type == "proxynova":
            self.log_signal.emit(f"正在从 proxynova.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxynova())
        elif self.source_type == "freeproxy":
            self.log_signal.emit(f"正在从 freeproxy.world 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_freeproxy_world())
        elif self.source_type == "proxydb":
            self.log_signal.emit(f"正在从 proxydb.net 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxydb())
        elif self.source_type == "openproxy":
            self.log_signal.emit(f"正在从 openproxy.space 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_openproxy())
        elif self.source_type == "premproxy":
            self.log_signal.emit(f"正在从 premproxy.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_premproxy())
        elif self.source_type == "proxylistplus":
            self.log_signal.emit(f"正在从 list.proxylistplus.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxylistplus())
        elif self.source_type == "free-proxy-list":
            self.log_signal.emit(f"正在从 free-proxy-list.net 获取HTTP代理...")
            proxies.extend(self.crawl_free_proxy_list())
        elif self.source_type == "geonode":
            self.log_signal.emit(f"正在从 geonode.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_geonode())
        elif self.source_type == "proxyscrape":
            self.log_signal.emit(f"正在从 proxyscrape.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxyscrape())
        elif self.source_type == "freedom":
            self.log_signal.emit(f"正在从 Freedom 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_freedom())
        elif self.source_type == "hidemyass":
            self.log_signal.emit(f"正在从 HideMyAss 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_hidemyass())
        elif self.source_type == "proxpn":
            self.log_signal.emit(f"正在从 ProXPN 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxpn())
        elif self.source_type == "storm":
            self.log_signal.emit(f"正在从 Storm 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_storm())
        elif self.source_type == "spys.one":
            self.log_signal.emit(f"正在从 spys.one 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_spys_one())
        elif self.source_type == "proxy-daily":
            self.log_signal.emit(f"正在从 proxy-daily.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxy_daily())
        elif self.source_type == "cool-proxy":
            self.log_signal.emit(f"正在从 cool-proxy.net 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_cool_proxy())
        elif self.source_type == "proxy-list.download":
            self.log_signal.emit(f"正在从 proxy-list.download 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxy_list_download())
        elif self.source_type == "proxyranker":
            self.log_signal.emit(f"正在从 proxyranker.com 获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxyranker())
        elif self.source_type == "all-sources":
            self.log_signal.emit(f"正在从所有源获取{self.proxy_type}代理...")
            proxies.extend(self.crawl_proxy_list_org())
            proxies.extend(self.crawl_proxynova())
            proxies.extend(self.crawl_freeproxy_world())
            proxies.extend(self.crawl_proxydb())
            proxies.extend(self.crawl_openproxy())
            proxies.extend(self.crawl_premproxy())
            proxies.extend(self.crawl_proxylistplus())
            
            if self.proxy_type == "http":
                proxies.extend(self.crawl_free_proxy_list())
            
            proxies.extend(self.crawl_geonode())
            proxies.extend(self.crawl_proxyscrape())
            proxies.extend(self.crawl_freedom())
            proxies.extend(self.crawl_hidemyass())
            proxies.extend(self.crawl_proxpn())
            proxies.extend(self.crawl_storm())
            proxies.extend(self.crawl_spys_one())
            proxies.extend(self.crawl_proxy_daily())
            proxies.extend(self.crawl_cool_proxy())
            proxies.extend(self.crawl_proxy_list_download())
            proxies.extend(self.crawl_proxyranker())
        
        # 为每个代理添加类型标记
        typed_proxies = [(ip, port, self.proxy_type) for ip, port in proxies]
        self.update_signal.emit(typed_proxies)
    
    def get_direct_session(self):
        """创建一个不使用代理的请求会话"""
        session = requests.Session()
        # 确保不使用系统代理设置
        session.trust_env = False
        # 设置通用请求头，模拟浏览器
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        return session
    
    def crawl_proxy_list_org(self):
        """从 proxy-list.org 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://proxy-list.org/english/index.php", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理列表
            proxy_elements = soup.select("div.table-wrap ul li.proxy")
            
            for element in proxy_elements:
                try:
                    # 代理信息通常在 script 标签中使用 Base64 编码
                    script_content = element.select_one("script").string
                    # 提取 Base64 编码的部分
                    import base64
                    import re
                    
                    base64_match = re.search(r"Proxy\('(.+?)'\)", script_content)
                    if base64_match:
                        base64_str = base64_match.group(1)
                        decoded = base64.b64decode(base64_str).decode('utf-8')
                        
                        if ':' in decoded:
                            ip, port = decoded.split(':')
                            proxies.append((ip, int(port)))
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 proxy-list.org 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_proxynova(self):
        """从 proxynova.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://www.proxynova.com/proxy-server-list/", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格行
            rows = soup.select("table#tbl_proxy_list tbody tr")
            
            for row in rows:
                try:
                    # IP地址通常在脚本中
                    ip_cell = row.select_one("td:nth-child(1)")
                    if not ip_cell:
                        continue
                        
                    # 提取IP地址
                    script_content = ip_cell.select_one("script")
                    if script_content:
                        # 从脚本中提取IP
                        import re
                        ip_match = re.search(r"document\.write\('(.+?)'\)", script_content.string)
                        if ip_match:
                            ip = ip_match.group(1).strip()
                        else:
                            continue
                    else:
                        # 如果没有脚本，直接获取文本
                        ip = ip_cell.text.strip()
                    
                    # 获取端口
                    port_cell = row.select_one("td:nth-child(2)")
                    if port_cell:
                        port = port_cell.text.strip()
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 proxynova.com 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_freeproxy_world(self):
        """从 freeproxy.world 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://www.freeproxy.world/", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            rows = soup.select("table.layui-table tbody tr")
            
            for row in rows:
                try:
                    columns = row.select("td")
                    if len(columns) >= 2:
                        ip = columns[0].text.strip()
                        port = columns[1].text.strip()
                        
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 freeproxy.world 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_proxydb(self):
        """从 proxydb.net 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("http://proxydb.net/", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理列表
            proxy_elements = soup.select("table.table tbody tr")
            
            for element in proxy_elements:
                try:
                    # 获取代理信息
                    proxy_cell = element.select_one("td:nth-child(1)")
                    if proxy_cell:
                        proxy_text = proxy_cell.text.strip()
                        if ':' in proxy_text:
                            ip, port = proxy_text.split(':')
                            try:
                                port = int(port)
                                proxies.append((ip, port))
                            except ValueError:
                                pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 proxydb.net 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_openproxy(self):
        """从 openproxy.space 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://openproxy.space/list", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理列表
            proxy_elements = soup.select("table.table tbody tr")
            
            for element in proxy_elements:
                try:
                    columns = element.select("td")
                    if len(columns) >= 2:
                        ip = columns[0].text.strip()
                        port = columns[1].text.strip()
                        
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 openproxy.space 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_premproxy(self):
        """从 premproxy.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://premproxy.com/proxy-by-country/", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            rows = soup.select("table#proxylist tbody tr")
            
            for row in rows:
                try:
                    columns = row.select("td")
                    if len(columns) >= 2:
                        proxy_text = columns[0].text.strip()
                        if ':' in proxy_text:
                            ip, port = proxy_text.split(':')
                            try:
                                port = int(port)
                                proxies.append((ip, port))
                            except ValueError:
                                pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 premproxy.com 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_proxylistplus(self):
        """从 list.proxylistplus.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            rows = soup.select("table.bg tr.cells")
            
            for row in rows:
                try:
                    columns = row.select("td")
                    if len(columns) >= 3:
                        ip = columns[1].text.strip()
                        port = columns[2].text.strip()
                        
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 list.proxylistplus.com 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_free_proxy_list(self):
        """从 free-proxy-list.net 获取HTTP代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            response = session.get("https://free-proxy-list.net/", timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            table = soup.find('table', id='proxylisttable')
            
            if table and table.tbody:
                for row in table.tbody.find_all('tr'):
                    try:
                        columns = row.find_all('td')
                        if len(columns) >= 8:
                            ip = columns[0].text.strip()
                            port = columns[1].text.strip()
                            https = columns[6].text.strip()
                            
                            try:
                                port = int(port)
                                # 只获取支持HTTPS的代理
                                if https.lower() == 'yes':
                                    proxies.append((ip, port))
                            except ValueError:
                                pass
                    except Exception as e:
                        self.log_signal.emit(f"解析代理时出错: {str(e)}")
            
        except Exception as e:
            self.log_signal.emit(f"从 free-proxy-list.net 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_geonode(self):
        """从 geonode.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            
            # 根据代理类型选择不同的API端点
            protocol = "http" if self.proxy_type == "http" else "socks5"
            url = f"https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=90&protocols={protocol}"
            
            response = session.get(url, timeout=15)
            data = response.json()
            
            for proxy in data.get('data', []):
                try:
                    ip = proxy.get('ip')
                    port = proxy.get('port')
                    if ip and port:
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 geonode.com 获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_proxyscrape(self):
        """从 proxyscrape.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            
            # 根据代理类型选择不同的API端点
            protocol = "http" if self.proxy_type == "http" else "socks5"
            url = f"https://api.proxyscrape.com/v2/?request=getproxies&protocol={protocol}&timeout=10000&country=all"
            
            response = session.get(url, timeout=15)
            proxy_list = response.text.strip().split('\r\n')
            
            for proxy in proxy_list:
                try:
                    if ':' in proxy:
                        ip, port = proxy.split(':')
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从 proxyscrape.com 获取代理时出错: {str(e)}")
        
        return proxies

    def crawl_freedom(self):
        """从 Freedom 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            
            # Freedom 提供的API端点
            url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
            if self.proxy_type == "socks5":
                url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
                
            response = session.get(url, timeout=15)
            proxy_list = response.text.strip().split('\n')
            
            for proxy in proxy_list:
                try:
                    if ':' in proxy:
                        ip, port = proxy.split(':')
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                            self.log_signal.emit(f"从Freedom获取代理: {ip}:{port}")
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析Freedom代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从Freedom获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_hidemyass(self):
        """从 HideMyAss 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            
            # HideMyAss 代理列表页面
            url = "https://proxylist.hidemyass-freeproxy.com/proxy-list/"
            
            response = session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            table = soup.find('table', class_='hma-table')
            if table and table.tbody:
                rows = table.tbody.find_all('tr')
                
                for row in rows:
                    try:
                        columns = row.find_all('td')
                        if len(columns) >= 7:
                            ip = columns[0].text.strip()
                            port = columns[1].text.strip()
                            protocol = columns[6].text.strip().lower()
                            
                            # 根据代理类型筛选
                            if (self.proxy_type == "http" and protocol == "http") or \
                               (self.proxy_type == "socks5" and protocol == "socks5"):
                                try:
                                    port = int(port)
                                    proxies.append((ip, port))
                                    self.log_signal.emit(f"从HideMyAss获取代理: {ip}:{port}")
                                except ValueError:
                                    pass
                    except Exception as e:
                        self.log_signal.emit(f"解析HideMyAss代理时出错: {str(e)}")
            
        except Exception as e:
            self.log_signal.emit(f"从HideMyAss获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_proxpn(self):
        """从 ProXPN 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            
            # ProXPN 代理API
            url = "https://api.proxyscrape.com/?request=displayproxies&proxytype=all&country=all&anonymity=all&ssl=all&timeout=10000"
            
            response = session.get(url, timeout=15)
            proxy_list = response.text.strip().split('\n')
            
            for proxy in proxy_list:
                try:
                    if ':' in proxy:
                        ip, port = proxy.split(':')
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                            self.log_signal.emit(f"从ProXPN获取代理: {ip}:{port}")
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析ProXPN代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从ProXPN获取代理时出错: {str(e)}")
        
        return proxies
    
    def crawl_storm(self):
        """从 Storm 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            
            # Storm 代理API
            url = "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
            if self.proxy_type == "http":
                url = "https://www.proxy-list.download/api/v1/get?type=http"
                
            response = session.get(url, timeout=15)
            proxy_list = response.text.strip().split('\n')
            
            for proxy in proxy_list:
                try:
                    if ':' in proxy:
                        ip, port = proxy.split(':')
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                            self.log_signal.emit(f"从Storm获取代理: {ip}:{port}")
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析Storm代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从Storm获取代理时出错: {str(e)}")
        
        return proxies

    def crawl_spys_one(self):
        """从 spys.one 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            url = "http://spys.one/free-proxy-list/"
            
            # 获取初始页面以获取表单数据
            response = session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            proxy_table = soup.find('table', {'class': 'spy1x'})
            if proxy_table:
                rows = proxy_table.find_all('tr')[2:]  # 跳过表头
                for row in rows:
                    try:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip_port = cols[0].text.strip()
                            if ':' in ip_port:
                                ip, port = ip_port.split(':')
                                try:
                                    port = int(port)
                                    proxies.append((ip, port))
                                    self.log_signal.emit(f"从spys.one获取代理: {ip}:{port}")
                                except ValueError:
                                    pass
                    except Exception as e:
                        self.log_signal.emit(f"解析spys.one代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从spys.one获取代理时出错: {str(e)}")
        
        return proxies

    def crawl_proxy_daily(self):
        """从 proxy-daily.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            url = "https://proxy-daily.com/"
            
            response = session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理列表
            proxy_divs = soup.find_all('div', {'class': 'centeredProxyList'})
            for div in proxy_divs:
                proxy_list = div.text.strip().split('\n')
                for proxy in proxy_list:
                    try:
                        if ':' in proxy:
                            ip, port = proxy.split(':')
                            try:
                                port = int(port)
                                proxies.append((ip, port))
                                self.log_signal.emit(f"从proxy-daily获取代理: {ip}:{port}")
                            except ValueError:
                                pass
                    except Exception as e:
                        self.log_signal.emit(f"解析proxy-daily代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从proxy-daily获取代理时出错: {str(e)}")
        
        return proxies

    def crawl_cool_proxy(self):
        """从 cool-proxy.net 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            url = "https://cool-proxy.net/"
            
            response = session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            proxy_table = soup.find('table', {'id': 'proxy_list'})
            if proxy_table:
                rows = proxy_table.find_all('tr')[1:]  # 跳过表头
                for row in rows:
                    try:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip = cols[0].text.strip()
                            port = cols[1].text.strip()
                            try:
                                port = int(port)
                                proxies.append((ip, port))
                                self.log_signal.emit(f"从cool-proxy获取代理: {ip}:{port}")
                            except ValueError:
                                pass
                    except Exception as e:
                        self.log_signal.emit(f"解析cool-proxy代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从cool-proxy获取代理时出错: {str(e)}")
        
        return proxies

    def crawl_proxy_list_download(self):
        """从 proxy-list.download 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            protocol = "http" if self.proxy_type == "http" else "socks5"
            url = f"https://www.proxy-list.download/api/v1/get?type={protocol}"
            
            response = session.get(url, timeout=15)
            proxy_list = response.text.strip().split('\r\n')
            
            for proxy in proxy_list:
                try:
                    if ':' in proxy:
                        ip, port = proxy.split(':')
                        try:
                            port = int(port)
                            proxies.append((ip, port))
                            self.log_signal.emit(f"从proxy-list.download获取代理: {ip}:{port}")
                        except ValueError:
                            pass
                except Exception as e:
                    self.log_signal.emit(f"解析proxy-list.download代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从proxy-list.download获取代理时出错: {str(e)}")
        
        return proxies

    def crawl_proxyranker(self):
        """从 proxyranker.com 获取代理"""
        proxies = []
        try:
            session = self.get_direct_session()
            url = "https://proxyranker.com/"
            
            response = session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找代理表格
            proxy_table = soup.find('table', {'class': 'table'})
            if proxy_table:
                rows = proxy_table.find_all('tr')[1:]  # 跳过表头
                for row in rows:
                    try:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip = cols[0].text.strip()
                            port = cols[1].text.strip()
                            try:
                                port = int(port)
                                proxies.append((ip, port))
                                self.log_signal.emit(f"从proxyranker获取代理: {ip}:{port}")
                            except ValueError:
                                pass
                    except Exception as e:
                        self.log_signal.emit(f"解析proxyranker代理时出错: {str(e)}")
        except Exception as e:
            self.log_signal.emit(f"从proxyranker获取代理时出错: {str(e)}")
        
        return proxies

# 主窗口类
class ProxyManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proxy_list = []
        self.valid_proxies = []  # 初始化有效代理列表
        self.db_manager = DatabaseManager()
        self.proxy_sources = [
            "proxy-list-org", 
            "proxynova", 
            "freeproxy", 
            "proxydb", 
            "openproxy",
            "premproxy",
            "proxylistplus",
            "free-proxy-list",
            "geonode",
            "proxyscrape",
            "freedom",
            "hidemyass",
            "proxpn",
            "storm",
            "spys.one",
            "proxy-daily",
            "cool-proxy",
            "proxy-list.download",
            "proxyranker",
            "all-sources"
        ]
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("免费网游加速器")
        self.setGeometry(100, 100, 1000, 700)  # 调整窗口大小
        
        # 设置应用程序样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f6fa;
            }
            
            QWidget {
                font-family: "Microsoft YaHei", "Segoe UI", "Arial";
                font-size: 12px;
            }
            
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                min-width: 120px;  /* 增加最小宽度 */
            }
            
            QPushButton:hover {
                background-color: #357abd;
            }
            
            QPushButton:pressed {
                background-color: #2d6da3;
            }
            
            QPushButton[style="warning"] {
                background-color: #e74c3c;
            }
            
            QPushButton[style="warning"]:hover {
                background-color: #c0392b;
            }
            
            QListWidget {
                background-color: white;
                border: 1px solid #dcdde1;
                border-radius: 4px;
                padding: 5px;
            }
            
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #f1f2f6;
            }
            
            QListWidget::item:selected {
                background-color: #4a90e2;
                color: white;
            }
            
            QComboBox {
                background-color: white;
                border: 1px solid #dcdde1;
                border-radius: 4px;
                padding: 5px;
                min-width: 100px;
            }
            
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            
            QComboBox::down-arrow {
                image: url(down_arrow.png);
                width: 12px;
                height: 12px;
            }
            
            QLineEdit {
                background-color: white;
                border: 1px solid #dcdde1;
                border-radius: 4px;
                padding: 5px;
            }
            
            QProgressBar {
                border: none;
                background-color: #f1f2f6;
                border-radius: 4px;
                text-align: center;
            }
            
            QProgressBar::chunk {
                background-color: #4a90e2;
                border-radius: 4px;
            }
            
            QTextEdit {
                background-color: white;
                border: 1px solid #dcdde1;
                border-radius: 4px;
                padding: 5px;
            }
            
            QSpinBox {
                background-color: white;
                border: 1px solid #dcdde1;
                border-radius: 4px;
                padding: 5px;
            }
            
            QTabWidget::pane {
                border: 1px solid #dcdde1;
                border-radius: 4px;
                background-color: white;
            }
            
            QTabBar::tab {
                background-color: #f5f6fa;
                border: 1px solid #dcdde1;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 8px 15px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #4a90e2;
            }
            
            QLabel {
                color: #2f3542;
            }
            
            QSplitter::handle {
                background-color: #dcdde1;
            }
            
            QScrollBar:vertical {
                border: none;
                background-color: #f1f2f6;
                width: 10px;
                border-radius: 5px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #c8c9cc;
                border-radius: 5px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #a4a5a7;
            }
        """)
        
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建选项卡
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # 代理管理选项卡
        proxy_tab = QWidget()
        proxy_layout = QVBoxLayout(proxy_tab)
        
        # 上部分布局
        top_layout = QHBoxLayout()
        
        # 左侧布局 - 代理源和爬取按钮
        left_layout = QVBoxLayout()
        
        # 代理源选择和管理
        source_layout = QHBoxLayout()
        source_label = QLabel("代理源:")
        self.source_combo = QComboBox()
        self.source_combo.addItems(self.proxy_sources)
        
        # 添加代理源管理按钮
        manage_sources_btn = QPushButton("管理")
        manage_sources_btn.clicked.connect(self.show_source_manager)
        
        source_layout.addWidget(source_label)
        source_layout.addWidget(self.source_combo)
        source_layout.addWidget(manage_sources_btn)
        
        # 代理类型选择
        proxy_type_layout = QHBoxLayout()
        proxy_type_label = QLabel("代理类型:")
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(["socks5", "http"])
        self.proxy_type_combo.setToolTip("选择要验证和使用的代理类型")
        proxy_type_layout.addWidget(proxy_type_label)
        proxy_type_layout.addWidget(self.proxy_type_combo)
        
        # 爬取按钮
        self.crawl_button = QPushButton("爬取代理")
        self.crawl_button.clicked.connect(self.crawl_proxies)
        
        # 手动添加代理
        add_proxy_layout = QHBoxLayout()
        self.add_proxy_input = QLineEdit()
        self.add_proxy_input.setPlaceholderText("输入代理 IP:端口")
        self.add_proxy_button = QPushButton("添加")
        self.add_proxy_button.clicked.connect(self.add_proxy_manually)
        add_proxy_layout.addWidget(self.add_proxy_input)
        add_proxy_layout.addWidget(self.add_proxy_button)
        
        # 导入导出按钮
        import_export_layout = QHBoxLayout()
        self.import_button = QPushButton("导入代理")
        self.import_button.clicked.connect(self.import_proxies)
        self.export_button = QPushButton("导出代理")
        self.export_button.clicked.connect(self.export_proxies)
        import_export_layout.addWidget(self.import_button)
        import_export_layout.addWidget(self.export_button)
        
        # 线程数设置
        thread_layout = QHBoxLayout()
        thread_label = QLabel("验证线程数:")
        self.thread_spinbox = QSpinBox()
        self.thread_spinbox.setRange(1, 50)
        self.thread_spinbox.setValue(10)
        self.thread_spinbox.setToolTip("设置验证代理时使用的线程数量")
        thread_layout.addWidget(thread_label)
        thread_layout.addWidget(self.thread_spinbox)
        
        # 代理筛选
        filter_layout = QHBoxLayout()
        filter_label = QLabel("筛选类型:")
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["全部", "socks5", "http"])
        self.filter_combo.currentIndexChanged.connect(self.filter_proxies)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_combo)
        
        # 统计信息
        self.stats_label = QLabel("统计: 0个代理 (0 SOCKS5, 0 HTTP)")
        
        left_layout.addLayout(source_layout)
        left_layout.addLayout(proxy_type_layout)
        left_layout.addWidget(self.crawl_button)
        left_layout.addLayout(add_proxy_layout)
        left_layout.addLayout(import_export_layout)
        left_layout.addLayout(thread_layout)
        left_layout.addLayout(filter_layout)
        left_layout.addWidget(self.stats_label)
        left_layout.addStretch()
        
        # 右侧布局 - 代理列表
        right_layout = QVBoxLayout()
        
        list_label = QLabel("代理列表:")
        self.proxy_listwidget = QListWidget()
        self.proxy_listwidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.proxy_listwidget.customContextMenuRequested.connect(self.show_context_menu)
        
        right_layout.addWidget(list_label)
        right_layout.addWidget(self.proxy_listwidget)
        
        # 添加左右布局到上部分布局
        top_layout.addLayout(left_layout, 1)
        top_layout.addLayout(right_layout, 3)
        
        # 创建进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # 下部分布局 - 按钮和进度条
        bottom_layout = QHBoxLayout()
        
        # 创建按钮
        self.verify_list_button = QPushButton("验证列表中IP")
        self.verify_list_button.clicked.connect(self.verify_list_proxies)
        
        self.verify_db_button = QPushButton("验证数据库中IP")
        self.verify_db_button.clicked.connect(self.verify_db_proxies)
        
        self.export_db_button = QPushButton("提取数据库中IP")
        self.export_db_button.clicked.connect(self.export_db_proxies)
        
        self.test_proxy_button = QPushButton("测试选中代理")
        self.test_proxy_button.clicked.connect(self.test_selected_proxy)
        
        self.verify_location_button = QPushButton("验证IP地理位置")
        self.verify_location_button.clicked.connect(self.verify_ip_locations)
        
        self.clear_list_button = QPushButton("清空列表")
        self.clear_list_button.clicked.connect(self.clear_proxy_list)
        
        # 设置取消代理按钮的样式
        self.unset_all_proxy_button = QPushButton("取消所有代理设置")
        self.unset_all_proxy_button.setProperty("style", "warning")
        self.unset_all_proxy_button.clicked.connect(self.unset_proxy)
        
        # 设置数据库去重按钮的样式
        self.deduplicate_db_button = QPushButton("整理数据库")
        self.deduplicate_db_button.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:pressed {
                background-color: #219a52;
            }
        """)
        self.deduplicate_db_button.clicked.connect(self.deduplicate_database)
        
        # 添加按钮到下部分布局
        bottom_layout.addWidget(self.verify_list_button)
        bottom_layout.addWidget(self.verify_db_button)
        bottom_layout.addWidget(self.export_db_button)
        bottom_layout.addWidget(self.test_proxy_button)
        bottom_layout.addWidget(self.verify_location_button)
        bottom_layout.addWidget(self.clear_list_button)
        bottom_layout.addWidget(self.unset_all_proxy_button)
        bottom_layout.addWidget(self.deduplicate_db_button)
        
        # 设置进度条样式和高度
        self.progress_bar.setFixedHeight(15)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #f1f2f6;
                border-radius: 7px;
                text-align: center;
                height: 15px;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4a90e2, stop:1 #357abd);
                border-radius: 7px;
            }
        """)
        
        # 添加上下部分布局到代理选项卡
        proxy_layout.addLayout(top_layout)
        proxy_layout.addWidget(self.progress_bar)
        proxy_layout.addLayout(bottom_layout)
        
        # 日志选项卡
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.log_textedit = QTextEdit()
        self.log_textedit.setReadOnly(True)
        
        log_layout.addWidget(self.log_textedit)
        
        # 帮助选项卡
        help_tab = QWidget()
        help_layout = QVBoxLayout(help_tab)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
        <h2>国外代理服务使用指南</h2>
        
        <h3>Freedom</h3>
        <p>Freedom是一个提供免费IP地址和端口的服务，主要用于代理服务器和Tor网络。</p>
        <p><b>使用方法：</b></p>
        <ol>
            <li>从下拉菜单选择"freedom"作为代理源</li>
            <li>选择所需的代理类型（HTTP或SOCKS5）</li>
            <li>点击"爬取代理"按钮获取最新代理</li>
            <li>验证代理后，右键点击有效代理并选择"设置为HTTP代理"或"设置为SOCKS5代理"</li>
        </ol>
        
        <h3>HideMyAss</h3>
        <p>HideMyAss是一个知名的提供免费代理服务器和VPN服务的网站，可以保护用户的网络隐私和安全。</p>
        <p><b>使用方法：</b></p>
        <ol>
            <li>从下拉菜单选择"hidemyass"作为代理源</li>
            <li>选择所需的代理类型（HTTP或SOCKS5）</li>
            <li>点击"爬取代理"按钮获取最新代理</li>
            <li>验证代理后，右键点击有效代理并选择"设置为HTTP代理"或"设置为SOCKS5代理"</li>
        </ol>
        
        <h3>ProXPN</h3>
        <p>ProXPN是一个提供免费代理服务器和VPN服务的网站，可以保护用户的网络隐私和安全。</p>
        <p><b>使用方法：</b></p>
        <ol>
            <li>从下拉菜单选择"proxpn"作为代理源</li>
            <li>选择所需的代理类型（HTTP或SOCKS5）</li>
            <li>点击"爬取代理"按钮获取最新代理</li>
            <li>验证代理后，右键点击有效代理并选择"设置为HTTP代理"或"设置为SOCKS5代理"</li>
        </ol>
        
        <h3>Storm</h3>
        <p>Storm是一个提供免费代理服务器和VPN服务的网站，可以保护用户的网络隐私和安全。</p>
        <p><b>使用方法：</b></p>
        <ol>
            <li>从下拉菜单选择"storm"作为代理源</li>
            <li>选择所需的代理类型（HTTP或SOCKS5）</li>
            <li>点击"爬取代理"按钮获取最新代理</li>
            <li>验证代理后，右键点击有效代理并选择"设置为HTTP代理"或"设置为SOCKS5代理"</li>
        </ol>
        
        <h3>代理类型说明</h3>
        <p><b>HTTP代理：</b>适用于网页浏览和基本的网络应用，速度较快但安全性较低。</p>
        <p><b>SOCKS5代理：</b>适用于各种网络应用，包括P2P下载、游戏等，安全性较高但速度可能较慢。</p>
        
        <h3>注意事项</h3>
        <ul>
            <li>免费代理的稳定性和速度可能不如付费代理</li>
            <li>使用代理时请遵守当地法律法规</li>
            <li>不要通过代理传输敏感信息（如银行账号、密码等）</li>
            <li>建议定期更换代理以提高安全性</li>
            <li>如果需要长期稳定的代理服务，建议考虑付费VPN服务</li>
        </ul>
        """)
        
        help_layout.addWidget(help_text)
        
        # 添加选项卡到选项卡部件
        tabs.addTab(proxy_tab, "加速VPN管理")
        tabs.addTab(log_tab, "日志")
       # tabs.addTab(help_tab, "使用指南")
        
        # 设置标题标签的样式
        title_label = QLabel("免费网游加速器")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        main_layout.insertWidget(0, title_label, 0, Qt.AlignCenter)
        
        # 设置状态标签的样式
        self.stats_label.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 1px solid #dcdde1;
                border-radius: 4px;
                padding: 8px;
                color: #2c3e50;
            }
        """)
        
        # 设置选项卡的最小高度
        tabs.setMinimumHeight(500)
        
        # 设置帮助文本的样式
        help_text.setStyleSheet("""
            QTextEdit {
                line-height: 1.6;
                background-color: white;
                padding: 15px;
            }
        """)
        
        # 设置日志文本框的样式
        self.log_textedit.setStyleSheet("""
            QTextEdit {
                font-family: "Consolas", "Microsoft YaHei Mono", monospace;
                font-size: 12px;
                line-height: 1.5;
                background-color: #2f3542;
                color: #dfe4ea;
                border: none;
            }
        """)
        
        # 设置所有标签的统一样式
        for widget in self.findChildren(QLabel):
            if widget != title_label and widget != self.stats_label:
                widget.setStyleSheet("""
                    QLabel {
                        color: #2c3e50;
                        font-weight: bold;
                        margin-right: 5px;
                    }
                """)
        
        # 调整布局间距
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        top_layout.setSpacing(15)
        bottom_layout.setSpacing(10)
        
        # 初始化验证线程
        self.verifier = None
        self.crawler = None
        
        # 显示窗口
        self.show()
        
        # 记录日志
        self.log("代理管理器已启动")
    
    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_textedit.append(f"[{timestamp}] {message}")
    
    def crawl_proxies(self):
        """爬取代理"""
        self.disable_all_buttons()  # 禁用所有按钮
        
        source = self.source_combo.currentText()
        proxy_type = self.proxy_type_combo.currentText()
        
        self.crawler = ProxyCrawler(source, proxy_type)
        self.crawler.update_signal.connect(self.update_proxy_list)
        self.crawler.log_signal.connect(self.log)
        self.crawler.finished.connect(self.enable_all_buttons)  # 爬取完成后启用按钮
        
        self.log(f"开始从 {source} 爬取{proxy_type}代理...")
        self.crawler.start()
    
    def update_proxy_list(self, proxies):
        count = 0
        for ip, port, proxy_type in proxies:
            # 检查是否已存在相同IP和端口的代理
            exists = False
            for i, (existing_ip, existing_port, _) in enumerate(self.proxy_list):
                if existing_ip == ip and existing_port == port:
                    exists = True
                    break
            
            if not exists:
                self.proxy_list.append((ip, port, proxy_type))
                item_text = f"{ip}:{port} [{proxy_type}]"
                
                # 根据当前筛选条件决定是否显示
                current_filter = self.filter_combo.currentText()
                if current_filter == "全部" or current_filter == proxy_type:
                    self.proxy_listwidget.addItem(item_text)
                
                count += 1
        
        self.log(f"成功添加 {count} 个新代理")
        self.update_stats()
    
    def verify_list_proxies(self):
        """验证列表中的代理"""
        if not self.proxy_list:
            QMessageBox.warning(self, "警告", "代理列表为空")
            return
            
        self.disable_all_buttons()  # 禁用所有按钮
        
        self.log("开始验证代理列表...")
        self.valid_proxies = []  # 重置有效代理列表
        self.total_proxies = len(self.proxy_list)  # 记录总代理数
        
        self.verifier = ProxyVerifier(self.proxy_list, self.thread_spinbox.value(), self.proxy_type_combo.currentText())
        self.verifier.update_signal.connect(self.update_proxy_status)
        self.verifier.progress_signal.connect(self.update_progress)
        self.verifier.log_signal.connect(self.log)
        self.verifier.finished.connect(self.on_list_verification_finished)  # 连接到列表验证完成处理函数
        
        self.verifier.start()

    def on_list_verification_finished(self):
        """列表验证完成后的处理"""
        invalid_count = self.total_proxies - len(self.valid_proxies)
        
        # 将有效代理添加到数据库
        inserted_count = 0
        for ip, port, response_time in self.valid_proxies:
            try:
                if self.db_manager.add_proxy(ip, port, self.proxy_type_combo.currentText(), response_time):
                    inserted_count += 1
            except Exception as e:
                self.log(f"添加代理到数据库失败 {ip}:{port} - {str(e)}")
        
        # 显示验证结果
        QMessageBox.information(self, "验证完成", 
            f"验证完成！\n"
            f"有效代理：{len(self.valid_proxies)} 个\n"
            f"无效代理：{invalid_count} 个\n"
            f"新增到数据库：{inserted_count} 个")
        
        # 清理列表中的无效代理
        items_to_remove = []
        for i in range(self.proxy_listwidget.count()):
            item = self.proxy_listwidget.item(i)
            if "[无效]" in item.text():
                items_to_remove.append(item)
        
        # 从列表中移除无效代理
        for item in items_to_remove:
            self.proxy_listwidget.takeItem(self.proxy_listwidget.row(item))
        
        # 更新代理列表
        self.proxy_list = [(ip, port, self.proxy_type_combo.currentText()) for ip, port, _ in self.valid_proxies]
        
        self.log(f"验证完成，保留了 {len(self.valid_proxies)} 个有效代理，新增到数据库 {inserted_count} 个")
        self.update_stats()
        self.enable_all_buttons()

    def verify_db_proxies(self):
        """验证数据库中的所有代理"""
        self.disable_all_buttons()  # 禁用所有按钮
        
        # 获取数据库中的所有代理
        proxies = self.db_manager.get_all_proxies()
        if not proxies:
            QMessageBox.information(self, "提示", "数据库中没有代理")
            self.enable_all_buttons()  # 重新启用所有按钮
            return
        
        # 清空当前列表
        self.clear_proxy_list()
        
        # 将数据库中的代理添加到列表中
        for proxy in proxies:
            ip, port, protocol, _ = proxy
            self.proxy_list.append((ip, port, protocol))
            self.proxy_listwidget.addItem(f"{ip}:{port} [{protocol}]")
        
        self.log(f"从数据库导入了 {len(proxies)} 个代理到列表")
            
        self.log("开始验证数据库中的代理...")
        self.valid_proxies = []  # 重置有效代理列表
        self.total_proxies = len(proxies)  # 记录总代理数
        
        # 创建验证线程
        self.verifier = ProxyVerifier(proxies, self.thread_spinbox.value(), self.proxy_type_combo.currentText())
        self.verifier.update_signal.connect(self.update_proxy_status)
        self.verifier.progress_signal.connect(self.update_progress)
        self.verifier.log_signal.connect(self.log)
        self.verifier.finished.connect(self.on_db_verification_finished)
        
        # 开始验证
        self.verifier.start()

    def on_db_verification_finished(self):
        """数据库验证完成后的处理"""
        invalid_count = self.total_proxies - len(self.valid_proxies)
        
        # 显示验证结果
        QMessageBox.information(self, "验证完成", 
            f"验证完成！\n有效代理：{len(self.valid_proxies)} 个\n无效代理：{invalid_count} 个")
        
        # 清理列表中的无效代理
        items_to_remove = []
        for i in range(self.proxy_listwidget.count()):
            item = self.proxy_listwidget.item(i)
            if "[无效]" in item.text():
                items_to_remove.append(item)
        
        # 从列表中移除无效代理
        for item in items_to_remove:
            self.proxy_listwidget.takeItem(self.proxy_listwidget.row(item))
        
        # 更新代理列表
        self.proxy_list = [(ip, port, self.proxy_type_combo.currentText()) for ip, port, _ in self.valid_proxies]
        
        # 清空数据库并重新添加有效代理
        self.db_manager.clear_all_proxies()
        for ip, port, response_time in self.valid_proxies:
            self.db_manager.add_proxy(ip, port, self.proxy_type_combo.currentText(), response_time)
        
        self.log(f"数据库验证完成，保存了 {len(self.valid_proxies)} 个有效代理")
        self.update_stats()
        self.enable_all_buttons()
    
    def update_proxy_status(self, ip, port, is_valid, response_time):
        """更新代理状态"""
        if is_valid:
            self.valid_proxies.append((ip, port, response_time))
            # 更新列表项显示
            for i in range(self.proxy_listwidget.count()):
                item = self.proxy_listwidget.item(i)
                item_text = item.text()
                if item_text.startswith(f"{ip}:{port}"):
                    # 移除可能存在的旧状态标记
                    base_text = item_text.split(" [")[0]
                    proxy_type = item_text.split(" [")[1].split("]")[0]
                    # 添加新的状态标记
                    item.setText(f"{base_text} [{proxy_type}] [有效][响应时间:{response_time:.2f}秒]")
                    item.setForeground(QColor("#2ecc71"))  # 设置为绿色
                    break
        else:
            # 更新列表项显示为无效
            for i in range(self.proxy_listwidget.count()):
                item = self.proxy_listwidget.item(i)
                item_text = item.text()
                if item_text.startswith(f"{ip}:{port}"):
                    # 移除可能存在的旧状态标记
                    base_text = item_text.split(" [")[0]
                    proxy_type = item_text.split(" [")[1].split("]")[0]
                    # 添加无效标记
                    item.setText(f"{base_text} [{proxy_type}] [无效]")
                    item.setForeground(QColor("#e74c3c"))  # 设置为红色
                    break
        
        # 更新数据库中的代理状态
        self.db_manager.update_proxy_status(ip, port, is_valid, response_time)

    def disable_all_buttons(self):
        """禁用所有操作按钮"""
        self.crawl_button.setEnabled(False)
        self.verify_list_button.setEnabled(False)
        self.verify_db_button.setEnabled(False)
        self.export_db_button.setEnabled(False)
        self.test_proxy_button.setEnabled(False)
        self.verify_location_button.setEnabled(False)
        self.clear_list_button.setEnabled(False)
        self.unset_all_proxy_button.setEnabled(False)
        self.deduplicate_db_button.setEnabled(False)
        self.import_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.add_proxy_button.setEnabled(False)

    def enable_all_buttons(self):
        """启用所有操作按钮"""
        self.crawl_button.setEnabled(True)
        self.verify_list_button.setEnabled(True)
        self.verify_db_button.setEnabled(True)
        self.export_db_button.setEnabled(True)
        self.test_proxy_button.setEnabled(True)
        self.verify_location_button.setEnabled(True)
        self.clear_list_button.setEnabled(True)
        self.unset_all_proxy_button.setEnabled(True)
        self.deduplicate_db_button.setEnabled(True)
        self.import_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.add_proxy_button.setEnabled(True)
    
    def deduplicate_database(self):
        """去重数据库中的代理"""
        self.disable_all_buttons()  # 禁用所有按钮
        
        try:
            removed_count = self.db_manager.deduplicate_proxies()
            # 获取当前数据库中的记录数
            current_count = len(self.db_manager.get_all_proxies())
            
            self.log(f"数据库去重完成，原有记录 {removed_count + current_count} 条，删除了 {removed_count} 条重复记录，剩余 {current_count} 条")
            QMessageBox.information(self, "去重成功", 
                f"数据库去重完成！\n"
                f"原有记录：{removed_count + current_count} 条\n"
                f"删除重复：{removed_count} 条\n"
                f"剩余记录：{current_count} 条")
        except Exception as e:
            self.log(f"数据库去重失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"数据库去重失败: {str(e)}")
        finally:
            self.enable_all_buttons()  # 操作完成后启用按钮
    
    def export_db_proxies(self):
        """导出数据库中的代理到列表"""
        self.disable_all_buttons()  # 禁用所有按钮
        
        try:
            # 清空当前列表
            self.clear_proxy_list()
            
            # 从数据库获取代理
            db_proxies = self.db_manager.get_all_proxies()
            for proxy in db_proxies:
                ip, port, protocol, _ = proxy
                self.proxy_list.append((ip, port, protocol))
                self.proxy_listwidget.addItem(f"{ip}:{port} [{protocol}]")
            
            self.log(f"从数据库导出了 {len(db_proxies)} 个代理")
            self.update_stats()
        finally:
            self.enable_all_buttons()  # 操作完成后启用按钮
    
    def clear_proxy_list(self):
        self.proxy_list.clear()
        self.proxy_listwidget.clear()
        self.log("代理列表已清空")
        self.update_stats()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def verification_finished(self):
        self.log("代理验证完成")
        QMessageBox.information(self, "完成", "代理验证已完成")
    
    def show_context_menu(self, position):
        if not self.proxy_listwidget.count():
            return
        
        selected_items = self.proxy_listwidget.selectedItems()
        if not selected_items:
            return
            
        # 获取选中代理的信息
        item_text = selected_items[0].text()
        proxy_info = item_text.split(" [")
        proxy_address = proxy_info[0]
        proxy_type = proxy_info[1].rstrip("]")
        
        menu = QMenu()
        
        # 根据代理类型添加不同的菜单项
        if proxy_type == "http":
            set_http_proxy_action = QAction(f"设置为HTTP代理", self)
            set_http_proxy_action.triggered.connect(lambda: self.set_as_proxy(proxy_address, "http"))
            menu.addAction(set_http_proxy_action)
        
        if proxy_type == "socks5":
            set_socks5_proxy_action = QAction(f"设置为SOCKS5代理", self)
            set_socks5_proxy_action.triggered.connect(lambda: self.set_as_proxy(proxy_address, "socks5"))
            menu.addAction(set_socks5_proxy_action)
        
        # 添加测试代理菜单项
        test_proxy_action = QAction("测试此代理", self)
        test_proxy_action.triggered.connect(lambda: self.test_proxy(proxy_address, proxy_type))
        menu.addAction(test_proxy_action)
        
        unset_proxy_action = QAction("取消代理设置", self)
        unset_proxy_action.triggered.connect(self.unset_proxy)
        menu.addAction(unset_proxy_action)
        
        menu.exec_(QCursor.pos())
    
    def set_as_proxy(self, proxy_text, proxy_type):
        """设置系统代理"""
        try:
            # 设置WinHTTP代理
            os.system(f'netsh winhttp set proxy proxy-server="{proxy_text}"')
            
            # 设置WinInet代理（Internet选项中的代理）
            INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                0, winreg.KEY_ALL_ACCESS)

            # 启用代理
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            
            # 设置代理服务器地址
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyServer', 0, winreg.REG_SZ, proxy_text)
            
            # 设置本地地址绕过代理
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyOverride', 0, winreg.REG_SZ, '<local>')
            
            # 刷新系统代理设置
            INTERNET_OPTION_REFRESH = 37
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            
            self.log(f"成功设置系统{proxy_type}代理为: {proxy_text}")
            QMessageBox.information(self, "成功", f"已设置系统{proxy_type}代理为: {proxy_text}")
            
            # 保存当前代理设置
            self.current_proxy = proxy_text
            self.current_proxy_type = proxy_type
            
        except Exception as e:
            self.log(f"设置代理失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"设置代理失败: {str(e)}")
            
    def unset_proxy(self):
        """取消系统代理设置"""
        try:
            # 取消WinHTTP代理
            os.system('netsh winhttp reset proxy')
            
            # 取消WinInet代理
            INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                0, winreg.KEY_ALL_ACCESS)
                
            # 禁用代理
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            
            # 清除代理服务器设置
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyServer', 0, winreg.REG_SZ, '')
            
            # 刷新系统代理设置
            INTERNET_OPTION_REFRESH = 37
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            
            self.log("已取消系统代理设置")
            QMessageBox.information(self, "成功", "已取消系统代理设置")
            
            # 清除当前代理设置
            self.current_proxy = None
            self.current_proxy_type = None
            
        except Exception as e:
            self.log(f"取消代理设置失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"取消代理设置失败: {str(e)}")

    def add_proxy_manually(self):
        proxy_text = self.add_proxy_input.text().strip()
        if not proxy_text:
            QMessageBox.warning(self, "警告", "请输入代理地址")
            return
        
        try:
            if ":" not in proxy_text:
                QMessageBox.warning(self, "警告", "代理格式错误，应为 IP:端口")
                return
                
            ip, port = proxy_text.split(":")
            port = int(port)
            proxy_type = self.proxy_type_combo.currentText()
            
            # 检查是否已存在相同IP和端口的代理
            exists = False
            for existing_ip, existing_port, _ in self.proxy_list:
                if existing_ip == ip and existing_port == port:
                    exists = True
                    break
            
            if not exists:
                self.proxy_list.append((ip, port, proxy_type))
                self.proxy_listwidget.addItem(f"{ip}:{port} [{proxy_type}]")
                self.log(f"手动添加代理: {ip}:{port} [{proxy_type}]")
                self.add_proxy_input.clear()
            else:
                QMessageBox.information(self, "提示", "该代理已在列表中")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"添加代理失败: {str(e)}")

    def import_proxies(self):
        """导入代理"""
        self.disable_all_buttons()  # 禁用所有按钮
        
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, 
                "选择代理文件", 
                "", 
                "文本文件 (*.txt);;所有文件 (*.*)"
            )
            if not file_name:
                self.enable_all_buttons()
                return
                
            with open(file_name, 'r', encoding='utf-8') as f:
                content = f.readlines()
            
            # 处理导入的代理
            imported_count = 0
            for line in content:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    if '[' in line:
                        # 格式: ip:port [type]
                        proxy_part = line.split('[')[0].strip()
                        proxy_type = line.split('[')[1].split(']')[0].strip()
                    else:
                        # 格式: ip:port
                        proxy_part = line
                        proxy_type = self.proxy_type_combo.currentText()
                        
                    ip, port = proxy_part.split(':')
                    port = int(port)
                    
                    # 检查是否已存在
                    exists = False
                    for existing_ip, existing_port, _ in self.proxy_list:
                        if existing_ip == ip and existing_port == port:
                            exists = True
                            break
                    
                    if not exists:
                        self.proxy_list.append((ip, port, proxy_type))
                        self.proxy_listwidget.addItem(f"{ip}:{port} [{proxy_type}]")
                        imported_count += 1
                except Exception as e:
                    self.log(f"导入代理时出错: {line} - {str(e)}")
                    
            self.log(f"成功导入 {imported_count} 个代理")
            QMessageBox.information(self, "导入完成", f"成功导入 {imported_count} 个代理")
            self.update_stats()
            
        except Exception as e:
            self.log(f"导入代理文件时出错: {str(e)}")
            QMessageBox.critical(self, "错误", f"导入代理文件时出错: {str(e)}")
        finally:
            self.enable_all_buttons()
    
    def export_proxies(self):
        """导出代理列表"""
        if not self.proxy_list:
            QMessageBox.warning(self, "警告", "代理列表为空")
            return
            
        self.disable_all_buttons()
        
        try:
            file_name, _ = QFileDialog.getSaveFileName(
                self, 
                "保存代理文件", 
                "", 
                "文本文件 (*.txt);;所有文件 (*.*)"
            )
            if not file_name:
                self.enable_all_buttons()
                return
                
            # 如果用户没有指定.txt后缀，自动添加
            if not file_name.endswith('.txt'):
                file_name += '.txt'
                
            with open(file_name, 'w', encoding='utf-8') as f:
                for ip, port, proxy_type in self.proxy_list:
                    f.write(f"{ip}:{port} [{proxy_type}]\n")
                    
            self.log(f"成功导出 {len(self.proxy_list)} 个代理到文件: {file_name}")
            QMessageBox.information(self, "导出完成", f"成功导出 {len(self.proxy_list)} 个代理")
            
        except Exception as e:
            self.log(f"导出代理文件时出错: {str(e)}")
            QMessageBox.critical(self, "错误", f"导出代理文件时出错: {str(e)}")
        finally:
            self.enable_all_buttons()
    
    def filter_proxies(self):
        """根据代理类型筛选列表"""
        filter_type = self.filter_combo.currentText()
        
        # 清空列表控件
        self.proxy_listwidget.clear()
        
        # 根据筛选类型添加代理到列表
        if filter_type == "全部":
            for ip, port, proxy_type in self.proxy_list:
                self.proxy_listwidget.addItem(f"{ip}:{port} [{proxy_type}]")
        else:
            for ip, port, proxy_type in self.proxy_list:
                if proxy_type == filter_type:
                    self.proxy_listwidget.addItem(f"{ip}:{port} [{proxy_type}]")
        
        self.update_stats()
    
    def update_stats(self):
        """更新统计信息"""
        total = len(self.proxy_list)
        socks5_count = sum(1 for _, _, proxy_type in self.proxy_list if proxy_type == "socks5")
        http_count = sum(1 for _, _, proxy_type in self.proxy_list if proxy_type == "http")
        
        self.stats_label.setText(f"统计: {total}个代理 ({socks5_count} SOCKS5, {http_count} HTTP)")

    def test_selected_proxy(self):
        """测试选中的代理"""
        selected_items = self.proxy_listwidget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择要测试的代理")
            return
            
        self.disable_all_buttons()  # 禁用所有按钮
        
        item = selected_items[0]
        proxy_text = item.text()
        proxy_type = proxy_text.split('[')[1].strip(']')
        
        self.test_proxy(proxy_text.split('[')[0].strip(), proxy_type)
    
    def test_proxy(self, proxy_address, proxy_type):
        """测试代理的匿名性和稳定性"""
        ip, port = proxy_address.split(":")
        port = int(port)
        
        self.log(f"开始测试代理 {ip}:{port} ({proxy_type})...")
        
        # 创建测试线程
        test_thread = threading.Thread(target=self._test_proxy_thread, args=(ip, port, proxy_type))
        test_thread.daemon = True
        test_thread.start()
    
    def _test_proxy_thread(self, ip, port, proxy_type):
        """代理测试线程"""
        try:
            # 设置代理
            proxies = {
                'http': f'{proxy_type}://{ip}:{port}',
                'https': f'{proxy_type}://{ip}:{port}'
            }
            
            # 测试网站列表
            test_sites = [
                {"name": "百度", "url": "http://www.baidu.com", "timeout": 5},
                {"name": "谷歌", "url": "http://www.google.com", "timeout": 10},
                {"name": "YouTube", "url": "http://www.youtube.com", "timeout": 10},
                {"name": "Twitter", "url": "http://www.twitter.com", "timeout": 10},
                {"name": "Facebook", "url": "http://www.facebook.com", "timeout": 10}
            ]
            
            # 测试IP泄露
            try:
                self.log(f"正在检查IP泄露情况...")
                ip_check_response = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=10)
                if ip_check_response.status_code == 200:
                    proxy_ip = ip_check_response.json().get("ip")
                    self.log(f"通过代理显示的IP: {proxy_ip}")
                    
                    # 获取本地IP进行对比
                    local_ip_response = requests.get("https://api.ipify.org?format=json", timeout=5)
                    if local_ip_response.status_code == 200:
                        local_ip = local_ip_response.json().get("ip")
                        if proxy_ip != local_ip:
                            self.log(f"✓ IP匿名性测试通过: 代理IP与本地IP不同")
                        else:
                            self.log(f"✗ IP匿名性测试失败: 代理IP与本地IP相同，可能存在IP泄露")
            except Exception as e:
                self.log(f"IP匿名性测试失败: {str(e)}")
            
            # 测试DNS泄露
            try:
                self.log(f"正在检查DNS泄露情况...")
                dns_check_url = "https://www.dnsleaktest.com/json/dnsid.json"
                dns_response = requests.get(dns_check_url, proxies=proxies, timeout=10)
                if dns_response.status_code == 200:
                    self.log(f"DNS泄露测试完成，请访问 https://www.dnsleaktest.com/ 查看详细结果")
            except Exception as e:
                self.log(f"DNS泄露测试失败: {str(e)}")
            
            # 测试网站访问
            self.log(f"开始测试网站访问能力...")
            success_count = 0
            
            for site in test_sites:
                try:
                    start_time = time.time()
                    response = requests.get(site["url"], proxies=proxies, timeout=site["timeout"])
                    end_time = time.time()
                    
                    if response.status_code == 200:
                        success_count += 1
                        self.log(f"✓ 成功访问 {site['name']}，响应时间: {(end_time - start_time):.2f}秒")
                    else:
                        self.log(f"✗ 访问 {site['name']} 失败，状态码: {response.status_code}")
                except Exception as e:
                    self.log(f"✗ 访问 {site['name']} 出错: {str(e)}")
            
            # 测试结果统计
            success_rate = (success_count / len(test_sites)) * 100
            self.log(f"网站访问测试完成，成功率: {success_rate:.1f}%")
            
            # 综合评分
            if success_rate >= 80:
                rating = "优秀"
            elif success_rate >= 60:
                rating = "良好"
            elif success_rate >= 40:
                rating = "一般"
            else:
                rating = "较差"
                
            self.log(f"代理 {ip}:{port} ({proxy_type}) 测试完成，综合评级: {rating}")
            
        except Exception as e:
            self.log(f"代理测试过程中出错: {str(e)}")

    def show_source_manager(self):
        """显示代理源管理对话框"""
        dialog = ProxySourceManager(self.proxy_sources, self)
        if dialog.exec_() == QDialog.Accepted:
            # 更新代理源列表
            self.proxy_sources = dialog.get_sources()
            # 更新下拉框
            current_source = self.source_combo.currentText()
            self.source_combo.clear()
            self.source_combo.addItems(self.proxy_sources)
            # 尝试恢复之前选择的源
            index = self.source_combo.findText(current_source)
            if index >= 0:
                self.source_combo.setCurrentIndex(index)

    def verify_ip_locations(self):
        """验证IP地理位置"""
        if not self.proxy_list:
            QMessageBox.warning(self, "警告", "代理列表为空")
            return
            
        self.disable_all_buttons()  # 禁用所有按钮
        
        # 创建线程验证地理位置
        self.location_thread = threading.Thread(target=self._verify_locations_thread)
        self.location_thread.daemon = True
        self.location_thread.start()
    
    def _verify_locations_thread(self):
        """验证IP地理位置的线程函数"""
        try:
            total = len(self.proxy_list)
            for i, (ip, port, proxy_type) in enumerate(self.proxy_list):
                try:
                    response = requests.get(f"https://ip.cn/api/index?ip={ip}&type=1", timeout=10)
                    data = response.json()
                    
                    if data.get("code") == 0:
                        location = data.get("address", "未知")
                        # 使用QMetaObject.invokeMethod在主线程中更新UI
                        QMetaObject.invokeMethod(self, "_update_list_item",
                                              Qt.QueuedConnection,
                                              Q_ARG(str, ip),
                                              Q_ARG(int, port),
                                              Q_ARG(str, proxy_type),
                                              Q_ARG(str, location))
                    else:
                        self.log(f"获取IP {ip} 地理位置失败: {data.get('message', '未知错误')}")
                        
                except Exception as e:
                    self.log(f"验证IP {ip} 地理位置时出错: {str(e)}")
                    
                # 更新进度
                progress = int((i + 1) / total * 100)
                QMetaObject.invokeMethod(self.progress_bar, "setValue",
                                      Qt.QueuedConnection,
                                      Q_ARG(int, progress))
                
        except Exception as e:
            self.log(f"验证IP地理位置时出错: {str(e)}")
        finally:
            # 在主线程中重新启用按钮
            QMetaObject.invokeMethod(self, "enable_all_buttons",
                                  Qt.QueuedConnection)
            self.log("IP地理位置验证完成")
    
    def _update_list_item(self, ip, port, proxy_type, location):
        """更新列表项显示"""
        # 在主线程中更新UI
        for i in range(self.proxy_listwidget.count()):
            item = self.proxy_listwidget.item(i)
            if item.text().startswith(f"{ip}:{port}"):
                item.setText(f"{ip}:{port} [{proxy_type}] - {location}")
                break

# 添加代理源管理对话框类
class ProxySourceManager(QDialog):
    def __init__(self, sources, parent=None):
        super().__init__(parent)
        self.sources = sources.copy()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("代理源管理")
        self.setModal(True)
        layout = QVBoxLayout(self)
        
        # 代理源列表
        self.source_list = QListWidget()
        self.source_list.addItems(self.sources)
        layout.addWidget(self.source_list)
        
        # 添加代理源
        add_layout = QHBoxLayout()
        self.add_input = QLineEdit()
        self.add_input.setPlaceholderText("输入新代理源名称")
        add_btn = QPushButton("添加")
        add_btn.clicked.connect(self.add_source)
        add_layout.addWidget(self.add_input)
        add_layout.addWidget(add_btn)
        layout.addLayout(add_layout)
        
        # 删除选中的代理源
        delete_btn = QPushButton("删除选中")
        delete_btn.clicked.connect(self.delete_source)
        layout.addWidget(delete_btn)
        
        # 确定和取消按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def add_source(self):
        """添加新代理源"""
        source = self.add_input.text().strip()
        if source and source not in self.sources:
            self.sources.append(source)
            self.source_list.addItem(source)
            self.add_input.clear()
    
    def delete_source(self):
        """删除选中的代理源"""
        current = self.source_list.currentRow()
        if current >= 0:
            item = self.source_list.takeItem(current)
            self.sources.remove(item.text())
    
    def get_sources(self):
        """获取当前代理源列表"""
        return self.sources

# 程序入口
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ProxyManagerApp()
    sys.exit(app.exec_()) 