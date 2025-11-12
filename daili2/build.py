# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
import os
import sys
import shutil
import PyInstaller.__main__

datas = [('proxies.db', '.'), ('down_arrow.png', '.')]
binaries = []
hiddenimports = ['PyQt5.sip', 'requests', 'bs4', 'socks', 'sqlite3', 'concurrent.futures', 'threading', 'queue', 'warnings', 'time', 'socket', 'json', 're', 'os', 'sys']
tmp_ret = collect_all('PyQt5')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('socks')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('requests')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('bs4')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('sqlite3')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

def build_exe():
    # 删除旧的构建文件
    if os.path.exists('build'):
        shutil.rmtree('build')
    if os.path.exists('dist'):
        shutil.rmtree('dist')
    
    # PyInstaller 参数
    args = [
        '--name=代理管理器',
        '--onefile',  # 生成单个可执行文件
        '--noconsole',  # 不显示控制台窗口
        '--icon=icon.ico',  # 设置图标
        '--clean',  # 清理临时文件
        '--noconfirm',  # 不确认覆盖
        '--add-data=proxies.db;.',  # 添加数据文件
        '--add-data=down_arrow.png;.',
        '--runtime-hook=runtime_hook.py',  # 添加运行时钩子
        'proxy_manager.py'  # 主程序文件必须放在最后
    ]
    
    # 添加所有隐藏导入
    for imp in hiddenimports:
        args.append(f'--hidden-import={imp}')
    
    # 添加所有数据文件
    for src, dst in datas:
        if not src.endswith(('.py', '.pyc', '.pyo')):  # 排除Python源文件
            args.append(f'--add-data={src};{dst}')
    
    # 添加所有二进制文件
    for src, dst in binaries:
        if os.path.exists(src):  # 确保文件存在
            args.append(f'--add-binary={src};{dst}')
    
    # 运行 PyInstaller
    PyInstaller.__main__.run(args)
    
    print("构建完成！")

if __name__ == "__main__":
    build_exe() 