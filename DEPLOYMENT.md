# 部署指南

## 开发环境

### 系统要求
- Python 3.8+
- pip 和 venv

### 安装步骤

1. 克隆项目
```bash
git clone <repository-url>
cd project
```

2. 创建虚拟环境
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 初始化数据库
```bash
python init_db.py
```

5. 运行应用
```bash
python app.py
```

访问 http://localhost:5000

## 生产环境部署

### 使用 Gunicorn

1. 安装 Gunicorn
```bash
pip install gunicorn
```

2. 运行应用
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### 使用 Nginx 反向代理

配置示例 `/etc/nginx/sites-available/personal-site`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /static {
        alias /path/to/project/static;
    }
}
```

### 使用 Systemd 服务

创建 `/etc/systemd/system/personal-site.service`:

```ini
[Unit]
Description=Personal Website
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/path/to/project
Environment="PATH=/path/to/project/venv/bin"
ExecStart=/path/to/project/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

启动服务：
```bash
sudo systemctl start personal-site
sudo systemctl enable personal-site
```

### SSL 证书 (使用 Let's Encrypt)

```bash
sudo certbot certonly --nginx -d your-domain.com
```

## 环境变量

创建 `.env` 文件（仅用于生产环境）：

```env
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///database.db
```

## 数据库管理

### 备份
```bash
cp database.db database.db.backup
```

### 恢复
```bash
cp database.db.backup database.db
```

## 监控和日志

使用 systemd 查看日志：
```bash
sudo journalctl -u personal-site -f
```

## 更新

更新依赖：
```bash
pip install --upgrade -r requirements.txt
```

重启服务：
```bash
sudo systemctl restart personal-site
```
