import sqlite3
import os
from datetime import datetime

DATABASE = 'database.db'

def init_database():
    """Initialize the SQLite database"""
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Create users table (for personal info)
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            bio TEXT,
            avatar_url TEXT,
            github_url TEXT,
            linkedin_url TEXT,
            twitter_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create articles table (for blog posts)
    c.execute('''
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            description TEXT,
            content TEXT NOT NULL,
            category TEXT,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            published BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create projects table (for portfolio)
    c.execute('''
        CREATE TABLE projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            image_url TEXT,
            project_url TEXT,
            github_url TEXT,
            tech_stack TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            featured BOOLEAN DEFAULT 0
        )
    ''')
    
    # Create contacts table (for contact form submissions)
    c.execute('''
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read BOOLEAN DEFAULT 0
        )
    ''')
    
    # Create skills table
    c.execute('''
        CREATE TABLE skills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            skill_name TEXT NOT NULL,
            proficiency INTEGER DEFAULT 80,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    c.execute('''
        INSERT INTO users (name, email, title, bio, github_url, linkedin_url)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ('李明', 'liming@example.com', '全栈开发工程师', 
          '热爱编程，专注于Web开发。擅长Python、JavaScript、React等技术栈。',
          'https://github.com', 'https://linkedin.com'))
    
    c.execute('''
        INSERT INTO articles (title, slug, description, content, category)
        VALUES (?, ?, ?, ?, ?)
    ''', ('Python 最佳实践', 'python-best-practices',
          '在这篇文章中，我们将讨论Python开发的最佳实践。',
          '<h1>Python 最佳实践</h1><p>这是一篇关于Python开发最佳实践的文章。</p>',
          '技术'))
    
    c.execute('''
        INSERT INTO projects (title, description, tech_stack, featured)
        VALUES (?, ?, ?, ?)
    ''', ('个人网站', '这是一个现代化的个人网站项目', 'Python,Flask,HTML,CSS,SQLite', 1))
    
    c.execute('''
        INSERT INTO skills (category, skill_name, proficiency)
        VALUES (?, ?, ?)
    ''', ('编程语言', 'Python', 90))
    
    c.execute('''
        INSERT INTO skills (category, skill_name, proficiency)
        VALUES (?, ?, ?)
    ''', ('编程语言', 'JavaScript', 85))
    
    c.execute('''
        INSERT INTO skills (category, skill_name, proficiency)
        VALUES (?, ?, ?)
    ''', ('框架', 'Flask', 85))
    
    c.execute('''
        INSERT INTO skills (category, skill_name, proficiency)
        VALUES (?, ?, ?)
    ''', ('前端', 'HTML/CSS', 90))
    
    conn.commit()
    conn.close()
    print(f'Database {DATABASE} initialized successfully!')

if __name__ == '__main__':
    init_database()
