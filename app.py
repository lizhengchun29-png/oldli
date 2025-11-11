from flask import Flask, render_template, request, jsonify
import sqlite3
from datetime import datetime
import os

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object('config.DevelopmentConfig')

DATABASE = 'database.db'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_app():
    """Initialize the application"""
    if not os.path.exists(DATABASE):
        os.system('python init_db.py')

@app.route('/')
def index():
    """Home page"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get user info
    c.execute('SELECT * FROM users LIMIT 1')
    user = c.fetchone()
    
    # Get featured projects
    c.execute('SELECT * FROM projects WHERE featured = 1 LIMIT 3')
    featured_projects = c.fetchall()
    
    # Get recent articles
    c.execute('SELECT * FROM articles WHERE published = 1 ORDER BY created_at DESC LIMIT 3')
    recent_articles = c.fetchall()
    
    # Get skills
    c.execute('SELECT DISTINCT category FROM skills')
    categories = c.fetchall()
    skills_by_category = {}
    for category in categories:
        c.execute('SELECT * FROM skills WHERE category = ?', (category['category'],))
        skills_by_category[category['category']] = c.fetchall()
    
    conn.close()
    
    return render_template('index.html', 
                         user=user,
                         featured_projects=featured_projects,
                         recent_articles=recent_articles,
                         skills_by_category=skills_by_category)

@app.route('/blog')
def blog():
    """Blog page"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM articles WHERE published = 1 ORDER BY created_at DESC')
    articles = c.fetchall()
    conn.close()
    
    return render_template('blog.html', articles=articles)

@app.route('/blog/<slug>')
def article(slug):
    """Article detail page"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM articles WHERE slug = ?', (slug,))
    article = c.fetchone()
    
    if not article:
        return render_template('404.html'), 404
    
    # Increment view count
    c.execute('UPDATE articles SET views = views + 1 WHERE slug = ?', (slug,))
    conn.commit()
    conn.close()
    
    return render_template('article.html', article=article)

@app.route('/projects')
def projects():
    """Projects page"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM projects ORDER BY created_at DESC')
    projects = c.fetchall()
    conn.close()
    
    return render_template('projects.html', projects=projects)

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

@app.route('/api/contact', methods=['POST'])
def submit_contact():
    """Submit contact form"""
    try:
        data = request.get_json()
        
        if not all([data.get('name'), data.get('email'), data.get('subject'), data.get('message')]):
            return jsonify({'error': '请填写所有字段'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO contacts (name, email, subject, message)
            VALUES (?, ?, ?, ?)
        ''', (data['name'], data['email'], data['subject'], data['message']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': '消息已发送！'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    """500 error handler"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
