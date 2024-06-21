from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://file_upload_user:k2QjUxbA0x7ZZ4XBZJ3KWUkhPD6hicg4@dpg-cpqt55rv2p9s73dq6uhg-a.oregon-postgres.render.com/file_upload')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

# Initialize SQLAlchemy database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Define File model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

# Anonymous user class
class AnonymousUser(AnonymousUserMixin):
    def __init__(self):
        self.username = 'Guest'

login_manager.anonymous_user = AnonymousUser

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('upload'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('upload'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not current_user.is_authenticated:
        flash('You are uploading files as a guest. Files will not be linked to a user account.')
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user_id = current_user.id if current_user.is_authenticated else None
            new_file = File(filename=filename, user_id=user_id)
            db.session.add(new_file)
            db.session.commit()
            flash('File successfully uploaded')
            return redirect(url_for('files'))
    return render_template('upload.html')

@app.route('/files')
@login_required
def files():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('files.html', files=user_files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Main entry point
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
