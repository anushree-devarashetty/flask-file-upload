from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

# Initialize Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable SQLAlchemy event system
app.secret_key = 'your_secret_key_here'  # Replace with your secret key

# Initialize SQLAlchemy database
db = SQLAlchemy(app)

# Define a simple model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"File('{self.filename}')"

# Route for uploading files
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        new_file = File(filename=file.filename)
        db.session.add(new_file)
        db.session.commit()
        return redirect(url_for('uploaded_files'))
    return render_template('upload.html')

# Route for listing uploaded files
@app.route('/files')
def uploaded_files():
    files = File.query.all()
    return render_template('files.html', files=files)

if __name__ == '__main__':
    app.run()
