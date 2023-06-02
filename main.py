import os

import pandas as pd
from flask import Flask, request, render_template_string, redirect, url_for
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
app.config['UPLOAD_FOLDER'] = 'C:/Users/bulat/PycharmProjects/flaskTest/'

login_manager = LoginManager()
login_manager.init_app(app)


class User:
    def __init__(self, username, password):
        self.id = username
        self.password_hash = generate_password_hash(password)

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.id


users = {
    'user1': User('user1', 'password1'),
    'user2': User('user2', 'password2')
}


@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username].password_hash, password):
            login_user(users[username])
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    else:
        return '''
            <form method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password">
                <input type="submit" value="Login">
            </form>
        '''


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
@login_required
def index():
    return 'Hello, {}!'.format(current_user.id)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully'
    else:
        return '''
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit" value="Upload">
            </form>
        '''


@app.route('/files')
def list_files():
    files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.endswith('.csv')]
    return render_template_string('''
        <ul>
            {% for file in files %}
                <li>
                    {{ file }}
                    <form method="post" action="{{ url_for('delete_file') }}">
                        <input type="hidden" name="filename" value="{{ file }}">
                        <input type="submit" value="Delete">
                    </form>
                </li>
            {% endfor %}
        </ul>
    ''', files=files)


@app.route('/data')
def get_data():
    filename = request.args.get('filename')
    if not filename:
        return 'No filename provided', 400
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return 'File not found', 404

    df = pd.read_csv(filepath)

    filter_column = request.args.get('filter_column')
    filter_value = request.args.get('filter_value')
    if filter_column and filter_value:
        df = df[df[filter_column] == filter_value]

    sort_column = request.args.get('sort_column')
    if sort_column:
        df = df.sort_values(by=sort_column)

    return render_template_string('''
        <table>
            <tr>
                {% for column in df.columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
            {% for row in df.itertuples() %}
                <tr>
                    {% for value in row[1:] %}
                        <td>{{ value }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </table>
    ''', df=df)


@app.route('/delete', methods=['POST'])
def delete_file():
    filename = request.form['filename']
    if not filename:
        return 'No filename provided', 400
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return 'File not found', 404
    os.remove(filepath)
    return 'File deleted successfully'


if __name__ == '__main__':
    app.run()
