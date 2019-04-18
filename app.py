from flask import Flask
from flask import render_template as rt
from flask import g, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, ValidationError, validators
from passlib.hash import sha256_crypt
from functools import wraps

from data import Articles


Articles = Articles()

app = Flask(__name__)
# Mysql config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'wind0'
app.config['MYSQL_PASSWORD'] = 'test'
app.config['MYSQL_DB'] = 'SR'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MySQL
mysql = MySQL(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized', 'danger')
            return redirect(url_for('login'))
    return decorated_function


@app.route('/')
def index():
    return rt('home.html')


@app.route('/about')
def about():
    return rt('about.html')


@app.route('/articles/')
def articles():
    return rt('articles.html', articles=Articles)


@app.route('/article/<string:id>/')
def article(id):
    return rt('article.html', id=id)


class RegisterForm(Form):
    name = StringField('Username', [validators.Length(min=1, max=50), validators.DataRequired()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')
    code = StringField('Invite code', [validators.DataRequired()])

    def validate_code(self, code):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM config")
        result = cur.fetchone()
        real_code = result['code']
        if str(code.data) != real_code:
            raise ValidationError('Incorrect code')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        password = sha256_crypt.encrypt(str(form.password.data))
        # create mysql cursor
        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users(name,password) VALUES (%s,%s)", (name, password))
        mysql.connection.commit()
        # closing connection
        cur.close()
        flash('You are now registered','success')
        return redirect(url_for('login'))
    return rt('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE name = %s", [name])
        # if there is more than zero results
        if result > 0:
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = name
                flash('Properly logged in', 'success')
                return redirect(url_for("dashboard"))
        else:
            error = "Incorrect credentials"
            return rt('/login.html', error=error)
    return rt('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return rt('dashboard.html')


app.secret_key = 'super secret key'
if __name__ == '__main__':
    app.run(debug=True)
    #app.run()
