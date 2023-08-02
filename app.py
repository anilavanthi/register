from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your_secret_key_here'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# db = SQLAlchemy(app)
# bcrypt = Bcrypt(app) 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# class Article(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String)
#     body = db.Column(db.String)


    #db.create_all()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the passwo
with app.app_context():
    db.create_all()
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('register'))

        # Create a new user object and add it to the database
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    # For GET request (rendering the registration page)
    return render_template('register.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         user = User.query.filter_by(username=username).first()

#         if user and check_password_hash(user.password, password):
#             flash(f'Welcome, {username}!', 'success')
#             return redirect(url_for('index'))
#         else:
#             flash('Invalid username or password.', 'error')

#     return render_template('login.html')
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         # ... (Validate login credentials and set user session if valid) ...
#         # For example:
#         if is_valid_login(username, password):
#             session['user_authenticated'] = True
#             flash(f'Welcome, {username}!', 'success')
#             return redirect(url_for('college_brochure'))
#         else:
#             flash('Invalid username or password.', 'error')

#     # ... (Rest of the login route as before) ...


# def is_user_authenticated():
#     return session.get('user_authenticated', False)

# @app.route('/college_brochure')
# def college_brochure():
#     return render_template('college_brochure.html')


# @app.route('/')
# def index():
#     return 'Hello, this is the index page!'

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         # ... (Validate login credentials and set user session if valid) ...
#         # For example:
#         if is_valid_login(username, password):
#             session['user_authenticated'] = True
#             flash(f'Welcome, {username}!', 'success')
#             return redirect(url_for('college_brochure'))
#         else:
#             flash('Invalid username or password.', 'error')
#             return redirect(url_for('login'))  # Redirect back to the login page

#     # For GET request (rendering the login page)
#     return render_template('login.html')


# def is_user_authenticated():
#     return session.get('user_authenticated', False)



# if __name__ == '__main__':
#     app.run(debug=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Password matches, set user as authenticated and redirect to college brochure
            session['user_authenticated'] = True
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('college_brochure'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    # For GET request (rendering the login page)
    return render_template('login.html')

# ... (Other routes and functions as before) ...

if __name__ == '__main__':
    app.run(debug=True)


