import os
from flask import Flask, render_template, flash, redirect, session, request, url_for,  logging
from flask_sqlalchemy import SQLAlchemy 
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required

#from flask_mysql import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask (__name__) 

     #set the db objects
app.config['SQLALCHEMY_DATABASE_URI'] ='postgresql://postgres:NaNiAl#x@localhost/stackoverflowlite'
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_REGISTERABLE'] = True

# database connection object
db = SQLAlchemy(app)

##---Database tables---

# Define models
roles_users = db.Table('roles_users', db.Column('user_id', db.Integer(), db.ForeignKey('user.id')), db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
     # User table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return '<User %r>' % (self.username)

#Setup Flask-Security for the app
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


  # Index
@app.route('/')
def index():
	return render_template('home.html')
   

   # About page
@app.route('/about')
def about():
	return render_template ('about.html')
   

   # Questions
@app.route('/questions')
def questions():
    
    # Get questions
    result = ("SELECT * FROM questions")

    questions = result #question.query_all()

    if result:
        return render_template('questions.html', questions=questions)
    else:
        msg = 'No Questions Found'
        return render_template('questions.html', msg=msg)
    # Close connection
    db.close()


  #Single Question
@app.route('/question/<string:id>/')
def question(id):

    # Get Question
    result = ("SELECT * FROM questions WHERE id = %s", [id])

    question = db.fetchone()

    return render_template('question.html', question=question)

# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #  add this to the database  user
        # Execute query
        ("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        # this saves this data in the database
        db.session.commit()

        # Close connection
        #db.close()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']


        # Get user by username
        result =("SELECT * FROM users WHERE username = %s", [username])

        if result:
            # Get stored hash
            data = result #db.fetchone()
            password = data #['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            #db.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    #cur = postgresql.connection.cursor()

    # Get questions
    result = db.execute("SELECT * FROM questions")

    questions = db.fetchall()

    if result > 0:
        return render_template('dashboard.html', questions=questions)
    else:
        msg = 'No Questions Found'
        return render_template('dashboard.html', msg=msg)
    # Close connection
    db.close()

# Questions Form Class
class QuestionForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

# Add Questions
@app.route('/add_question', methods=['GET', 'POST'])
@is_logged_in
def add_question():
    form = QuestionForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Add
        db.execute("INSERT INTO questions(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))

        # save this data in the database
        db.session.commit()

        #Close connection
        db.close()

        flash('Question Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_question.html', form=form)


# Edit Question
@app.route('/edit_question/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_question(id):
    # Create cursor
    #cur = postgresql.connection.cursor()

    # Get question by id
    result = db.execute("SELECT * FROM questions WHERE id = %s", [id])

    question = db.fetchone()
    db.close()
    # Get form
    form = QuestionForm(request.form)

    # Populate question form fields
    form.title.data = question['title']
    form.body.data = question['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        # Create Cursor
        #cur = postgresql.connection.cursor()
        app.logger.info(title)
        # Execute
        db.execute ("UPDATE questions SET title=%s, body=%s WHERE id=%s",(title, body, id))
        
        # Commit to DB
        db.session.commit()

        #Close connection
        db.close()

        flash('Question Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Question
@app.route('/delete_question/<string:id>', methods=['POST'])
@is_logged_in
def delete_question(id):
    # Create cursor
    #cur = postgresql.connection.cursor()

    # Execute
    db.execute("DELETE FROM questions WHERE id = %s", [id])

    # Commit to DB
    db.session.commit()

    #Close connection
    db.close()

    flash('Question Deleted', 'success')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
