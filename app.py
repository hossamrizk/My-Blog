# flask --app app.py --debug run

from flask import Flask, render_template, flash, request, redirect, url_for
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import VARBINARY
from flask_migrate import Migrate
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date
import create
import os
import uuid as uuid
from webforms import SearchForm,LoginForm, postform, UserForm, PasswordForm, NameForm

# Create a Flask Instance
app = Flask(__name__)

# Add CKEditor Instance

ckeditor = CKEditor(app)

#Create Database
# Sqlite
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# MySql
# app.config['SQLALCHEMY_DATABSE_URI'] = 'mysql://username:password@localhost/db_name'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123456789@localhost/our_users'


# Heroku Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://ajvxwrluwchsxv:b812c35ac60948474a1dcb6c30d0a8e7213699ee44dbd02556f775ee0a17de1a@ec2-107-21-67-46.compute-1.amazonaws.com:5432/d5qn954vq44lqe'


#Create Secret Key
app.config['SECRET_KEY'] = "write password"


# Intialize Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Pass stuff to navbar
@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)

@app.route('/admin')
@login_required

def admin():
    id = current_user.id
    if id ==7:
        return render_template("admin.html")
    else:
        flash("You are not an authorized for this action")
        return redirect(url_for('dashboard'))

# Create search function
@app.route('/search', methods=["POST"])
def search():
    form = SearchForm()
    posts = Posts.query
    if form.validate_on_submit():
        # Get data from submited form
        post.searched = form.searched.data

        # Query database
        posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
        posts = posts.order_by(Posts.title).all()

        return render_template("search.html",
                               form=form,
                               searched=post.searched,
                               posts=posts)

    # Ensure a default response or an error handler in case the form doesn't validate
    return render_template("404.html")  # Adjust this to an appropriate error template or response


# Flask_login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Create login page
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Login successfull!')
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password")
        else:
            flash('There is an error in username or password, Try again pls.')
    return render_template('login.html',form=form)

# Create a logout page
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("We are sorry you are leaving :(")
    flash("Come back soon :)")
    return redirect(url_for('login'))

# Create dashboard page
@app.route('/dashboard',methods=['GET','POST'])
@login_required # Make user can not enter dashboard page until he login
def dashboard():
    return render_template('dashboard.html')


# Add Post page
@app.route('/add-post', methods = ['GET','POST'])
@login_required
def add_post():
    form = postform()
    if form.validate_on_submit():
        poster = current_user.id
        post = Posts(title=form.title.data,
                     poster_id = poster,
                     content=form.content.data,
                     slug=form.slug.data)

        # Now after click submit button we want to redirecr ro that page and clear the form from the things we typed in
        form.title.data=''
        form.content.data=''
        form.slug.data=''

        # Add Post data to database
        db.session.add(post)
        db.session.commit()

        flash("Post submitted successfully")

    # Redirect the web page
    return render_template('add_post.html',form=form)


# Create a page for list all posts in
@app.route('/posts')
def posts_func():
    # Grab all the posts from database
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html',posts=posts)


# Create a separeted page for each post
@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template('post.html',post=post)


# Add Edit option to posts
@app.route('/posts/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit(id):
    post = Posts.query.get_or_404(id)
    form = postform()
    if form.validate_on_submit():
        post.title = form.title.data
        #post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data

        # Update data base
        db.session.add(post)
        db.session.commit()
        flash("Post Updated !")
        return redirect(url_for('post',id=post.id))

    if current_user.id == post.poster_id:

        # After Clicking on edit button, we want to all informations to be there written.
        form.title.data = post.title
        #form.author.data = post.author
        form.slug.data = post.slug
        form.content.data = post.content

        return render_template('edit.html',form=form)
    else:
        flash("Sorry This post isn`t yours, You cant edit it !")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)

# Delete Post
@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.poster.id:
        try:
            # Updata Database
            db.session.delete(post_to_delete)
            db.session.commit()

            flash("Post Deleted !")

            # Where to return after deletion
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('posts.html', posts=posts)
        except:
            flash("Sorry There was a problem, Try again")
            return render_template('posts.html', posts=posts)
    else:
        # Where to return after deletion
        posts = Posts.query.order_by(Posts.date_posted)
        flash("Sorry this post isn`t yours, You can`t delete it")
        return render_template('posts.html', posts=posts)




# Json file
@app.route('/date')
def get_current_date():
    favourite_pizza = {
        'john:': 'pepronie',
        'mary:': 'cheese',
        'tim:': 'mushroom'
    }
    return favourite_pizza


# Delete function
@app.route('/delete/<int:id>')
def delete(id):
    name = None
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted sucessfully!!')
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form, name=name, our_users=our_users)

    except:
        flash('There was a problem happened')
        return render_template('add_user.html', form=form, name=name, our_users=our_users)


# Update database
@app.route('/update/<int:id>', methods = ['GET','POST']) # when a user accesses a URL like '/update/1', the function will be triggered, and '1' will be passed as the id parameter.
@login_required
def update(id): #The id corresponds to the value provided in the URL, such as '/update/1'.
    form = UserForm()
    name_to_update = Users.query.get_or_404(id) # It queries the database (likely a database table named 'Users') to retrieve a user with the specified id. If no user with the given id is found, a 404 error response is returned.
    if request.method == "POST": # This block of code checks if the HTTP request method is POST, which means that the form has been submitted.
        name_to_update.first_name = request.form['first_name']
        name_to_update.second_name = request.form['second_name']
        name_to_update.email = request.form['email']
        name_to_update.favourite_color = request.form['favourite_color']
        name_to_update.about_author = request.form['about_author']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash('Information updated successfulty')
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update,id=id)
        except:
            flash('Some thing happened worng ! Pls try again ')
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update,id=id)
    else:
        return render_template("update.html",
                               form=form,
                               name_to_update=name_to_update,
                               id = id)

# Create Route
@app.route('/user/add',methods=['GET','POST'])

# Add user Form
def add_user():
    name = None
    first_name = None
    second_name = None
    about_author = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash password
            hash_pw = generate_password_hash(form.password_hash.data,'pbkdf2:sha256')
            user = Users(first_name=form.first_name.data,second_name=form.second_name.data,email=form.email.data,favourite_color=form.favourite_color.data,password_hash =hash_pw,username=form.username.data,about_author=form.about_author.data)
            db.session.add(user)
            db.session.commit()
        name = form.username.data
        first_name = form.first_name.data
        second_name = form.second_name.data
        about_author = form.about_author.data
        form.first_name.data = ''
        form.second_name.data = ''
        form.email.data = ''
        form.favourite_color = ''
        form.password_hash = ''
        form.username.data = ''
        form.about_author.data = ''
        # Process the form data and add a new user to the database here
        flash("User added successfully")
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html',form=form,name=name,our_users=our_users)


@app.route('/')

#def index():
#    return "<h1> Hello world!</h1>"

def index():
    first_name = 'Hossam'
    stuff = 'this is bold text'
    favourite = ['Arabic','Math','English',41]
    return render_template("index.html",
                           first_name=first_name,
                           #stuff=stuff,
                           favourite=favourite)

@app.route('/user/<name>')

def user(name):
    return render_template("user.html", user_name=name)

# Create custom error pages
# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")


# Internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html")


# Create a passwrd test page Page
@app.route('/test_pw',methods=['GET','POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm()
    # Validate Form
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data

        form.email.data = ''
        form.password_hash.data = ''
        # check up user by email
        pw_to_check = Users.query.filter_by(email=email).first()

        # Check hash password
        passed = check_password_hash(pw_to_check.password_hash, password)

        #flash("Correctly submited the form !")
    return render_template('test_pw.html',
                           email=email,
                           password=password,
                           pw_to_check=pw_to_check,
                           passed = passed,
                           form=form)



# Name page
@app.route('/name',methods=['GET','POST'])
def name():
    name = None
    form = NameForm()
    # Validate Form
    if form.validate_on_submit():
        name = form.name.data

        form.name.data = ''
        flash("Correctly submited the form !")
    return render_template('name.html',
                           name = name,
                           form= form)

# -----------------------------------------------------------------------------
# Models Section


# Blog Bost model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(225))
    content = db.Column(db.Text)# This is the content of the bost must be Text not String
    #author = db.Column(db.String(225)) # The name of the post owner
    date_posted = db.Column(db.DateTime,default=datetime.utcnow()) #Data and time of the post
    slug = db.Column(db.String(225)) # عشان لما نيجي نعمل سيرش علي بوست منعملش سيرش ب ال id بتاعه لا نعمل سيرش بكلام عادي

    # Foreign key to link Users (refer to primary key of the user id)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    first_name = db.Column(db.String(20),nullable=False)
    second_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120),nullable=False,unique=True)
    favourite_color = db.Column(db.String(120))
    about_author = db.Column(db.Text,nullable = True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    profile_pic = db.Column(db.String(120), nullable=True)


    # User Can have many posts
    posts = db.relationship('Posts', backref='poster')

    # do password stuff

    # This line creates a column in our database for storing users hash passwords
    password_hash = db.Column(db.String(128))
    #password_hash = db.Column(VARBINARY(128))
    #This is a property decorator in Python. It means that you can access password as if it were an attribute of the object, but you can't read it directly. If someone tries to read the password, an error will be raised, indicating that it's not a readable attribute. This is done for security reasons to prevent accidental exposure of the plain text password.
    @property
    def password(self):
        raise AttributeError('Password not readable attribute')


    #When you set a new password, it doesn't get stored as-is in the password attribute; instead, it's processed through a password hashing function. The generate_password_hash function takes the plain text password and creates a secure hash from it, which is then stored in the password_hash database column.
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)


    #The verify_password method is used for verifying a user's password during login. When a user attempts to log in, the plain text password they provide is compared to the stored hash in the password_hash column. The check_password_hash function checks if the provided password matches the stored hash. If it does, the login is successful; if not, it fails.
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

        # Create A String

    def __repr__(self):
        return '<User %r>' % self.username



if __name__ == '__main__':
    app.run(debug=True)
