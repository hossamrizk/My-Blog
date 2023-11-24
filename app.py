# flask --app app.py --debug run

from flask import Flask, render_template, flash, request, redirect, url_for
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_migrate import Migrate
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
import uuid as uuid
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123456789@localhost/our_users'


# Heroku Database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://ajvxwrluwchsxv:b812c35ac60948474a1dcb6c30d0a8e7213699ee44dbd02556f775ee0a17de1a@ec2-107-21-67-46.compute-1.amazonaws.com:5432/d5qn954vq44lqe'


#Create Secret Key
app.config['SECRET_KEY'] = "write password"


UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


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


@app.route('/admin_delete_post/<int:post_id>',methods=['GET','POST'])
@login_required

def admin_delete_post(post_id):
    # Logic to allow the admin to delete any post
    if current_user.id == 7:  # Replace 7 with your admin user ID
        post = Posts.query.get(post_id)  # Assuming you have a Post model
        # Logic to delete the post
        # Delete the post from the database
        flash("Post deleted by admin.")
    else:
        flash("You are not authorized for this action.")
    return redirect(url_for('admin'))  # Redirect back to the admin page

# Create search function
@app.route('/search', methods=["POST"])
def search():
    form = SearchForm()
    if form.validate_on_submit():
        searched = form.searched.data

        # Query posts and users for matches
        posts_results = Posts.query.filter(Posts.title.like('%' + searched + '%')).all()

        users_results = Users.query.filter(or_(Users.username.like('%' + searched + '%'),
                                              Users.first_name.like('%' + searched + '%'),
                                              Users.second_name.like('%' + searched + '%'))).all()

        # Combine and display search results
        return render_template("search.html",
                               form=form,
                               searched=searched,
                               posts_results=posts_results,
                               users_results=users_results)

    # Default response or error handler
    return render_template("404.html")


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
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.first_name = request.form['first_name']
        name_to_update.second_name = request.form['second_name']
        name_to_update.email = request.form['email']
        name_to_update.username = request.form['username']
        name_to_update.bio = request.form['bio']
        name_to_update.dof = request.form['dof']

        # Check for profile pic
        if request.files['profile_pic']:
            name_to_update.profile_pic = request.files['profile_pic']

            # Grab Image Name
            pic_filename = secure_filename(name_to_update.profile_pic.filename)
            # Set UUID
            pic_name = str(uuid.uuid1()) + "_" + pic_filename
            # Save That Image
            saver = request.files['profile_pic']

            # Change it to a string to save to db
            name_to_update.profile_pic = pic_name
            try:
                db.session.commit()
                saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
                flash("User Updated Successfully!")
                return render_template("dashboard.html",
                                       form=form,
                                       name_to_update=name_to_update)
            except:
                flash("Error!  Looks like there was a problem...try again!")
                return render_template("dashboard.html",
                                       form=form,
                                       name_to_update=name_to_update)
        else:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("dashboard.html",
                                   form=form,
                                   name_to_update=name_to_update)
    else:
        return render_template("dashboard.html",
                               form=form,
                               name_to_update=name_to_update,
                               id=id)

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
@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Posts.query.get_or_404(id)
    form = postform()

    if form.validate_on_submit():
        post.title = form.title.data
        post.slug = form.slug.data
        post.content = form.content.data

        try:
            # Update database
            db.session.commit()
            flash("Post Updated!")
            return redirect(url_for('post', id=post.id))
        except:
            flash("Sorry, there was a problem updating the post.")
            return redirect(url_for('edit', id=post.id))

    if current_user.id == post.poster_id or current_user.id == 7:  # Admin user ID is 7
        # Populate form fields with post data
        form.title.data = post.title
        form.slug.data = post.slug
        form.content.data = post.content

        return render_template('edit.html', form=form)
    else:
        flash("Sorry, you can't edit this post.")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)


# Delete Post
@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    if current_user.id == 7 or post_to_delete.poster.id:  # Admin user ID is 7
        try:
            # Update Database
            db.session.delete(post_to_delete)
            db.session.commit()

            flash("Post Deleted by admin!")
        except:
            flash("Sorry, there was a problem deleting the post.")
    elif current_user.id == post_to_delete.poster.id:
        try:
            # Update Database
            db.session.delete(post_to_delete)
            db.session.commit()

            flash("Post Deleted!")
        except:
            flash("Sorry, there was a problem deleting the post.")
    else:
        flash("Sorry, you can't delete this post.")

    # Where to return after deletion or if the deletion fails
    posts = Posts.query.order_by(Posts.date_posted).all()
    return render_template('posts.html', posts=posts)





# Json file

@app.route('/json')
def Personal_info():
    admin_info = {
        'Education:': "Bachelor's degree in Artificial Intelligence",
        'Age:': '23',
        'From:': 'egypt',
        'Name:': 'Hossam Rizk'
    }
    return admin_info


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
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)

    if request.method == "POST":
        name_to_update.first_name = request.form['first_name']
        name_to_update.second_name = request.form['second_name']
        name_to_update.email = request.form['email']
        name_to_update.dof = request.form['dof']
        name_to_update.location = request.form['location']
        name_to_update.bio = request.form['bio']
        name_to_update.username = request.form['username']

        # Check if profile_pic was included in the request.files
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            if profile_pic.filename != '':
                pic_filename = secure_filename(profile_pic.filename)
                pic_name = str(uuid.uuid1()) + "_" + pic_filename

                # Save the file to a specific directory or storage location
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))

                # Update the user's profile with the file name or path in the database
                name_to_update.profile_pic = pic_name

        try:
            db.session.commit()
            flash('Information updated successfully')
        except Exception as e:
            flash('Something went wrong! Please try again.')
            print(e)  # Print the exception for debugging purposes

    return render_template("update.html", form=form, name_to_update=name_to_update, id=id)


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
            user = Users(first_name=form.first_name.data,
                         second_name=form.second_name.data,
                         email=form.email.data,
                         dof=form.dof.data,
                         location=form.location.data,
                         password_hash =hash_pw,
                         username=form.username.data,
                         bio=form.bio.data)
            db.session.add(user)
            db.session.commit()
        name = form.username.data
        first_name = form.first_name.data
        second_name = form.second_name.data
        bio = form.bio.data
        form.first_name.data = ''
        form.second_name.data = ''
        form.email.data = ''
        form.dof.data = ''
        form.location.data = ''
        form.password_hash = ''
        form.username.data = ''
        form.bio.data = ''
        # Process the form data and add a new user to the database here
        flash("User added successfully")
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html',form=form,name=name,our_users=our_users)


@app.route('/')
def main():
    return render_template("main.html",)


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


# -----------------------------------------------------------------------------
# Models Section


# Blog Bost model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(225))
    content = db.Column(db.Text)# This is the content of the bost must be Text not String
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
    dof = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(60),nullable=False)
    bio = db.Column(db.Text,nullable = True)
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
