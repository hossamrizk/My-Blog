# This file Contains all Forms we have

# Imports
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from flask_ckeditor import CKEditorField
from wtforms import StringField, DateField,SubmitField,PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import data_required, EqualTo, Length, DataRequired
from wtforms.widgets import TextArea


# Create Search Form

class SearchForm(FlaskForm):
    searched = StringField("searched", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create login form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Submit")


# Create Posts Form
class postform(FlaskForm):
    title =StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Content',validators=[DataRequired()])
    author = StringField('Author')
    #content = StringField('Content', validators=[DataRequired()],widget=TextArea())
    slug = StringField('slug', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Create User form
class UserForm(FlaskForm):
    first_name = StringField('First Name:',
                       validators=[data_required()])
    second_name = StringField('Second Name:',
                       validators=[data_required()])

    username = StringField('Username:',
                       validators=[data_required()])
    email = StringField('E-mail:',
                       validators=[data_required()])
    dof = DateField('Date or birth:',
                    validators=[data_required()])

    location = StringField('Country:',
                           validators=[data_required()])
    bio = TextAreaField('About Me')
    password_hash = PasswordField('password',validators=[data_required(),
                                                         EqualTo('password_hash2',message='Password Must Match!')])
    password_hash2 =PasswordField('Confirm Password',validators=[data_required()])

    profile_pic = FileField("Profile Picture")
    submit = SubmitField('Submit')

# Password Form
class PasswordForm(FlaskForm):
    email = StringField('Enter Your email Please.',
                        validators=[data_required()])
    password_hash = PasswordField('Enter Your password Please.',
                                    validators=[data_required()])

    submit = SubmitField('Submit')


# Create a form class
class NameForm(FlaskForm):
    name = StringField('Enter Your Name Please.',
                       validators=[data_required()])
    submit = SubmitField('Submit')

