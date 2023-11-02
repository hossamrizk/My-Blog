# flask --app hello.py --debug run

from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')

#def index():
#    return "<h1> Hello world!</h1>"


def index():
    first_name = 'Hossam'
    stuff = 'this is bold text'
    favourite = ['Arabic','Math','English',41]
    return render_template("index.html",
                           first_name=first_name,
                           stuff=stuff,
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