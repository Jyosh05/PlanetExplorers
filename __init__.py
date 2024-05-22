from flask import Flask, render_template
from flaskext.mysql import MySQL

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_super_secret_key'

mysql = MySQL(app)
#Aloysius Portion
def input_validation():
    pass
def get_info():
    pass


def update_info():
    pass

def add_info():
    pass

def delete_info():
    pass







@app.route('/')
def home():
    return render_template("home.html") # need to create template


if __name__ == '__main__':
    app.run()