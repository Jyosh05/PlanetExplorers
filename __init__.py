from flask import Flask, render_template, request, redirect, url_for,  session, flash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_super_secret_key'


@app.route('/')
def home():
    return render_template("home.html") # need to create template


if __name__ == '__main__':
    app.run()