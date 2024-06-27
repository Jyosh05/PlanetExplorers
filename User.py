from utils import *
from flask import render_template, redirect,url_for, request, flash
import urllib.parse
@app.route('/')
@limiter.limit("10 per minute")
def home():
    return render_template("home.html")  # need to create template

@app.route('/learnerHome')
@roles_required('student')
def learnerHome():
    if 'user' in session and 'username' in session['user']:
        username = session['user']['username']
        user = userSession(username)
        if user:
            print(f'user {username} is logged in')
            return render_template("User/profile.html", user=user)
        else:
            flash("User not found in database")
            return redirect(url_for('login'))  # Redirect to login if user not found
    else:
        flash("User session not found")
        return redirect(url_for('login'))  # Redirect to login if session not found


@app.route('/login', methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        try:
            username = request.form.get("username")
            password = request.form.get("password")
            if not username or not password:
                raise ValueError("username and password are required")
            input_validation(username)
            input_validation(password)


            query = "SELECT * FROM users WHERE username = %s"
            mycursor.execute(query, (username,))
            user = mycursor.fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                session['user'] = {'username': user[1], 'role': user[9]}
                regenerate_session()
                log_this("login successful", user[0])  # Pass user_id instead of the whole user tuple
                # return render_template("profile.html")
                role = user[9]

                print(f"Logged in user role: {role}")
                return redirect(url_for(role_redirects.get(role, 'home')))
            else:
                log_this("Invalid username or password")
                print("Invalid username or password")
        except ValueError as e:
            print(f"Error: {e}")
            log_this("Runtime error during login")

    # Encode sensitive data in the URL for GET requests
    if request.method == "GET" and 'username' in request.args and 'password' in request.args:
        encoded_username = urllib.parse.quote(request.args.get("username"))
        encoded_password = urllib.parse.quote(request.args.get("password"))
        encoded_url = f"/login?username={encoded_username}&password={encoded_password}"
        return redirect(encoded_url)

    return render_template("User/login.html")