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
            mycursor.execute("SELECT profilePic FROM users WHERE username = %s", (username,))
            profile_pic = mycursor.fetchone()

            if profile_pic and profile_pic[0]:
                profile_pic_url = url_for('static', filename=profile_pic[0])
            else:
                profile_pic_url = url_for('static', filename='img/default_profile_pic.png')

            # You can store the profile_pic_url in the session or pass it to the template
            session['profile_pic_url'] = profile_pic_url
            return render_template("User/profile.html", user=user, profile_pic_url=profile_pic_url)
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

            if user:
                lockout_time = user[13]
                if lockout_time and datetime.now() < lockout_time:
                    remaining_time = (lockout_time - datetime.now()).seconds // 60
                    flash(f'Your account is locked. Please try again later in {remaining_time} minutes or contact admin.', 'error')
                    return redirect(url_for('login'))

                if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                    session['user'] = {'id': user[0], 'username': user[1], 'role': user[9]}
                    mycursor.execute(
                        'UPDATE users SET failed_login_attempts = 0, locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s',
                        (user[0],))
                    mydb.commit()
                    regenerate_session()
                    log_this("login successful", user[0])

                    role = user[9]
                    print(f"Logged in user role: {role}")
                    return redirect(url_for(role_redirects.get(role, 'home')))
                else:
                    failed_login_attempts = user[12] + 1
                    lockout_duration = 0

                    if failed_login_attempts == 3:
                        lockout_duration = 15  # 15 minutes for 3 failed attempts
                    elif failed_login_attempts > 3:
                        lockout_duration = 15 * (failed_login_attempts - 2)  # 15 minutes for each attempt after the third

                    locked_until = datetime.now() + timedelta(minutes=lockout_duration) if lockout_duration else None
                    unlock_token = generate_unlock_token()
                    mycursor.execute(
                        'UPDATE users SET failed_login_attempts = %s, locked = TRUE, lockout_time = %s, unlock_token = %s WHERE id = %s',
                        (failed_login_attempts, locked_until, unlock_token, user[0]))
                    mydb.commit()

                    if lockout_duration:
                        flash(f'Account is locked for {lockout_duration} minutes due to multiple failed login attempts.', 'danger')
                        send_unlock_email(user[3], unlock_token)
                    else:
                        flash('Invalid credentials. Please try again.', 'danger')

                    return redirect(url_for('login'))
            else:
                # Query all users from the database
                query = "SELECT id, password, failed_login_attempts, email FROM users"
                mycursor.execute(query)
                users = mycursor.fetchall()

                # Iterate through users to find a match
                for user in users:
                    if bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                        user_id = user[0]
                        failed_login_attempts = user[2] + 1
                        lockout_duration = 0

                        if failed_login_attempts == 3:
                            lockout_duration = 15  # 15 minutes for 3 failed attempts
                        elif failed_login_attempts > 3:
                            lockout_duration = 15 * (
                                        failed_login_attempts - 2)  # 15 minutes for each attempt after the third

                        locked_until = datetime.now() + timedelta(
                            minutes=lockout_duration) if lockout_duration else None
                        unlock_token = generate_unlock_token()

                        mycursor.execute(
                            'UPDATE users SET failed_login_attempts = %s, locked = TRUE, lockout_time = %s, unlock_token = %s WHERE id = %s',
                            (failed_login_attempts, locked_until, unlock_token, user_id)
                        )
                        mydb.commit()

                        if lockout_duration:
                            flash(
                                f'Account is locked for {lockout_duration} minutes due to multiple failed login attempts.',
                                'danger')
                            send_unlock_email(user[3], unlock_token)
                        else:
                            flash('Invalid credentials. Please try again.', 'danger')
                            log_this("Invalid username or password")

                        return redirect(url_for('login'))


        except ValueError as e:
            print(f"Error: {e}")
            log_this(f"Runtime error during login: {e}")
            flash(f"Error: {e}", 'danger')
            return redirect(url_for('login'))

    # Encode sensitive data in the URL for GET requests (Not recommended)
    if request.method == "GET" and 'username' in request.args and 'password' in request.args:
        encoded_username = urllib.parse.quote(request.args.get("username"))
        encoded_password = urllib.parse.quote(request.args.get("password"))
        encoded_url = f"/login?username={encoded_username}&password={encoded_password}"
        return redirect(encoded_url)

    return render_template("User/login.html")

@app.route('/unlock_account/<token>')
def unlock_account(token):
    mycursor.execute('SELECT * FROM users WHERE unlock_token = %s AND locked = TRUE AND lockout_time > %s', (token, datetime.now()))
    user = mycursor.fetchone()

    if user:
        mycursor.execute('UPDATE users SET failed_login_attempts = 0, locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s', (user[0],))
        mydb.commit()
        flash('Your account has been unlocked. You can now log in.', 'success')

    else:
        flash('Invalid or expired unlock token', 'danger')

    return redirect(url_for('login'))

def send_unlock_email(email, token):
    subject = 'Unlock Your Account'
    unlock_url = url_for('unlock_account', token=token, _external=True)
    template = f'<p>Hi,</p>' \
               f'<p>You have requested to unlock your account. Please click the link below to unlock your account:</p>' \
               f'<p><a href="{unlock_url}">{unlock_url}</a></p>' \
               f'<p>If you did not request this, please ignore this email.</p>' \
               f'<p>Best regards,<br>PlanetExplorers Team</p>'
    send_reset_link_email(email, subject, template)

@app.route('/teacher/create_module')
@roles_required("teacher")
def create_module():
    return render_template("Teacher/module.html")
