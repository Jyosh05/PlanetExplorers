import time

import mysql.connector

from utils import *
from flask import render_template, redirect, url_for, request, flash
import urllib.parse
from werkzeug.utils import secure_filename
import os
from flask import jsonify

@app.route('/')
def home():
    return render_template("home.html")  # need to create template


@app.route('/learnerHome')
@roles_required('student')
def learnerHome():
    return render_template("User/studentHome.html")

@app.route('/profile')
def profile():
    user = session.get('user')
    login_method = session.get('login_method')

    if not user or not login_method:
        flash('Please log in to access your profile', 'danger')
        return redirect(url_for('login'))

    if login_method == 'login':
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
        return render_template('User/profile.html', user=user, profile_pic_url=profile_pic_url)

    elif login_method == 'google':
        return render_template('User/google_profile.html', user=user)

    else:
        flash('Unknown login method', 'danger')
        return redirect(url_for('login'))


@app.route('/login', methods=["GET", "POST"])
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
                    flash(f'Your account is locked. Please try again later in {remaining_time} minutes or contact admin.', 'danger')
                    return redirect(url_for('login'))

                if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                    session['user'] = {'id': user[0], 'username': user[1], 'role': user[9]}
                    session['login_method'] = 'login'
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
                        lockout_duration = 2  # 2 minutes for 3 failed attempts
                    elif failed_login_attempts > 3:
                        lockout_duration = 2 * (
                                failed_login_attempts - 2)  # 2 minutes for each attempt after the third

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
                            lockout_duration = 2  # 2 minutes for 3 failed attempts
                        elif failed_login_attempts > 3:
                            lockout_duration = 2 * (
                                        failed_login_attempts - 2)  # 2 minutes for each attempt after the third

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

@app.route('/login/google')
def login_with_google():
    redirect_uri = url_for('authorize', _external= True)
    return google.authorize_redirect(redirect_uri,prompt='consent')

@app.route('/auth/callback')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('https://www.googleapis.com/oauth2/v2/userinfo')
    print(resp)
    user_info = resp.json()
    mycursor.execute("SELECT * FROM oauth WHERE googleid = %s",(user_info['id'],))
    user = mycursor.fetchone()
    print(user_info['id'])
    if not user:
        mycursor.execute("""
            INSERT INTO oauth(googleid, email, email_verified,name, profilePic)
            VALUES(%s,%s,%s,%s,%s)
        """,(str(user_info['id']), user_info['email'], user_info['verified_email'], user_info.get('name'), user_info.get('picture')))
        mydb.commit()
    session['user'] = user_info
    session['login_method'] = 'google'
    return render_template('User/studentHome.html', user='student')



@app.route('/unlock_account/<token>')
def unlock_account(token):
    mycursor.execute('SELECT * FROM users WHERE unlock_token = %s AND locked = TRUE AND lockout_time > %s', (token, datetime.now()))
    user = mycursor.fetchone()

    if user:
        mycursor.execute('UPDATE users SET locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s', (user[0],))
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


@app.route('/teacher/create_module', methods=['GET', 'POST'])
@roles_required("teacher")
def create_module():
    if request.method == 'GET':
        return render_template("Teacher/module.html")

    if request.method == 'POST':
        try:
            data = request.get_json()
            module_name = data.get('module_name')
            questions = data.get('questions')
            user_id = session['user'].get('id')
            print(user_id)
            timestamp = datetime.now()
            print(timestamp)

            if not module_name or not questions or len(questions) < 1:
                return jsonify({'error': "Module name and at least 1 question are required"}), 400

            # Your validation function might raise exceptions, so handle them
            input_validation(module_name)
            for question in questions:
                input_validation(
                    question.get('question'),
                    question.get('choice_a'),
                    question.get('choice_b'),
                    question.get('choice_c'),
                    question.get('choice_d'),
                    question.get('answer')
                )

            cursor = mydb.cursor()
            cursor.execute("INSERT INTO modules(module_name,teacher_id,created_at) VALUES (%s,%s,%s)", (module_name,user_id,timestamp))
            module_id = cursor.lastrowid

            for question in questions:
                question_text = question.get('question')
                choice_a = question.get('choice_a')
                choice_b = question.get('choice_b')
                choice_c = question.get('choice_c')
                choice_d = question.get('choice_d')
                answer = question.get('answer')
                explorer_points = question.get('explorerpoints')

                if not question_text or not choice_a or not choice_b or not choice_c or not choice_d or not answer or explorer_points is None:
                    return jsonify({ "error": "Each question must have a question text, four choices, a correct answer, and explorerpoints."}), 400
                print(f"Inserting into questions with values: {module_id}, {question_text}, {choice_a}, {choice_b}, {choice_c}, {choice_d}, {answer}, {explorer_points}")

                cursor.execute(
                    "INSERT INTO questions(module_id,question,choice_a,choice_b,choice_c,choice_d,answer,explorer_points) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (module_id, question_text, choice_a, choice_b, choice_c, choice_d, answer, explorer_points)
                )
                mydb.commit()

            return jsonify({"message": "Module created successfully!"}), 200

        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except mysql.connector.Error as err:
            mydb.rollback()
            return jsonify({"error": "Database error: " + str(err)}), 500
        except Exception as e:
            return jsonify({"error": "An unexpected error has occurred: " + str(e)}), 500


@app.route('/teacherProfile')
@roles_required('teacher')
def teacherProfile():
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
    return render_template('Teacher/teacherProfile.html', user=user, profile_pic_url=profile_pic_url)

@app.route('/updateTeacherProfile', methods=['GET', 'POST'])
@roles_required('teacher')
def updateTeacherProfile():
    if 'user' in session and 'username' in session['user']:
        username = session['user']['username']
        if request.method == 'POST':
            new_username = request.form.get('username')
            name = request.form.get('name')
            email = request.form.get('email')
            age = request.form.get('age')
            address = request.form.get('address')
            phone = request.form.get('phone')
            if new_username or name or email or age or address or phone:
                try:
                    mycursor.execute(
                        "UPDATE users SET username = %s, name = %s, email = %s, age = %s, address = %s, phone = %s WHERE username = %s",
                        (new_username, name, email, age, address, phone, username))
                    mydb.commit()
                    flash('Teacher information updated successfully', 'success')
                except Exception as e:
                    flash(f'Error updating user information: {str(e)}', 'error')
                    return redirect(url_for('updateTeacherProfile'))

            # Handle profile picture upload
            if 'image' in request.files:
                file = request.files['image']
                if file.filename == '':
                    flash('No profile picture selected', 'error')
                elif file and allowed_file(file.filename):
                    if file.content_length < 32 * 1024 * 1024:  # Check if file size is less than 32 MB
                        # Save the file to a temporary location first
                        filename = secure_filename(file.filename)
                        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{filename}')
                        file.save(temp_filepath)

                        try:
                            file_id = scan_file(temp_filepath)
                        except Exception as e:
                            flash(f'Error uploading file to VirusTotal: {str(e)}', 'error')
                            os.remove(temp_filepath)
                            return redirect(url_for('updateTeacherProfile'))

                        if file_id:
                            flash('Give us a moment! We are scanning your file contents', 'info')

                            start_time = time.time()
                            timeout = 300  # 5 minutes timeout
                            while time.time() - start_time < timeout:
                                try:
                                    report = get_scan_report(file_id)
                                except Exception as e:
                                    flash(f'Error retrieving scan report: {str(e)}', 'error')
                                    break

                                if report:
                                    attributes = report.get('data', {}).get('attributes', {})
                                    if attributes.get('status') == 'completed':
                                        scan_results = attributes.get('results', {})
                                        is_non_malicious = all(
                                            result.get('category') != 'malicious' for result in scan_results.values()
                                        )

                                        if is_non_malicious:
                                            # Rename and move the file to its final location
                                            final_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                                            os.rename(temp_filepath, final_filepath)
                                            image_path = f"img/{filename}"
                                            try:
                                                mycursor.execute("UPDATE users SET profilePic = %s WHERE username = %s",
                                                                 (image_path, username))
                                                mydb.commit()
                                                flash('Profile picture scanned and uploaded successfully!', 'success')
                                            except Exception as e:
                                                flash(f'Error updating profile picture: {str(e)}', 'error')
                                            return redirect(url_for('updateTeacherProfile'))
                                        else:
                                            flash('The file is malicious and has not been saved.', 'error')
                                            os.remove(temp_filepath)  # Remove the file if it is malicious
                                            return redirect(url_for('updateTeacherProfile'))
                                else:
                                    flash('Failed to retrieve scan report.', 'error')
                                    break
                                time.sleep(10)  # wait for 10 seconds before retrying
                            else:
                                flash('Scan is not yet complete. Try again later.', 'error')
                                os.remove(temp_filepath)  # Clean up temporary file if scan is incomplete
                        else:
                            flash('Failed to upload file to VirusTotal for scanning.', 'error')
                            os.remove(temp_filepath)
                    else:
                        flash('Profile Picture must be less than 32 MB', 'error')
                else:
                    flash('Invalid file format. Allowed formats are png, jpg, jpeg, gif.', 'error')

            # Fetch updated user data
            user = userSession(new_username if new_username else username)
            if user:
                session['user']['username'] = new_username if new_username else username  # Update session with new username if changed
                return render_template("Teacher/teacherProfile.html", user=user)
            else:
                flash("User not found in database after update")
                return redirect(url_for('login'))  # Redirect to log in if user not found after update
        else:
            # GET request handling
            user = userSession(username)
            return render_template("Teacher/updateTeacherProfile.html", user=user)  # Render form with current user data prepopulated
    else:
        flash("User session not found")
        return redirect(url_for('login'))


@app.route('/updateTeacherPassword', methods=['POST', 'GET'])
@roles_required('teacher')
def updateTeacherPassword():
    if 'user' in session:
        if 'username' in session['user']:
            username = session['user']['username']
            print("Session data:", session['user'])  # Debug statement
            print("Username from session:", username)  # Debug statement

            if request.method == 'POST':
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')

                if new_password and confirm_password:
                    if new_password == confirm_password:
                        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                        try:
                            # Check if the new hashed password already exists in the database
                            print("Checking if the new hashed password already exists in the database.")  # Debug statement
                            mycursor.execute("SELECT password FROM users")
                            all_passwords = mycursor.fetchall()

                            # Check if the new password matches any existing password
                            password_exists = False
                            for stored_password in all_passwords:
                                if bcrypt.checkpw(new_password.encode('utf-8'), stored_password[0].encode('utf-8')):
                                    password_exists = True
                                    break

                            if password_exists:
                                flash('Password already exists. Please create another password', 'danger')
                                return redirect(url_for('updateTeacherPassword'))
                            else:
                                try:
                                    print(f"Updating password for username: {username}")  # Debug statement
                                    print(f"Hashed password: {hashed_password}")  # Debug statement
                                    mycursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
                                    mydb.commit()
                                    flash('Password updated successfully', 'success')
                                    print('Password updated successfully')  # Debug statement

                                    # # Refresh session user data
                                    # user = userSession(username)
                                    # if user:
                                    #     session['user'] = user  # Update session with refreshed user data
                                    # else:
                                    #     flash('User not found in database after update', 'error')
                                    #     return redirect(url_for('login'))

                                except Exception as e:
                                    flash(f'Error updating password: {str(e)}', 'danger')
                                    print(f'SQL Update Error: {str(e)}')  # Debug statement
                                    return redirect(url_for('updateTeacherPassword'))
                        except Exception as e:
                            flash(f'Error checking existing password: {str(e)}', 'danger')
                            print(f'SQL Select Error: {str(e)}')  # Debug statement
                            return redirect(url_for('updateTeacherPassword'))
                    else:
                        flash('Passwords do not match.', 'danger')
                        return redirect(url_for('updateTeacherPassword'))
                else:
                    flash('Please provide both password fields.', 'danger')
                    return redirect(url_for('updateTeacherPassword'))
        else:
            flash("Username not found in session")
            return redirect(url_for('login'))
    else:
        flash("User session not found")
        return redirect(url_for('login'))

    return render_template("Teacher/updateTeacherPassword.html")



@app.route('/user/orders')
@roles_required('student', 'teacher')
def user_orders():
    user_id = session['user']['id']
    mycursor.execute("""
        SELECT o.id, o.total_price, o.status
        FROM orders o
        WHERE o.user_id = %s
    """, (user_id,))
    orders = mycursor.fetchall()
    return render_template('User/order_history.html', orders=orders)


@app.route('/logout')
def logout():
    print(session)
    session.pop('user',None)
    print("Logged out successfully")
    print(session)
    return redirect(url_for('login'))
