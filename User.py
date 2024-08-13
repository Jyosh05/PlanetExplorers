import time
from random import randint
import mysql.connector
from utils import *
from flask import render_template, redirect, url_for, request, flash
import urllib.parse
from werkzeug.utils import secure_filename
import os
from flask import jsonify

@app.route('/')
def home():
    if 'user' in session:
        session.pop('user', None)
    return render_template("home.html")  # need to create template


@app.route('/learnerHome')
@limiter.limit("20 per minute")
@roles_required('student')
def learnerHome():
    try:
        with mydb.cursor() as mycursor:
            cursor = mydb.cursor(dictionary=True)
            cursor.execute("SELECT module_id, module_name FROM modules")
            modules = cursor.fetchall()
            print("Modules:", modules)
            return render_template("User/studentHome.html", modules=modules)

    finally:
        mycursor.close()



@app.route('/profile')
@limiter.limit("20 per minute")
@roles_required('student')
def profile():
    try:
        with mydb.cursor() as mycursor:
            user = session.get('user')
            login_method = session.get('login_method')

            # profile_pic = url_for('static', filename='img/default_profile_pic.png')


            if not user or not login_method:
                flash('Please log in to access your profile', 'danger')
                return redirect(url_for('login'))

            if session['login_method'] == 'login':
                if 'user' in session and 'username' in session['user']:
                    username = session['user']['username']
                    user = userSession(username)
                    if user:
                        print(f'user {username} is logged in')
                        mycursor.execute("SELECT profilePic FROM users WHERE username = %s", (username,))
                        profile_pic_url = mycursor.fetchone()

                        if profile_pic_url and profile_pic_url[0]:
                            profile_pic = url_for('static', filename=profile_pic_url[0])
                        else:
                            profile_pic = url_for('static', filename='img/default_pp.png')

                        # You can store the profile_pic_url in the session or pass it to the template
                        session['profile_pic'] = profile_pic
                    return render_template('User/profile.html', user=user, profile_pic=profile_pic)

            elif session['login_method'] == 'google':
                email = user['email']  # Assuming email is stored in the session under 'user'

                # Fetch the Google profile details from the oauth table
                mycursor.execute("""
                        SELECT email, profilePic, name, role, explorer_points
                        FROM oauth
                        WHERE email = %s
                    """, (email,))
                user_info = mycursor.fetchone()

                if user_info:
                    email, profile_pic, name, role, explorer_points = user_info
                    if not profile_pic:
                        profile_pic = url_for('static', filename='img/default_pp.png')
                    session['profile_pic'] = profile_pic
                else:
                    flash('User information not found', 'danger')
                    return redirect(url_for('login'))

                return render_template('User/google_profile.html',
                                    user=user,
                                    email=email,
                                    profilePic=profile_pic,
                                    name=name,
                                    role=role,
                                    explorer_points=explorer_points)

            else:
                flash('Unknown login method', 'danger')
                return redirect(url_for('login'))

    finally:
        mycursor.close()


@app.route('/login', methods=["GET", "POST"])
@limiter.limit("20 per minute")
def login():
    try:
        with mydb.cursor() as mycursor:
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
                            if 'user' in session and 'id' in session['user']:
                                log_this("Account locked")
                            return redirect(url_for('login'))

                        if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                            session['user'] = {'id': user[0], 'username': user[1], 'role': user[9]}
                            session['login_method'] = 'login'
                            mycursor.execute(
                                'UPDATE users SET failed_login_attempts = 0, locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s',
                                (user[0],))
                            mydb.commit()
                            regenerate_session()
                            if 'user' in session and 'id' in session['user']:
                                log_this("login successful")

                            role = user[9]
                            session['role'] = role
                            session['login_method'] = 'login'

                            return redirect(url_for(role_redirects.get(role, 'home')))


                            # usersEmail = user[3]
                            # otp_expiry = 0
                            #
                            # if usersEmail:
                            #     try:
                            #         otp = randint(100000, 999999)
                            #         otp_expiry = datetime.now() + timedelta(minutes=5)
                            #         # session['otp'] = otp
                            #         # session['otp_expiry'] = time.time() + 60  # 300 seconds = 5 minutes
                            #         mycursor.execute(
                            #             'UPDATE users SET otp = %s, otpExpiry = %s WHERE username = %s',
                            #             (otp, otp_expiry, username))
                            #         mydb.commit()
                            #
                            #         subject = 'OTP for Authentication'
                            #         template = f'Dear User\n\n<p>Here is the OTP to authenticate for your account: {otp}.' \
                            #                    f' The OTP is only valid for 5 minutes. \n\n\n Yours Truly, \nPlanetExplorers Team</p>'
                            #         send_reset_link_email(usersEmail, subject, template)
                            #         flash('OTP sent to your email.', 'success')
                            #         return redirect(url_for('otpAuthentication'))
                            #     except Exception as e:
                            #         flash(f"Failed to send verification email. Please try again. Reason: {e}")


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
                                log_this(f'Account is locked for {lockout_duration} minutes due to multiple failed login attempts.')
                                send_unlock_email(user[3], unlock_token)
                            else:
                                flash('Invalid credentials. Please try again.', 'danger')
                                log_this("Invalid username or password",user_id="unknown")

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

                                    log_this(
                                        f'Account is locked for {lockout_duration} minutes due to multiple failed login attempts.',
                                        )
                                    send_unlock_email(user[3], unlock_token)
                                else:
                                    flash('Invalid credentials. Please try again.', 'danger')
                                    log_this("Invalid username or password",user_id="unknown")

                                return redirect(url_for('login'))

                except ValueError as e:
                    print(f"Error: {e}")
                    sql_injection = f"Runtime error during login: {e}"
                    log_this(sql_injection)
                    flash(f"Error: {e}", 'danger')
                    return redirect(url_for('login'))

            # Encode sensitive data in the URL for GET requests (Not recommended)
            if request.method == "GET" and 'username' in request.args and 'password' in request.args:
                encoded_username = urllib.parse.quote(request.args.get("username"))
                encoded_password = urllib.parse.quote(request.args.get("password"))
                encoded_url = f"/login?username={encoded_username}&password={encoded_password}"
                return redirect(encoded_url)

            return render_template("User/login.html")

    finally:
        mycursor.close()

# @app.route('/otpAuthentication', methods=['POST', 'GET'])
# def otpAuthentication():
#     if 'user' in session and 'username' in session['user']:
#         username = session['user']['username']
#         if request.method == 'POST':
#             query = "SELECT * FROM users WHERE username = %s"
#             mycursor.execute(query, (username,))
#             user = mycursor.fetchone()
#
#             user_otp = request.form.get('user_otp')
#
#             # Check if the OTP is valid and has not expired
#             stored_otp = user[16]
#             expiry_time = user[17]
#
#             if stored_otp and datetime.now() < expiry_time:
#                 if user_otp == stored_otp:
#                     mycursor.execute(
#                         'UPDATE users SET otp = NULL, otpExpiry = NULL WHERE username = %s',
#                         (user[1],))
#                     mydb.commit()
#
#                     role = user[9]
#                     session['role'] = role
#                     session['login_method'] = 'login'
#
#                     return redirect(url_for(role_redirects.get(role, 'home')))
#                 else:
#                     flash("Incorrect OTP, please try again.",'danger')
#                     return render_template('otpAuthentication.html')
#             else:
#                 flash("OTP has expired. Please request a new one.", 'danger')
#                 return redirect(url_for('login'))
#
#     return render_template('otpAuthentication.html')
#

@app.route('/login/google')
@limiter.limit("20 per minute")
def login_with_google():
    redirect_uri = url_for('authorize', _external= True)
    return google.authorize_redirect(redirect_uri,prompt='consent')

@app.route('/auth/callback')
def authorize():
    try:
        with mydb.cursor() as mycursor:
            token = google.authorize_access_token()
            resp = google.get('https://www.googleapis.com/oauth2/v2/userinfo')
            print(resp)
            user_info = resp.json()
            mycursor.execute("SELECT * FROM oauth WHERE googleid = %s",(user_info['id'],))
            user = mycursor.fetchone()
            print(user_info['id'])
            role = 'student'
            if not user:
                mycursor.execute("""
                    INSERT INTO oauth(googleid, email, email_verified,name, profilePic,role)
                    VALUES(%s,%s,%s,%s,%s,%s)
                """,(str(user_info['id']), user_info['email'], user_info['verified_email'], user_info.get('name'), user_info.get('picture'),role))
                mydb.commit()
            session['user'] = user_info
            session['login_method'] = 'google'
            session['user']['role'] = role
            print(f"Session Data:{session}")

            return redirect(url_for('learnerHome'))

    finally:
        mycursor.close()



@app.route('/unlock_account/<token>')
def unlock_account(token):
    try:
        with mydb.cursor() as mycursor:
            mycursor.execute('SELECT * FROM users WHERE unlock_token = %s AND locked = TRUE AND lockout_time > %s', (token, datetime.now()))
            user = mycursor.fetchone()

            if user:
                mycursor.execute('UPDATE users SET locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s', (user[0],))
                mydb.commit()
                flash('Your account has been unlocked. You can now log in.', 'success')
                if 'user' in session and 'id' in session['user']:
                    log_this("User account has been unlocked")

            else:
                flash('Invalid or expired unlock token', 'danger')
                if 'user' in session and 'id' in session['user']:
                    log_this("User gave invalid or expired unlock token")

            return redirect(url_for('login'))
    finally:
        mycursor.close()


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
@limiter.limit("40 per minute")
@roles_required("teacher")
def create_module():
    try:
        with mydb.cursor() as mycursor:
            if request.method == 'GET':
                return render_template("Teacher/module.html")

            if request.method == 'POST':
                try:
                    data = request.get_json()
                    module_name = data.get('module_name')
                    questions = data.get('questions')
                    user_id = session['user'].get('id')
                    timestamp = datetime.now()

                    if not module_name or not questions or len(questions) < 1:
                        return jsonify({'error': "Module name and at least 1 question are required"}), 400

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
                    cursor.execute("INSERT INTO modules(module_name,teacher_id,created_at) VALUES (%s,%s,%s)", (module_name, user_id, timestamp))
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
                            return jsonify({"error": "Each question must have a question text, four choices, a correct answer, and explorerpoints."}), 400

                        cursor.execute(
                            "INSERT INTO questions(module_id,question,choice_a,choice_b,choice_c,choice_d,answer,explorer_points) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                            (module_id, question_text, choice_a, choice_b, choice_c, choice_d, answer, explorer_points)
                        )
                    mydb.commit()

                    return jsonify({"redirect": url_for("teacherHome")}), 200

                except ValueError as ve:
                    return jsonify({"error": str(ve)}), 400
                except mysql.connector.Error as err:
                    mydb.rollback()
                    return jsonify({"error": "Database error: " + str(err)}), 500
                except Exception as e:
                    return jsonify({"error": "An unexpected error has occurred: " + str(e)}), 500

    finally:
        mycursor.close()

#Update module
@app.route('/update_module/<int:module_id>', methods=['GET', 'POST'])
def update_module(module_id):
    try:
        with mydb.cursor() as mycursor:
            # Fetch the module details
            mycursor.execute("SELECT * FROM modules WHERE module_id = %s", (module_id,))
            module = mycursor.fetchone()

            # Fetch the questions related to the module
            mycursor.execute("SELECT * FROM questions WHERE module_id = %s", (module_id,))
            questions = mycursor.fetchall()

            if request.method == 'POST':
                try:
                    # Update module details
                    module_name = request.form['module_name']
                    mycursor.execute("""
                        UPDATE modules 
                        SET module_name = %s 
                        WHERE module_id = %s
                    """, (module_name, module_id))

                    # Update each question
                    for question in questions:
                        question_id = question[0]  # Assuming question_id is the first column
                        question_text = request.form[f'question_{question_id}']
                        choice_a = request.form[f'choice_a_{question_id}']
                        choice_b = request.form[f'choice_b_{question_id}']
                        choice_c = request.form[f'choice_c_{question_id}']
                        choice_d = request.form[f'choice_d_{question_id}']
                        answer = request.form[f'answer_{question_id}']
                        explorer_points = request.form[f'explorer_points_{question_id}']

                        mycursor.execute("""
                            UPDATE questions 
                            SET question = %s, choice_a = %s, choice_b = %s, choice_c = %s, choice_d = %s, answer = %s, explorer_points = %s 
                            WHERE question_id = %s AND module_id = %s
                        """, (
                        question_text, choice_a, choice_b, choice_c, choice_d, answer, explorer_points, question_id, module_id))

                    # Commit the transaction
                    mydb.commit()
                    flash('Module and questions updated successfully!', 'success')
                    return redirect(url_for('teacherHome'))
                except Exception as e:
                    mydb.rollback()
                    flash(f"An error occurred: {e}", 'danger')

            return render_template('Teacher/update_module.html', module=module, questions=questions)

    finally:
        mycursor.close()

@app.route('/student/module/<int:module_id>', methods=['GET'])
@roles_required('student')
def get_module_questions(module_id):
    cursor = mydb.cursor(dictionary=True)
    cursor.execute("SELECT question_id, question, choice_a, choice_b, choice_c, choice_d FROM questions WHERE module_id = %s", (module_id,))
    questions = cursor.fetchall()
    return render_template('User/student_module_question.html', questions=questions, module_id=module_id)


@app.route('/student/module/<int:module_id>/submit', methods=['POST'])
@roles_required('student')
def submit_answers(module_id):
    try:
        # Retrieve the submitted answers
        answers = request.get_json()
        print(f"Received answers: {answers}")

        # Get the user ID from the session
        user_id = session['user'].get('id')
        print(f"User ID: {user_id}")

        if not user_id:
            return jsonify({"error": "User not authenticated."}), 401

        cursor = mydb.cursor(dictionary=True)

        # Fetch the correct answers and points for the module
        cursor.execute("SELECT question_id, answer, explorer_points FROM questions WHERE module_id = %s", (module_id,))
        questions = cursor.fetchall()
        print(f"Fetched questions: {questions}")

        correct_answers = 0
        total_explorer_points = 0
        wrong_questions = []

        # Create dictionaries for quick lookup
        correct_answers_dict = {str(q['question_id']): q['answer'] for q in questions}
        points_dict = {str(q['question_id']): q['explorer_points'] for q in questions}
        print(f"Correct answers dictionary: {correct_answers_dict}")
        print(f"Points dictionary: {points_dict}")

        # Process user answers
        for question_id, user_answer in answers.items():
            if not question_id.startswith('question_'):
                continue  # Skip invalid keys

            # Extract numeric part of question_id
            question_id_num = question_id.split('_')[1]
            correct_answer = correct_answers_dict.get(question_id_num)
            explorer_points = points_dict.get(question_id_num, 0)

            print(f"Processing question_id: {question_id_num}")
            print(f"User answer: {user_answer}")
            print(f"Correct answer: {correct_answer}")
            print(f"Explorer points: {explorer_points}")

            if user_answer == correct_answer:
                correct_answers += 1
                total_explorer_points += explorer_points
            else:
                wrong_questions.append(question_id_num)  # Collect question_id for wrong answers

        print(f"Correct answers count: {correct_answers}")
        print(f"Total explorer points: {total_explorer_points}")
        print(f"Wrong questions: {wrong_questions}")

        # Update explorer points based on login method
        if session['login_method'] == 'login':
            print("Updating explorer points for login")
            cursor.execute("UPDATE users SET explorer_points = explorer_points + %s WHERE id = %s",
                           (total_explorer_points, user_id))
        elif session['login_method'] == 'google':
            print("Updating explorer points for Google")
            print(user_id)
            user_id = str(user_id)
            print(total_explorer_points)
            retrieve = "SELECT explorer_points FROM oauth where googleid = %s"
            cursor.execute(retrieve, (user_id,))
            points = cursor.fetchone()
            points_value = points['explorer_points'] if points and 'explorer_points' in points else 0
            total_explorer_points += points_value
            query = "UPDATE oauth SET explorer_points = %s WHERE googleid = %s"
            cursor.execute(query,
                           (total_explorer_points, user_id,))
            print(f"Executing query: {query}")
            print(f"Parameters: {total_explorer_points}, {user_id}")

        mydb.commit()  # Commit the transaction
        print("Database commit successful")

        return jsonify({
            "redirect": url_for("show_results", module_id=module_id,
                                wrong_questions=','.join(map(str, wrong_questions)))
        }), 200

    except KeyError as e:
        print(f"KeyError: {str(e)}")
        return jsonify({"error": f"Missing data: {str(e)}"}), 400
    except mysql.connector.Error as err:
        mydb.rollback()
        print(f"Database error: {err}")
        return jsonify({"error": "Database error: " + str(err)}), 500
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error has occurred: " + str(e)}), 500


@app.route('/student/module/<int:module_id>/results', methods=['GET'])
@roles_required('student')
def show_results(module_id):
    wrong_questions = request.args.get('wrong_questions', '')

    if wrong_questions:
        wrong_questions = list(map(int, wrong_questions.split(',')))  # Convert to list

    cursor = mydb.cursor(dictionary=True)
    if wrong_questions:
        # Use 'question_id' if that is the correct column name in your schema
        cursor.execute("SELECT question, answer FROM questions WHERE question_id IN (%s)" % ','.join(
            ['%s'] * len(wrong_questions)), tuple(wrong_questions))
    else:
        # No wrong questions, return empty
        cursor.execute("SELECT question, answer FROM questions WHERE module_id = %s AND 1=0", (module_id,))

    wrong_questions_details = cursor.fetchall()

    return render_template('User/student_results.html', wrong_questions=wrong_questions_details)


@app.route('/teacherProfile')
@limiter.limit("20 per minute")
@roles_required('teacher')
def teacherProfile():
    try:
        with mydb.cursor() as mycursor:
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
                        profile_pic_url = url_for('static', filename='img/default_pp.png')

                    # You can store the profile_pic_url in the session or pass it to the template
                    session['profile_pic_url'] = profile_pic_url
            return render_template('Teacher/teacherProfile.html', user=user, profile_pic_url=profile_pic_url)
    finally:
        mycursor.close()

@app.route('/updateTeacherProfile', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@roles_required('teacher')
def updateTeacherProfile():
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and 'username' in session['user']:
                current_username = session['user']['username']
                if request.method == 'POST':
                    new_username = request.form.get('username')
                    name = request.form.get('name')
                    email = request.form.get('email')
                    age = request.form.get('age')
                    address = request.form.get('address')
                    phone = request.form.get('phone')
                    if new_username or name or email or age or address or phone:
                        if new_username != current_username:
                            existing_username_check = "SELECT * FROM users WHERE username = %s"
                            mycursor.execute(existing_username_check, (new_username,))
                            existing_user_username = mycursor.fetchone()
                            if existing_user_username:
                                flash('User with the same username already exists. Please choose a different username.', 'danger')
                                user = userSession(current_username)
                                return render_template('Teacher/updateTeacherProfile.html', user=user)

                        # Check for existing email
                        if email:
                            existing_email_check = "SELECT * FROM users WHERE email = %s AND username != %s"
                            mycursor.execute(existing_email_check, (email, current_username))
                            existing_user_email = mycursor.fetchone()
                            if existing_user_email:
                                flash('User with the same email already exists. Please choose a different email.', 'danger')
                                user = userSession(current_username)
                                return render_template('Teacher/updateTeacherProfile.html', user=user)
                        try:
                            if input_validation(new_username, name, email, address) and age_validation(age) and validate_phone_number(phone):
                                mycursor.execute(
                                    "UPDATE users SET username = %s, name = %s, email = %s, age = %s, address = %s, phone = %s WHERE username = %s",
                                    (new_username, name, email, age, address, phone, current_username))
                                mydb.commit()
                                flash('Teacher information updated successfully', 'success')
                                log_this("Teachers detail updated successfully")
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
                                filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}')
                                file.save(filepath)
                                image_path = f"img/{filename}"
                                try:
                                    mycursor.execute("UPDATE users SET profilePic = %s WHERE username = %s",
                                                     (image_path, current_username))
                                    mydb.commit()
                                    flash('Profile picture uploaded successfully!', 'success')
                                except Exception as e:
                                    flash(f'Error updating profile picture: {str(e)}', 'error')
                                return redirect(url_for('updateTeacherProfile'))
                            else:
                                flash('Profile Picture must be less than 32 MB', 'danger')
                        else:
                            flash('Invalid file format. Allowed formats are png, jpg, jpeg, gif.', 'danger')

                    # Fetch updated user data
                    user = userSession(new_username if new_username else current_username)
                    if user:
                        session['user']['username'] = new_username if new_username else current_username  # Update session with new username if changed
                        return render_template("Teacher/teacherProfile.html", user=user)
                    else:
                        flash("User not found in database after update")
                        return redirect(url_for('login'))  # Redirect to log in if user not found after update
                else:
                    # GET request handling
                    user = userSession(current_username)
                    return render_template("Teacher/updateTeacherProfile.html", user=user)  # Render form with current user data prepopulated
            else:
                flash("User session not found")
                return redirect(url_for('login'))

    finally:
        mycursor.close()


@app.route('/updateTeacherPassword', methods=['POST', 'GET'])
@limiter.limit("20 per minute")
@roles_required('teacher')
def updateTeacherPassword():
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session:
                if 'username' in session['user']:
                    username = session['user']['username']
                    print("Session data:", session['user'])  # Debug statement
                    print("Username from session:", username)  # Debug statement

                    if request.method == 'POST':
                        new_password = request.form.get('password')
                        confirm_password = request.form.get('confirm_password')

                        if new_password and confirm_password:
                            if new_password == confirm_password:
                                if not password_checker(new_password):
                                    flash("An Unexpected Error Has Occurred")
                                    return redirect(url_for('updateTeacherPassword'))
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
                                        if 'user' in session and 'id' in session['user']:
                                            log_this("Existing password exists when creating a password")
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
                                            mycursor.execute("SELECT email FROM users WHERE username = %s", (username,))

                                            email_result = mycursor.fetchone()
                                            email = email_result[0]
                                            print(email)

                                            subject = 'Password Changed'
                                            template = f'''<p>Dear user, <br><br>
                                                    You have recently changed your password.<br><br>
                                                    Yours, <br><br>
                                                    PlanetExplorers Team</p>'''
                                            send_reset_link_email(email, subject, template)

                                        except Exception as e:
                                            flash(f'Error updating password: {str(e)}', 'danger')
                                            if 'user' in session and 'id' in session['user']:
                                                log_this("Error updating password")
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

    finally:
        mycursor.close()

@app.route('/userOrders')
@roles_required('student', 'teacher')
def user_orders():
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and 'id' in session['user']:
                user_id = session['user']['id']

                mycursor.execute("""
                    SELECT * FROM orders 
                    WHERE user_id = %s 
                    ORDER BY order_date DESC
                """, (user_id,))
                orders = mycursor.fetchall()

                order_list = []
                for order in orders:
                    mycursor.execute("""
                        SELECT oi.*, sp.name 
                        FROM order_items oi 
                        JOIN storeproducts sp ON oi.product_id = sp.id 
                        WHERE oi.order_id = %s
                    """, (order[0],))
                    items = mycursor.fetchall()
                    order_list.append({'order': order, 'items': items})

                print("Order List:", order_list)  # Debugging output
                return render_template('Store/user_orders.html', orders=order_list)
            else:
                flash("You need to log in to view your orders.", 'warning')
                return redirect(url_for('login'))
    finally:
        mycursor.close()


@app.route('/logout')
def logout():
    # session.pop('user',None)
    # print("Logged out successfully")
    # print(session)
    #
    # log_this("User logged out successfully")
    # return redirect(url_for('login'))

    if 'user' in session:
        user_id = session['user']['id']
        log_this("User logged out successfully", user_id)
        session.pop('user', None)
    else:
        log_this("Logout attempted without active session")

    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))