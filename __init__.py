from flask import render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
# Configuration is a file containing sensitive information

import bcrypt
import urllib.parse
import os
from utils import *
from User import *
from Admin import *

try:
    from config import abuse_key, RECAPTCHA_SITE_KEY
except ImportError:
    # Handle the case where config cannot be imported
    raise RuntimeError("Failed to import configuration settings")



@app.before_request
def before_request():
    # Check IP Blacklisting
    user_ip = request.remote_addr
    if is_ip_blacklisted(user_ip, abuse_key):
        abort(403)  # Forbidden access

    # Ensure session is modified if user is logged in
    if 'user' in session:
        session.modified = True


@app.route('/forget_password', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def forget_password():
    with mydb.cursor() as mycursor:
        if request.method == "POST":
            email = request.form['email']
            recaptcha = request.form['g-recaptcha-response']

            # verify recaptcha
            valid = verify_response(recaptcha)
            if valid:
                mycursor.execute('SELECT email FROM users WHERE email = %s', (email,))
                email_exist = mycursor.fetchone()

                if email_exist:
                    # generate reset token
                    token = generate_confirm_token(email)
                    reset_url = url_for('reset_password', token=token, _external=True)
                    subject = 'Password Reset Requested'
                    template = f'''<p>Dear user, <br><br>
                                You requested to change your password. Click the link to reset your password: <a href="{reset_url}">{reset_url}</a>. 
                                The link will be valid for 5 minutes. <br>
                                If you did not request a password change, please ignore this email.<br><br>
                                Yours, <br>
                                PlanetExplorers Team</p>'''
                    send_reset_link_email(email, subject, template)
                    flash('Password reset link has been sent to your email.', 'success')
                else:
                    flash('Error sending email. Check if the email entered is registered in your account or your WiFi connection is strong. ', 'danger')
            else:
                flash('Invalid reCAPTCHA. Please try again.', 'danger')

            return redirect(url_for('forget_password'))

    mycursor.close()
    return render_template("User/forget_password.html", site_key=RECAPTCHA_SITE_KEY)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def reset_password(token):
    with mydb.cursor() as mycursor:
        # Verify the reset token
        email = confirm_token(token)
        if not email:
            flash('Invalid or expired token.', 'danger')
            return redirect(url_for('forget_password'))  # Redirect to the forgot password page if token is invalid

        if request.method == 'POST':
            new_password = request.form['password']
            confirm_password = request.form['confirm_password']
            try:
                if input_validation(new_password and confirm_password):
                    if not password_checker(new_password):
                        flash('An Unknown Error Has Occurred')
                        return redirect(url_for('login'))

                    # Validate new password and confirm password
                    if new_password != confirm_password:
                        flash('Passwords do not match.', 'danger')
                        return redirect(request.url)

                    else:
                        try:
                            # Retrieve all hashed passwords from the database
                            mycursor.execute("SELECT password FROM users")
                            all_passwords = mycursor.fetchall()

                            # Check if the new password matches any existing password
                            password_exists = False
                            for stored_password in all_passwords:
                                if bcrypt.checkpw(new_password.encode('utf-8'), stored_password[0].encode('utf-8')):
                                    password_exists = True
                                    break

                            if password_exists:
                                flash('Password already exists. Please create another password.')

                            else:
                                # Hash the new password and update the user's password in the database
                                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                                update_query = "UPDATE users SET password = %s WHERE email = %s"
                                mycursor.execute(update_query, (hashed_password, email))
                                expire_token = "UPDATE token_validation SET used = %s WHERE token = %s"
                                used = True
                                mycursor.execute(expire_token,(used,token))
                                mydb.commit()

                                flash('Your password has been reset successfully.', 'success')
                                subject = 'Password Changed'
                                template = f'''<p>Dear user, <br><br>
                                                        You have recently changed your password.<br><br>
                                                        Yours, <br>
                                                        PlanetExplorers Team</p>'''
                                send_reset_link_email(email, subject, template)
                                return redirect(url_for('login'))  # Redirect to login page after successful password reset

                        except Exception as e:
                            print("Error updating password:", e)
                            return False  # Indicate failure due to error
            except ValueError:
                flash('Error Resetting Password. Please try again!', 'danger')
    mycursor.close()

    return render_template('User/reset_password.html', token=token)


@app.route('/register', methods=["GET", "POST"])
@limiter.limit("100 per hour")
def register():
    # with mydb.cursor() as mycursor:
        if request.method == "POST":
            try:
                username = request.form.get('username')
                password = request.form.get('password')
                if not password_checker(password):
                    flash("password does not meet requirement", 'danger')
                    return redirect(url_for('register'))
                email = request.form.get('email')
                if check_existing_credentials(username, email):
                    flash("Username or email already in use",'danger')
                    return redirect(url_for('register'))

                name = request.form.get('name')
                age = request.form.get('age')
                address = request.form.get('address')
                phone = request.form.get('phone')

                input_validation(username,password,email,name,address)
                age_validation(age)
                validate_phone_number(phone)

                add_info(username, password, email, name, age, address, phone)
                mycursor.close()
                return redirect(url_for('login'))
            except ValueError as error:
                print(error)
                return redirect(url_for('register'))
            except Exception as e:
                print(e)
                return redirect(url_for('register'))

    # mycursor.close()
        return render_template('User/register.html')

@app.route('/verify_register', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def verify_register():
    try:
        with mydb.cursor() as mycursor:

            if 'user' in session and 'username' in session['user']:
                    username = session['user']['username']
                    query = "SELECT email from users WHERE username = %s"
                    mycursor.execute(query,(username,))
                    email = mycursor.fetchone()[0]

                    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # The serializer requires a secret key
                    # to ensure the tokens are securely generated and can be validated later.
                    token = serializer.dumps(email,
                                             salt=app.config[
                                                 'SECRET_KEY'])  # dumps method serializes the email address into a token
                    expiration = datetime.utcnow() + timedelta(minutes=5)  # Token expires in 5 minutes
                    save_token = 'INSERT INTO token_validation (email, token, expiration) VALUES (%s, %s, %s)'
                    mycursor.execute(save_token, (email, token, expiration))
                    mydb.commit()

                    send_verification_email(email,token)
                    flash('Email verification link has been sent to your email', 'success')
                    mycursor.close()
                    return redirect(url_for('login'))

            else:
                flash('Error sending email', 'danger')
                return redirect(url_for('login'))
    finally:
        mycursor.close()



@app.route('/verify_email/<token>', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def verify_email(token):
    with mydb.cursor() as mycursor:
        try:
            yes = False
            email = confirm_token(token)
            if not email:
                flash('Invalid or expired token.', 'danger')
                return redirect(url_for('login'))  # Redirect to the login page if token is invalid

            if request.method == 'POST':
                yes = True
                try:
                    # Update the user's email verification status
                    query = "UPDATE users SET email_verified = %s WHERE email = %s"
                    mycursor.execute(query, (yes, email))
                    mydb.commit()

                    # Mark the token as used
                    query2 = "UPDATE token_validation SET used = %s WHERE token = %s"
                    mycursor.execute(query2, (yes, token))
                    mydb.commit()

                    flash("Email verified, please login again", "success")
                except Exception as e:
                    # Handle potential database errors
                    mydb.rollback()  # Rollback the transaction in case of error
                    flash(f"An error occurred: {e}", "danger")

                return redirect(url_for('login'))

            # Handle GET request
            try:
                # Update the user's email verification status
                query = "UPDATE users SET email_verified = %s WHERE email = %s"
                mycursor.execute(query, (True, email))
                mydb.commit()

                # Mark the token as used
                query2 = "UPDATE token_validation SET used = %s WHERE token = %s"
                mycursor.execute(query2, (True, token))
                mydb.commit()

                return redirect(url_for('email_verified_success'))
            except Exception as e:
                mydb.rollback()  # Rollback the transaction in case of error
                flash(f"An error occurred: {e}", "danger")
                return redirect(url_for('login'))

        finally:
            mycursor.close()

@app.route('/email_verified_sucess')
def email_verified_success():
    return render_template('User/verify_email.html')  # Render a template if GET request


@app.route('/teacher_register', methods=["GET", "POST"])
@limiter.limit("100 per hour")
def teacher_register():
    with mydb.cursor() as mycursor:
        if request.method == "POST":
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            name = request.form.get('name')
            age = request.form.get('age')
            address = request.form.get('address')
            phone = request.form.get('phone')
            register_as_teacher = request.form.get('register_as_teacher')

            try:
                input_validation(username, password, email, name, address)
                age_validation(age)
                validate_phone_number(phone)
            except ValueError as e:
                return str(e), 400

            if check_existing_credentials(username, email):
                return "Username or email already exists", 400

            # Save registration info temporarily in session
            session['username'] = username
            session['password'] = password
            session['email'] = email
            session['name'] = name
            session['age'] = age
            session['address'] = address
            session['phone'] = phone

            if register_as_teacher:
                return redirect(url_for('teacher_payment', username=username))
            else:
                add_info(username, password, email, name, age, address, phone)
                return redirect(url_for('login'))

    mycursor.close()
    return render_template('User/register.html')


@app.route('/confirm_teacher_registration/<token>')
@limiter.limit("100 per hour")
def confirm_teacher_registration(token):
    with mydb.cursor() as mycursor:
        try:
            email = confirm_token(token)
            if email:
                payment_details = session.get('payment_details')
                if payment_details and payment_details['email'] == email:
                    try:
                        # Decrypt payment details for validation
                        card_number = decrypt_payment_data(payment_details['card_number'])
                        cvv = decrypt_payment_data(payment_details['cvv'])

                        if process_payment(payment_details['card_name'], card_number, payment_details['exp_month'], payment_details['exp_year'], cvv):
                            if update_user_role(payment_details['username'], 'teacher'):
                                add_info_teacher(
                                    payment_details['username'], session['password'], session['email'],
                                    session['name'], session['age'], payment_details['address'], session['phone']
                                )
                                session.clear()  # Clear session data after successful registration and payment
                                flash('Your account has been created successfully.', 'success')
                                return redirect(url_for('login'))
                            else:
                                flash('Failed to update user role', 'danger')
                                return redirect(url_for('login'))
                        else:
                            flash('Payment failed', 'danger')
                            return redirect(url_for('login'))
                    except ValueError as e:
                        flash(str(e), 'danger')
                        return redirect(url_for('login'))
                else:
                    flash('No payment details found or email mismatch.', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('The confirmation link is invalid or has expired.', 'danger')
                return redirect(url_for('login'))

        finally:
            mycursor.close()


@app.route('/payment/<username>', methods=["GET", "POST"])
@limiter.limit("100 per hour")
def teacher_payment(username):
    with mydb.cursor() as mycursor:
        if request.method == "POST":
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            address = request.form.get('address')
            address2 = request.form.get('address2')
            state = request.form.get('state')
            zip_code = request.form.get('zip')
            card_name = request.form.get('card_name')
            card_number = request.form.get('card_number').replace(" ", "")  # Remove spaces for validation
            exp_month = request.form.get('exp_month')
            exp_year = request.form.get('exp_year')
            cvv = request.form.get('cvv')

            try:
                # Validate input for harmful content
                input_validation(full_name, email, address, address2, zip_code, card_name, card_number, exp_month, exp_year, cvv)

                # Encrypt the payment details
                encrypted_card_number = encrypt_payment_data(card_number)
                encrypted_cvv = encrypt_payment_data(cvv)

                # Generate confirmation token
                token = generate_confirm_token(email)

                # Send verification email
                confirm_url = url_for('confirm_teacher_registration', token=token, _external=True)
                html = render_template('Teacher/email_teacher_verification.html', confirm_url=confirm_url)
                send_reset_link_email(email, 'Confirm Your Registration', html)

                # Temporarily store encrypted payment details in session
                session['payment_details'] = {
                    'username': username,
                    'full_name': full_name,
                    'email': email,
                    'address': address,
                    'address2': address2,
                    'zip_code': zip_code,
                    'card_name': card_name,
                    'card_number': encrypted_card_number,
                    'exp_month': exp_month,
                    'exp_year': exp_year,
                    'cvv': encrypted_cvv
                }

                flash('A confirmation email has been sent to your email address. Please confirm to complete the payment.', 'success')
                return redirect(url_for('login'))

            except ValueError as e:
                return str(e), 400

    mycursor.close()
    return render_template('Teacher/teacher_payment.html', username=username)


# need to test virus total with malicious file
@app.route('/updateProfile', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
@roles_required('student')
def updateProfile():
    with mydb.cursor() as mycursor:
        try:
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
                                flash('User with the same username already exists. Please choose a different username.',
                                      'danger')
                                user = userSession(current_username)
                                return render_template('User/updateProfile.html', user=user)

                            # Check for existing email
                        if email:
                            existing_email_check = "SELECT * FROM users WHERE email = %s AND username != %s"
                            mycursor.execute(existing_email_check, (email, current_username))
                            existing_user_email = mycursor.fetchone()
                            if existing_user_email:
                                flash('User with the same email already exists. Please choose a different email.', 'danger')
                                user = userSession(current_username)
                                return render_template('User/updateProfile.html', user=user)
                        try:
                            if input_validation(new_username, name, email, address) and age_validation(age) and validate_phone_number(phone):
                                mycursor.execute(
                                    "UPDATE users SET username = %s, name = %s, email = %s, age = %s, address = %s, phone = %s WHERE username = %s",
                                    (new_username, name, email, age, address, phone, current_username))
                                mydb.commit()
                                flash('User information updated successfully', 'success')
                                global user_id
                                if 'user' in session and 'id' in session['user']:
                                    user_id = session['user']['id']
                                    log_this(f"User {user_id} information updated successfully")
                        except Exception as e:
                            flash(f'Error updating user information: {str(e)}', 'error')
                            return redirect(url_for('updateProfile'))

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
                                    flash('Profile picture scanned and uploaded successfully!', 'success')
                                except Exception as e:
                                    flash(f'Error updating profile picture: {str(e)}', 'error')
                                return redirect(url_for('updateProfile'))
                            else:
                                flash('Profile Picture must be less than 32 MB', 'danger')
                        else:
                            flash('Invalid file format. Allowed formats are png, jpg, jpeg, gif.', 'danger')

                    # Fetch updated user data
                    user = userSession(new_username if new_username else current_username)
                    if user:
                        session['user']['username'] = new_username if new_username else current_username  # Update session with new username if changed
                        return render_template("User/profile.html", user=user)
                    else:
                        flash("User not found in database after update")
                        return redirect(url_for('login'))  # Redirect to log in if user not found after update
                else:
                    # GET request handling
                    user = userSession(current_username)
                    return render_template("User/updateProfile.html", user=user)  # Render form with current user data prepopulated
            else:
                flash("User session not found")
                return redirect(url_for('login'))

        finally:
            mycursor.close()


@app.route('/updatePassword', methods=['POST', 'GET'])
@limiter.limit("100 per hour")
@roles_required('student')
def updatePassword():
    if 'user' in session:
        if 'username' in session['user']:
            username = session['user']['username']

            with mydb.cursor() as mycursor:

                if request.method == 'POST':
                    new_password = request.form.get('password')
                    confirm_password = request.form.get('confirm_password')

                    if new_password and confirm_password:
                        try:
                            if input_validation(new_password and confirm_password):
                                if new_password == confirm_password:
                                    if not password_checker(new_password):
                                        flash("An Unexpected Error Has Occurred")
                                        return redirect(url_for('updatePassword'))
                                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                                    try:
                                        # Check if the new hashed password already exists in the database
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
                                            return redirect(url_for('updatePassword'))
                                        else:
                                            try:
                                                mycursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username,))
                                                mydb.commit()
                                                flash('Password updated successfully', 'success')
                                                if 'user' in session and 'id' in session['user']:
                                                    log_this("Password updated successfully")

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

                                                subject = 'Password Changed'
                                                template = f'''<p>Dear user, <br><br>
                                                            You have recently changed your password.<br><br>
                                                            Yours, <br>
                                                            PlanetExplorers Team</p>'''
                                                send_reset_link_email(email, subject, template)

                                            except Exception as e:
                                                flash(f'Error updating password: {str(e)}', 'danger')
                                                print(f'SQL Update Error: {str(e)}')  # Debug statement
                                                return redirect(url_for('updatePassword'))
                                    except Exception as e:
                                        flash(f'Error checking existing password: {str(e)}', 'danger')
                                        print(f'SQL Select Error: {str(e)}')  # Debug statement
                                        return redirect(url_for('updatePassword'))
                                else:
                                    flash('Passwords do not match.', 'danger')
                                    return redirect(url_for('updatePassword'))
                            else:
                                flash('Please provide both password fields.', 'danger')
                                return redirect(url_for('updatePassword'))
                        except ValueError:
                            flash('Error updating password. Please try again!', 'danger')


        else:
            flash("Username not found in session")
            return redirect(url_for('login'))
    else:
        flash("User session not found")
        return redirect(url_for('login'))

    mycursor.close()
    return render_template("User/updatePassword.html")



@app.route('/deleteAccount', methods=['POST','GET'])
@roles_required('student', 'teacher')
def deleteAccount():
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and session['login_method'] == 'login':
                username = session['user']['username']
                delete_account = 'DELETE from users WHERE username = %s'
                mycursor.execute(delete_account, (username,))
                mydb.commit()
                session.pop('user', None)
                flash('Your account has been deleted', 'success')
                if 'user' in session and 'id' in session['user']:
                    log_this("User account has been deleted")
                return redirect(url_for('login'))
            if 'user' in session and session['login_method'] == 'google':
                id = session['user']['id']
                deleteaccount = 'DELETE from oauth WHERE googleid = %s'
                mycursor.execute(deleteaccount,(id,))
                mydb.commit()
                session.pop('user',None)
                flash('Your account has been deleted','success')
                if 'user' in session and 'id' in session['user']:
                    log_this("User account has been deleted")
                return redirect(url_for('login'))
            else:
                flash('Account not found', 'error')
                return redirect(url_for('profile'))
    except Exception as e:
        print('Error: ', e)
        mydb.rollback()
        flash('Error occurred while deleting account', 'error')
        return redirect(url_for('profile'))

    finally:
        mycursor.close()


@app.route('/teacherHome')
@limiter.limit("100 per hour")
@roles_required('teacher')
def teacherHome():
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and 'username' in session['user']:
                username = session['user']['username']
                user = userSession(username)
                if user:
                    log_this("login successful")

                    # Fetch all modules associated with the teacher
                    teacher_id = session['user']['id']  # Assuming the userSession provides a user object with an 'id'
                    mycursor.execute("SELECT module_id, module_name FROM modules WHERE teacher_id = %s", (teacher_id,))
                    modules = mycursor.fetchall()

                    return render_template("Teacher/teacherHome.html", user=user, modules=modules)
                else:
                    flash("User not found in database")
                    return redirect(url_for('login'))  # Redirect to log in if user not found
            else:
                flash("User session not found")
                return redirect(url_for('login'))  # Redirect to log in if session not found
    finally:
        mycursor.close()

@app.route('/store')
@limiter.limit("100 per hour")
def store():
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    mycursor.close()
    return render_template("Store/store.html", products=products)


@app.route('/view_cart')
@limiter.limit("100 per hour")
@roles_required('student')
def view_cart():
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and 'id' in session['user']:
                user_id = session['user']['id']

                # Fetch items in the cart for the current user with total price calculation
                mycursor.execute("""
                    SELECT sp.id, sp.name, sp.price_in_points, c.quantity, sp.price_in_points * c.quantity AS total_price_in_points
                    FROM cart c
                    INNER JOIN storeproducts sp ON c.product_id = sp.id
                    WHERE c.user_id = %s
                """, (user_id,))
                cart_items = mycursor.fetchall()

                total_items = sum(item[3] for item in cart_items)
                total_price_in_points = sum(item[4] for item in cart_items)

                return render_template("Store/cart.html", cart_items=cart_items, total_items=total_items, total_price_in_points=total_price_in_points, empty_message=False)
            else:
                flash("You need to log in to view your shopping cart.", 'warning')
                return redirect(url_for('login'))

    finally:
        mycursor.close()


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@limiter.limit("100 per hour")
@roles_required('student')
def add_to_cart(product_id):
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session:
                user_id = session['user']['id']
                quantity = int(request.form.get('quantity'))

                try:
                    # Start transaction
                    mycursor.execute("START TRANSACTION")

                    # Lock the row and check if the product exists and get its details
                    mycursor.execute("SELECT quantity, price_in_points FROM storeproducts WHERE id = %s FOR UPDATE", (product_id,))
                    product = mycursor.fetchone()

                    if product:
                        available_quantity = product[0]
                        price_in_points = product[1]

                        # Check if the requested quantity is available
                        if quantity <= available_quantity:
                            # Check if the product is already in the cart
                            mycursor.execute("SELECT quantity, total_points FROM cart WHERE user_id = %s AND product_id = %s", (user_id, product_id))
                            cart_item = mycursor.fetchone()

                            if cart_item:
                                # Update the quantity and total points in the cart
                                new_quantity = cart_item[0] + quantity
                                new_total_points = new_quantity * price_in_points
                                if new_quantity <= available_quantity:
                                    mycursor.execute("UPDATE cart SET quantity = %s, total_points = %s WHERE user_id = %s AND product_id = %s", (new_quantity, new_total_points, user_id, product_id))
                                    mydb.commit()
                                    return jsonify(success=True, message='Item added to cart successfully.')
                                else:
                                    mydb.rollback()
                                    return jsonify(success=False, error='Not enough stock available.')
                            else:
                                # Insert the new item into the cart
                                total_points = quantity * price_in_points
                                mycursor.execute("INSERT INTO cart (user_id, product_id, quantity, total_points) VALUES (%s, %s, %s, %s)", (user_id, product_id, quantity, total_points))
                                mydb.commit()
                                return jsonify(success=True, message='Item added to cart successfully.')
                        else:
                            mydb.rollback()
                            return jsonify(success=False, error='Not enough stock available.')
                    else:
                        mydb.rollback()
                        return jsonify(success=False, error='Product not found.')
                except Exception as e:
                    mydb.rollback()
                    return jsonify(success=False, error=str(e))
            return jsonify(success=False, error='You need to log in to add items to your cart.')

    finally:
        mycursor.close()


@app.route('/update_cart/<int:product_id>', methods=['POST'])
@limiter.limit("100 per hour")
@roles_required('student')
def update_cart(product_id):
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and 'id' in session['user']:
                user_id = session['user']['id']
                data = request.get_json()
                new_quantity = data['quantity']

                # Get the price of the product
                mycursor.execute("SELECT price_in_points FROM storeproducts WHERE id = %s", (product_id,))
                product = mycursor.fetchone()
                if product:
                    price_in_points = product[0]
                    new_total_points = new_quantity * price_in_points

                    # Update the cart with the new quantity and total points
                    mycursor.execute("""
                        UPDATE cart
                        SET quantity = %s, total_points = %s
                        WHERE user_id = %s AND product_id = %s
                    """, (new_quantity, new_total_points, user_id, product_id))
                    mydb.commit()

                    # Fetch updated cart data
                    mycursor.execute("""
                        SELECT sp.id, sp.name, sp.price_in_points, c.quantity, c.total_points
                        FROM cart c
                        INNER JOIN storeproducts sp ON c.product_id = sp.id
                        WHERE c.user_id = %s
                    """, (user_id,))
                    cart_items = mycursor.fetchall()

                    total_items = sum(item[3] for item in cart_items)
                    total_price_in_points = sum(item[4] for item in cart_items)

                    return jsonify({
                        'success': True, 'item_price_in_points': cart_items[0][4], 'total_items': total_items, 'total_price_in_points': total_price_in_points})
                else:
                    return jsonify({'success': False, 'error': 'Product not found'}), 404
            else:
                return jsonify({'success': False}), 403

    finally:
        mycursor.close()


@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
@roles_required('student')
def remove_from_cart(product_id):
    try:
        with mydb.cursor() as mycursor:
            if 'user' in session and 'id' in session['user']:
                user_id = session['user']['id']

                mycursor.execute("DELETE FROM cart WHERE user_id = %s AND product_id = %s", (user_id, product_id))
                mydb.commit()

                # Calculate total items and total price
                mycursor.execute("SELECT SUM(quantity) FROM cart WHERE user_id = %s", (user_id,))
                total_items = mycursor.fetchone()[0] or 0

                mycursor.execute("SELECT SUM(c.quantity * p.price_in_points) FROM cart c JOIN storeproducts p ON c.product_id = p.id WHERE c.user_id = %s", (user_id,))
                total_price_in_points = mycursor.fetchone()[0] or 0.0

                return jsonify(success=True, total_items=total_items, total_price=total_price_in_points)
            else:
                return jsonify(success=False), 403

    finally:
        mycursor.close()


@app.route('/payment_points', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
@roles_required('student')
def payment_tokens():
    try:
         with mydb.cursor() as mycursor:
            if 'user' in session and 'id' in session['user']:
                user_id = session['user']['id']

                # Define shipping costs
                shipping_costs = {
                    'free_collection': 0,
                    'home_delivery': 10,
                    'next_day_delivery': 50
                }

                if request.method == 'POST':
                    shipping_option = request.form.get('shippingOption')

                    # Ensure shipping option is valid
                    if shipping_option not in shipping_costs:
                        flash("Invalid shipping option.", 'danger')
                        return redirect(url_for('view_cart'))

                    shipping_cost = shipping_costs[shipping_option]

                    try:
                        # Start transaction
                        mycursor.execute("START TRANSACTION")

                        # Fetch cart items for current user
                        mycursor.execute("""
                            SELECT sp.id, sp.quantity, sp.price_in_points, c.quantity, sp.name
                            FROM cart c
                            INNER JOIN storeproducts sp ON c.product_id = sp.id
                            WHERE c.user_id = %s
                        """, (user_id,))
                        cart_items = mycursor.fetchall()

                        # Calculate total cost in points
                        total_points = sum(item[2] * item[3] for item in cart_items) + shipping_cost

                        # Check if user has enough explorer points
                        mycursor.execute("SELECT explorer_points FROM users WHERE id = %s", (user_id,))
                        user_points = mycursor.fetchone()[0]

                        if user_points < total_points:
                            mydb.rollback()
                            flash("You do not have enough explorer points.", 'danger')
                            return redirect(url_for('view_cart'))

                        # Deduct points from user account and update stock
                        for item in cart_items:
                            product_id, available_quantity, price_in_points, ordered_quantity, product_name = item

                            # Check stock before updating
                            if ordered_quantity > available_quantity:
                                mydb.rollback()
                                flash("Not enough stock available.", 'danger')
                                return redirect(url_for('view_cart'))

                            # Update stock in storeproducts
                            mycursor.execute("UPDATE storeproducts SET quantity = quantity - %s WHERE id = %s", (ordered_quantity, product_id))

                        # Deduct points from user account
                        mycursor.execute("UPDATE users SET explorer_points = explorer_points - %s WHERE id = %s", (total_points, user_id))

                        # Insert order into orders table
                        mycursor.execute("INSERT INTO orders (user_id, total_points, shipping_option) VALUES (%s, %s, %s)", (user_id, total_points, shipping_option))
                        order_id = mycursor.lastrowid

                        # Insert each cart item into order_items table
                        for item in cart_items:
                            product_id, available_quantity, price_in_points, ordered_quantity, product_name = item
                            mycursor.execute("INSERT INTO order_items (order_id, product_id, product_name, quantity, price_in_points) VALUES (%s, %s, %s, %s, %s)",
                                             (order_id, product_id, product_name, ordered_quantity, price_in_points))

                        # Clear cart after successful payment
                        mycursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))

                        mydb.commit()
                        return redirect(url_for('order_complete'))

                    except Exception as e:
                        mydb.rollback()
                        flash(f"An error occurred: {e}", 'danger')
                        return redirect(url_for('view_cart'))

                # Fetch cart items for display on the payment page
                mycursor.execute("""
                    SELECT sp.name, sp.price_in_points, c.quantity
                    FROM cart c
                    INNER JOIN storeproducts sp ON c.product_id = sp.id
                    WHERE c.user_id = %s
                """, (user_id,))
                cart_items = mycursor.fetchall()

                # Calculate total price without shipping cost
                total_points = sum(item[1] * item[2] for item in cart_items)  # Total in points

                return render_template('Store/payment_points.html', cart_items=cart_items, total_points=total_points, shipping_costs=shipping_costs)
            else:
                flash("You need to log in to complete your purchase.", 'warning')
                return redirect(url_for('login'))

    finally:
        mycursor.close()



@app.route('/order_complete')
@limiter.limit("100 per hour")
@roles_required('student')
def order_complete():
    flash("Payment successful! Your order has been placed.", 'success')
    return redirect(url_for('store'))


if __name__ == '__main__':
    create_admin_user()
    app.run()
