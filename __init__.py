from flask import render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename

# Configuration is a file containing sensitive information
from Configuration import RECAPTCHA_SITE_KEY
import bcrypt
import urllib.parse
import os
from utils import *
from User import *
from Admin import *

# !!!!!IF THERE IS ANY DB ERROR, CHECK THE CONFIG FILE AND IF THE PASSWORD IS CONFIG PROPERLY!!!!!

# !!!!CHECK THE INPUT FUNCTION BEFORE USING, THERE IS CURRENTLY 1 FUNCTION THAT ADDS IN NEW USERS AS STUDENTS ONLY!!!!
# ALL FUNCTIONS: input_validation(input_string), age_validation(age), update_info(input_string),add_info(username, /password, email, age, address),
# delete_info(),get_info()


@app.before_request
def before_request():
    if 'user' in session:
        session.modified = True
    else:
        session.clear()


@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == "POST":
        email = request.form['email']
        recaptcha = request.form['g-recaptcha-response']

        #verify recaptcha
        valid = verify_response(recaptcha)
        if valid:
            # generate reset token
            token = generate_confirm_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = 'Password Reset Requested'
            template = f'<p>Click the link to reset your password: <a href="{reset_url}">{reset_url}</a></p>'
            send_reset_link_email(email, subject, template)
            flash('Password reset link has been sent to your email.', 'success')
        else:
            flash('Invalid reCAPTCHA. Please try again.', 'danger')

        return redirect(url_for('forget_password'))

    return render_template("User/forget_password.html", site_key=RECAPTCHA_SITE_KEY)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify the reset token
    email = confirm_token(token)
    if not email:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forget_password'))  # Redirect to the forgot password page if token is invalid

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate new password and confirm password
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        # Update user's password in the database
        update_password(email, new_password)

        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))  # Redirect to login page after successful password reset

    return render_template('User/reset_password.html', token=token)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        if check_existing_credentials(username, email):
            print("Username or email already in use")
            return redirect(url_for('register'))

        name = request.form.get('name')
        age = request.form.get('age')
        address = request.form.get('address')
        phone = request.form.get('phone')
        print("Received form data:")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"Email: {email}")
        print(f"Name: {name}")
        print(f"Age: {age}")
        print(f"Address: {address}")
        print(f"Phone: {phone}")
        add_info(username, password, email, name, age, address, phone)
        return redirect(url_for('home'))
    return render_template('User/register.html')


@app.route('/updateProfile', methods=['GET', 'POST'])
@roles_required('student', 'teacher')
def updateProfile():
    if 'user' in session and 'username' in session['user']:
        username = session['user']['username']
        if request.method == 'POST':
            new_username = request.form['username']
            name = request.form['name']
            email = request.form['email']
            age = request.form['age']
            address = request.form['address']
            phone = request.form['phone']
            mycursor.execute(
                "UPDATE users SET username = %s, name = %s, email = %s, age = %s, address = %s, phone = %s WHERE username = %s",
                (new_username, name, email, age, address, phone, username))
            mydb.commit()

            # Handle profile picture upload
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file.filename == '':
                    flash('No profile picture selected')
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    filepath = f"{app.config['UPLOAD_FOLDER']}/{filename}"
                    # file.save(filepath)
                    image_path = f"img/{filename}"  # Store relative path
                    # Update profile picture path in the database
                    mycursor.execute("UPDATE users SET profilePic = %s WHERE username = %s", (image_path, username))
                    mydb.commit()
                    flash('Profile picture uploaded successfully!', 'success')
                else:
                    flash('Invalid file format. Allowed formats are png, jpg, jpeg, gif.', 'error')

            # Fetch updated user data
            user = userSession(new_username)
            if user:
                session['user']['username'] = new_username  # Update session with new username if changed
                return render_template("User/profile.html", user=user)
            else:
                flash("User not found in database after update")
                return redirect(url_for('login'))  # Redirect to login if user not found after update
        else:
            # GET request handling
            user = userSession(username)
            return render_template("User/updateProfile.html", user=user)  # Render form with current user data prepopulated
    else:
        flash("User session not found")
        return redirect(url_for('login'))


@app.route('/deleteAccount', methods=['POST'])
@roles_required('student', 'teacher')
def deleteAccount():
    try:
        if 'user' in session:
            username = session['user']['username']
            delete_account = 'DELETE from users WHERE username = %s'
            mycursor.execute(delete_account, (username,))
            mydb.commit()
            session.pop('user', None)
            flash('Your account has been deleted', 'success')
            return redirect(url_for('login'))
        else:
            flash('Account not found', 'error')
            return redirect(url_for('profile'))
    except Exception as e:
        print('Error: ', e)
        mydb.rollback()
        flash('Error occurred while deleting account', 'error')
        return redirect(url_for('profile'))


@app.route('/teacherHome')
@roles_required('teacher')
def teacherHome():
    if 'user' in session and 'username' in session['user']:
        username = session['user']['username']
        user = userSession(username)
        if user:
            print(f'user {username} is logged in')
            return render_template("Teacher/teacherHome.html", user=user)
        else:
            flash("User not found in database")
            return redirect(url_for('login'))  # Redirect to login if user not found
    else:
        flash("User session not found")
        return redirect(url_for('login'))  # Redirect to login if session not found


@app.route('/store')
@limiter.limit("5 per minute")
def store():
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    mycursor.close()
    return render_template("Store/store.html", products=products)


if __name__ == '__main__':
    # calling create table function
    # Call the function when the application starts
    create_admin_user()
    app.run(debug=True)