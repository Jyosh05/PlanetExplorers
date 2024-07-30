from utils import *
from flask import render_template, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
import time
import os


@app.route('/adminHome')
@roles_required('admin')
def adminHome():

    return render_template('Admin/adminHome.html')


@app.route('/adminProfile')
@roles_required('admin')
def adminProfile():
    if 'user' in session and 'username' in session['user']:
        username = session['user']['username']
        user = userSession(username)
        if user:
            print(f'user {username} is logged in')
            return render_template("Admin/adminProfile.html", user=user)
        else:
            flash("User not found in database")
            return redirect(url_for('login'))  # Redirect to log in if user not found
    else:
        flash("User session not found")
        return redirect(url_for('login'))  # Redirect to log in if session not found


@app.route('/adminUpdateProfile', methods=['GET', 'POST'])
@roles_required('admin')
def adminUpdateProfile():
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
                    flash('User information updated successfully', 'success')
                except Exception as e:
                    flash(f'Error updating user information: {str(e)}', 'error')
                    log_this('Admin Profile information updated successfully', user_id=1)
                    return redirect(url_for('adminUpdateProfile'))

            # Handle profile picture upload
            if 'image' in request.files:
                file = request.files['image']
                if file.filename == '':
                    flash('No profile picture selected', 'error')
                elif file and allowed_file(file.filename):
                    if file.content_length < 32 * 1024 * 1024:  # check if files size is less than 32 MB
                        filename = secure_filename(file.filename)
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                    else:
                        flash('Profile Picture must be less than 32 MB', 'error')

                    try:
                        file_id = scan_file(filepath)
                    except Exception as e:
                        flash(f'Error uploading file to VirusTotal: {str(e)}', 'error')
                        os.remove(filepath)
                        log_this(f'Error uploading file to VirusTotal: {str(e)}', user_id=1)
                        return redirect(url_for('adminUpdateProfile'))

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
                                    if any(result['category'] == 'malicious' for result in
                                           attributes.get('results', {}).values()):
                                        flash('The file is malicious and has not been saved.', 'error')
                                        os.remove(filepath)  # Remove the file if it is malicious
                                        log_this("Malicious file that has not been saved while updating profile", user_id=1)
                                        session['user']['profile_picture'] = 'default_pp.png'
                                        return redirect(url_for('adminUpdateProfile'))
                                    else:
                                        image_path = f"img/{filename}"
                                        try:
                                            session['user']['profile_picture'] = filename
                                            mycursor.execute("UPDATE users SET profilePic = %s WHERE username = %s",
                                                             (image_path, username))
                                            mydb.commit()
                                            flash('Profile picture scanned and uploaded successfully!', 'success')
                                        except Exception as e:
                                            flash(f'Error updating profile picture: {str(e)}', 'error')
                                        log_this('Profile picture scanned and uploaded successfully!', user_id=1)
                                        return redirect(url_for('adminUpdateProfile'))
                            else:
                                flash('Failed to retrieve scan report.', 'error')
                                break
                            time.sleep(10)  # wait for 10 seconds before retrying
                        else:
                            flash('Scan is not yet complete. Try again later.', 'error')
                    else:
                        flash('Failed to upload file to VirusTotal for scanning.', 'error')
                else:
                    flash('Invalid file format. Allowed formats are png, jpg, jpeg, gif.', 'error')

            # Fetch updated user data
            user = userSession(new_username if new_username else username)
            if user:
                session['user']['username'] = new_username if new_username else username  # Update session with new username if changed
                return render_template("Admin/adminProfile.html", user=user)
            else:
                flash("User not found in database after update")
                log_this("User not found in database after update", user_id=1)
                return redirect(url_for('login'))  # Redirect to log in if user not found after update
        else:
            # GET request handling
            user = userSession(username)
            return render_template("Admin/adminUpdateProfile.html", user=user)  # Render form with current user data prepopulated
    else:
        flash("User session not found")
        log_this("User session not found when updating Profile", user_id=1)
        return redirect(url_for('login'))


@app.route('/adminUpdatePassword', methods=['POST', 'GET'])
@roles_required('admin')
def adminUpdatePassword():
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
                                log_this("Existing password exists when creating a password", user_id=1)
                                return redirect(url_for('adminUpdatePassword'))
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
                                    return redirect(url_for('adminUpdatePassword'))
                        except Exception as e:
                            flash(f'Error checking existing password: {str(e)}', 'danger')
                            print(f'SQL Select Error: {str(e)}')  # Debug statement
                            return redirect(url_for('adminUpdatePassword'))
                    else:
                        flash('Passwords do not match.', 'danger')
                        return redirect(url_for('adminUpdatePassword'))
                else:
                    flash('Please provide both password fields.', 'danger')
                    return redirect(url_for('adminUpdatePassword'))
        else:
            flash("Username not found in session")
            return redirect(url_for('login'))
    else:
        flash("User session not found")
        return redirect(url_for('login'))

    return render_template("Admin/adminUpdatePassword.html")


@app.route('/adminCreateTeacher', methods=['GET', 'POST'])
@roles_required('admin')
def adminCreateTeacher():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        name = request.form.get('name')
        age = request.form.get('age')
        address = request.form.get('address')
        phone = request.form.get('phone')

        existing_teacher_check_username = "SELECT * FROM users WHERE username = %s"
        mycursor.execute(existing_teacher_check_username, (username,))
        existing_teacher_username = mycursor.fetchone()

        # checking for existing teacher username
        if existing_teacher_username:
            flash('User with the same username already exists. Please choose a different username.')
            log_this("User with the same username is entered but already exists", user_id=1)
            return render_template('Admin/adminCreateTeacher.html')

        existing_teacher_email = "SELECT * FROM users WHERE email = %s"
        mycursor.execute(existing_teacher_email, (email,))
        existing_teacher_email_check = mycursor.fetchone()

        # checking for existing teacher email
        if existing_teacher_email_check:
            flash('User with the same email already exists. Please choose a different email.', 'danger')
            return render_template('Admin/adminCreateTeacher.html')

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            role = 'teacher'
            print("Received form data:")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print(f"Email: {email}")
            print(f"Name: {name}")
            print(f"Age: {age}")
            print(f"Address: {address}")
            print(f"Phone: {phone}")
            query = """
                        INSERT INTO users (username, password, email, name ,age, address, phone, role)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)  # Include 'name' in the query
                    """
            # Tuple to make sure the input cannot be changed
            values = (username, hashed_password, email, name, age, address, phone, role)
            # Executing the parameterized query and the tuple as the inputs
            mycursor.execute(query, values)
            mydb.commit()
            flash('Teacher created successfully!', 'success')
            log_this("Teacher account created successfully", user_id=1)
            return redirect(url_for('blogs'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            log_this(f'An error occurred: {str(e)}', user_id=1)
            return render_template('Admin/adminCreateTeacher.html')

    return render_template('Admin/adminCreateTeacher.html')


@app.route('/adminDeleteTeacher/<int:id>', methods=['GET', 'POST'])
@roles_required('admin')
def adminDeleteTeacher(id):
    try:
        select_query = "SELECT * FROM users WHERE id = %s"
        mycursor.execute(select_query, (id,))
        teacher = mycursor.fetchone()

        if teacher:
            delete_query = "DELETE FROM users WHERE id = %s"
            mycursor.execute(delete_query, (id,))
            mydb.commit()
            log_this(f"Teacher Account with User ID {id} deleted", user_id=1)

            return redirect(url_for('blogs'))
        else:
            return "Teacher not found"

    except Exception as e:
        print('Error: ', e)
        mydb.rollback()
        log_this("Error occurred while deleting teacher",user_id=1)
        return "Error occurred while deleting teacher"


@app.route('/adminTeacherTable', methods=['GET'])
@roles_required('admin')
def adminTeachersRetrieve():
    if 'user' in session and 'id' in session['user']:
        admin_id = session['user']['id']
    select_query = "SELECT * FROM users WHERE role = %s or role = %s"
    mycursor.execute(select_query, ('teacher', 'admin',))
    rows = mycursor.fetchall()
    count = len(rows)
    return render_template('Admin/adminTeacherTable.html', teachers=rows, count=count, admin_id=admin_id)


@app.route('/adminTeacherUpdate/<int:id>', methods=['GET', 'POST'])
@roles_required('admin')
def adminTeacherUpdate(id):
    if 'user' in session and 'id' in session['user']:
        admin_id = session['user']['id']

    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            role = request.form.get('role')
            lock_account = request.form.get('lock_account')
            unlock_account = request.form.get('unlock_account')

            # Fetch existing teacher details from the database
            select_query = "SELECT id, username, password, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            teacher_details = mycursor.fetchone()

            if teacher_details:
                # Hash the password if provided, otherwise keep the existing one
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) if password else teacher_details[2]

                update_teacher = "UPDATE users SET username = %s, password = %s, email = %s, role = %s WHERE id = %s"
                data = (username, hashed_password, email, role, id)
                mycursor.execute(update_teacher, data)

                if lock_account:
                    mycursor.execute('UPDATE users SET locked = TRUE, locked_until = %s WHERE id = %s', (
                        datetime.now() + timedelta(days=365),
                        id))  # Locked for a long period, essentially permanently locked

                # Unlock account if requested
                if unlock_account:
                    mycursor.execute(
                        'UPDATE users SET failed_login_attempts = 0, locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s',
                        (id,))

                mydb.commit()

                flash('Teacher details updated successfully', 'success')
                log_this("Teachers detail updated successfully", user_id=1)
                return redirect(url_for('adminTeacherUpdate', id=teacher_details[0]))

            else:
                log_this("Teacher not found while updating account", user_id=1)
                return "Teacher not found"

        except Exception as e:
            print("Error: ", e)
            mydb.rollback()
            log_this("Error occurred while updating teacher", user_id=1)
            return "Error occurred while updating teacher"

    else:
        try:
            # Fetch existing teacher details to prepopulate the form, excluding the hashed password
            select_query = "SELECT id, username, email, role, locked FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            teacher_details = mycursor.fetchone()

            if teacher_details:
                return render_template('Admin/updateTeacher.html', teacher_details=teacher_details, admin_id=admin_id)
            else:
                return render_template('Admin/updateTeacher.html', teacher_details=None, error="Teacher not found")

        except Exception as e:
            print('Error:', e)
            log_this("Error occurred while fetching teacher details", user_id=1)
            return "Error occurred while fetching teacher details"


@app.route('/adminCreateStudent', methods=['GET', 'POST'])
@roles_required('admin')
def adminCreateStudent():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        name = request.form.get('name')
        age = request.form.get('age')
        address = request.form.get('address')
        phone = request.form.get('phone')

        existing_student_check_username = "SELECT * FROM users WHERE username = %s"
        mycursor.execute(existing_student_check_username, (username,))
        existing_student_check_username = mycursor.fetchone()

        # checking for existing teacher username
        if existing_student_check_username:
            flash('User with the same username already exists. Please choose a different username.')
            return render_template('adminCreateStudent.html')

        existing_student_email = "SELECT * FROM users WHERE email = %s"
        mycursor.execute(existing_student_email, (email,))
        existing_student_email = mycursor.fetchone()

        # checking for existing teacher email
        if existing_student_email:
            flash('User with the same email already exists. Please choose a different email.')
            log_this("User with the same email already exists when creating student", user_id=1)
            return render_template('Admin/adminCreateStudent.html')

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            role = 'student'
            print("Received form data:")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print(f"Email: {email}")
            print(f"Name: {name}")
            print(f"Age: {age}")
            print(f"Address: {address}")
            print(f"Phone: {phone}")
            query = """
                        INSERT INTO users (username, password, email, name ,age, address, phone, role)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)  # Include 'name' in the query
                    """
            # Tuple to make sure the input cannot be changed
            values = (username, hashed_password, email, name, age, address, phone, role)
            # Executing the parameterized query and the tuple as the inputs
            mycursor.execute(query, values)
            mydb.commit()
            flash('Student created successfully!', 'success')
            log_this("Student created successfully",user_id=1)
            return redirect(url_for('blogs'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            log_this("Error occurred", user_id=1)
            return render_template('Admin/adminCreateStudent.html')

    return render_template('Admin/adminCreateStudent.html')


@app.route('/adminStudentTable', methods=['GET'])
@roles_required('admin')
def adminUsersRetrieve():
    select_query = "SELECT * FROM users WHERE role = %s"
    mycursor.execute(select_query, ('student',))
    rows = mycursor.fetchall()
    count = len(rows)
    return render_template('Admin/adminStudentTable.html', nameOfPage='User Management System', students=rows, count=count)


@app.route('/adminStudentUpdate/<int:id>', methods=['GET', 'POST'])
@roles_required('admin')
def adminStudentUpdate(id):
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            role = request.form.get('role')
            lock_account = request.form.get('lock_account')
            unlock_account = request.form.get('unlock_account')

            # Fetch existing product details from the database
            select_query = "SELECT id, username, password, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            student_details = mycursor.fetchone()

            if student_details:
                # Hash the password if provided, otherwise keep the existing one
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) if password else student_details[2]

                update_student = "UPDATE users SET username = %s, password = %s, email = %s, role = %s WHERE id = %s"
                data = (username, hashed_password, email, role, id)
                mycursor.execute(update_student, data)
                # Lock account if requested
                if lock_account:
                    mycursor.execute('UPDATE users SET locked = TRUE, lockout_time = %s WHERE id = %s', (
                    datetime.now() + timedelta(days=365),
                    id))  # Locked for a long period, essentially permanently locked

                # Unlock account if requested
                if unlock_account:
                    mycursor.execute(
                        'UPDATE users SET failed_login_attempts = 0, locked = FALSE, lockout_time = NULL, unlock_token = NULL WHERE id = %s',
                        (id,))

                mydb.commit()

                flash('Student details updated successfully.', 'success')
                log_this("Student details updated successfully", user_id=1)
                return redirect(url_for('adminStudentUpdate', id=student_details[0]))

            else:
                log_this("User not found when updating Student",user_id=1)
                return "Student not found"

        except Exception as e:
            print("Error: ", e)
            mydb.rollback()
            log_this("Error occurred while updating student",user_id=1)
            return "Error occurred while updating student"

    else:
        try:
            # Fetch existing teacher details to prepopulate the form
            select_query = "SELECT id, username, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            student_details = mycursor.fetchone()

            if student_details:
                return render_template('Admin/updateStudent.html', student_details=student_details)
            else:
                return render_template('Admin/updateStudent.html', student_details=None, error="Student not found")

        except Exception as e:
            print('Error:', e)
            log_this("Error occurred while fetching student details",user_id=1)
            return "Error occurred while fetching student details"


@app.route('/adminDeleteStudent/<int:id>', methods=['GET', 'POST'])
def adminDeleteStudent(id):
    try:
        select_query = "SELECT * FROM users WHERE id = %s"
        mycursor.execute(select_query, (id,))
        student = mycursor.fetchone()

        if student:
            delete_query = "DELETE FROM users WHERE id = %s"
            mycursor.execute(delete_query, (id,))
            mydb.commit()

            return redirect(url_for('blogs'))
        else:
            log_this("User not found when deleting account",id)
            return "Student not found"

    except Exception as e:
        print('Error: ', e)
        mydb.rollback()
        log_this("Error occurred while deleting student", id)
        return "Error occurred while deleting student"


@app.route('/adminstore')
@roles_required('admin')
def adminstore():
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    mycursor.close()
    return render_template("Store/adminStore.html", products=products)


@app.route('/adminstoreaddpage', methods=['GET'])
@roles_required('admin')
def adminstoreaddpage():
    return render_template("Store/addProduct.html")


@app.route('/adminstoreadd', methods=['POST'])
@roles_required('admin')
def adminstoreadd():
    mycursor = mydb.cursor()
    name = request.form['name']
    description = request.form['description']
    price_in_points = request.form['price_in_points']
    quantity = request.form['quantity']

    # Handle image upload
    file = request.files.get('image')
    if file and allowed_file(file.filename):
        filename = file.filename
        filename = secure_filename(filename)
        filepath = f"{app.config['UPLOAD_FOLDER']}/{filename}"
        file.save(filepath)
        image_path = f"img/{filename}"  # Store relative path

        mycursor.execute(
            "INSERT INTO storeproducts (name, description, quantity, image_path, price_in_points) VALUES (%s, %s, %s, %s, %s)",
            (name, description, quantity, image_path, price_in_points))
        mydb.commit()
        mycursor.close()
        return redirect(url_for('adminstore'))

    return "File not allowed or not provided", 400


@app.route('/adminstoreupdatepage/<int:product_id>', methods=['GET'])
@roles_required('admin')
def adminstoreupdatepage(product_id):
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts WHERE id = %s", (product_id,))
    product = mycursor.fetchone()
    mycursor.close()
    return render_template("Store/updateProduct.html", product=product)


@app.route('/adminstoreupdate', methods=['POST'])
@roles_required('admin')
def adminstoreupdate():
    mycursor = mydb.cursor()
    product_id = request.form['product_id']
    name = request.form['name']
    description = request.form['description']
    price_in_points = request.form['price_in_points']
    quantity = request.form['quantity']

    # Handle image upload
    file = request.files.get('image')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = f"{app.config['UPLOAD_FOLDER']}/{filename}"
        file.save(filepath)
        image_path = f"img/{filename}"  # Store relative path

        # Update the product with a new image
        mycursor.execute(
            "UPDATE storeproducts SET name = %s, description = %s, quantity = %s, image_path = %s, price_in_points = %s WHERE id = %s",
            (name, description, quantity, image_path, price_in_points, product_id))
    else:
        # Update the product without changing the image
        mycursor.execute(
            "UPDATE storeproducts SET name = %s, description = %s, quantity = %s, price_in_points = %s WHERE id = %s",
            (name, description, quantity, price_in_points, product_id))

    mydb.commit()
    mycursor.close()
    log_this("Products in store updated", user_id=1)
    return redirect(url_for('adminstore'))


@app.route('/adminstoredelete', methods=['POST'])
@roles_required('admin')
def adminstoredelete():
    mycursor = mydb.cursor()
    product_id = request.form['product_id']
    mycursor.execute("DELETE FROM storeproducts WHERE id = %s", (product_id,))
    mydb.commit()
    mycursor.close()
    log_this("Product deleted successfully", user_id=1)
    return redirect(url_for('adminstore'))


@app.route('/blogs')
@roles_required('admin')
def blogs():
    mycursor.execute("SELECT * FROM audit_logs")
    data = mycursor.fetchall()
    print(data)
    return render_template("audit_logs.html", data=data, nameOfPage='Log')
