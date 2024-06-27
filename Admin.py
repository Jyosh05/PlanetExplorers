from utils import *
from flask import render_template, flash, request, redirect,url_for
from werkzeug.utils import secure_filename
@app.route('/adminHome')
@roles_required('admin')
def adminHome():
    return render_template('Admin/adminHome.html')

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
            flash('Teacher with the same username already exists. Please choose a different username.')
            return render_template('Admin/adminCreateTeacher.html')

        existing_teacher_email = "SELECT * FROM users WHERE email = %s"
        mycursor.execute(existing_teacher_email, (email,))
        existing_teacher_email_check = mycursor.fetchone()

        # checking for existing teacher email
        if existing_teacher_email_check:
            flash('Teacher with the same email already exists. Please choose a different email.')
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
            return redirect(url_for('adminHome'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            return render_template('Admin/adminCreateTeacher.html')

    return render_template('Admin/adminCreateTeacher.html')


@app.route('/adminDeleteTeacher/<int:id>', methods=['GET', 'POST'])
def adminDeleteTeacher(id):
    try:
        select_query = "SELECT * FROM users WHERE id = %s"
        mycursor.execute(select_query, (id,))
        teacher = mycursor.fetchone()

        if teacher:
            delete_query = "DELETE FROM users WHERE id = %s"
            mycursor.execute(delete_query, (id,))
            mydb.commit()

            return redirect(url_for('adminHome'))
        else:
            return "Teacher not found"

    except Exception as e:
        print('Error: ', e)
        mydb.rollback()
        return "Error occurred while deleting teacher"

@app.route('/adminTeacherTable', methods=['GET'])
@roles_required('admin')
def adminTeachersRetrieve():
    select_query = "SELECT * FROM users WHERE role = %s or role = %s"
    mycursor.execute(select_query, ('teacher', 'admin',))
    rows = mycursor.fetchall()
    count = len(rows)
    return render_template('Admin/adminTeacherTable.html', nameOfPage='Staff Management System', teachers=rows, count=count)

@app.route('/adminTeacherUpdate/<int:id>', methods=['GET', 'POST'])
@roles_required('admin')
def adminTeacherUpdate(id):
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            role = request.form.get('role')

            # Fetch existing product details from the database
            select_query = "SELECT id, username, password, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            teacher_details = mycursor.fetchone()

            if teacher_details:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) if password else \
                teacher_details[2]

                update_teacher = "UPDATE users SET username = %s, password = %s, email = %s, role = %s WHERE id = %s"
                data = (username, hashed_password, email, role, id)
                mycursor.execute(update_teacher, data)
                mydb.commit()

                return redirect(url_for('adminTeacherUpdate', id=teacher_details[0]))

            else:
                return "Teacher not found"

        except Exception as e:
            print("Error: ", e)
            mydb.rollback()
            return "Error occurred while updating teacher"

    else:
        try:
            # Fetch existing teacher details to prepopulate the form
            select_query = "SELECT id, username, password, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            teacher_details = mycursor.fetchone()

            if teacher_details:
                return render_template('Admin/updateTeacher.html', teacher_details=teacher_details)
            else:
                return render_template('Admin/updateTeacher.html', teacher_details=None, error="Teacher not found")

        except Exception as e:
            print('Error:', e)
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
            return redirect(url_for('adminHome'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
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

            # Fetch existing product details from the database
            select_query = "SELECT id, username, password, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            student_details = mycursor.fetchone()

            if student_details:
                # Hash the password if provided, otherwise keep the existing one
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) if password else \
                student_details[2]

                update_student = "UPDATE users SET username = %s, password = %s, email = %s, role = %s WHERE id = %s"
                data = (username, hashed_password, email, role, id)
                mycursor.execute(update_student, data)
                mydb.commit()

                return redirect(url_for('adminStudentUpdate', id=student_details[0]))

            else:
                return "Student not found"

        except Exception as e:
            print("Error: ", e)
            mydb.rollback()
            return "Error occurred while updating student"

    else:
        try:
            # Fetch existing teacher details to prepopulate the form
            select_query = "SELECT id, username, password, email, role FROM users WHERE id = %s"
            mycursor.execute(select_query, (id,))
            student_details = mycursor.fetchone()

            if student_details:
                return render_template('Admin/updateStudent.html', student_details=student_details)
            else:
                return render_template('Admin/updateStudent.html', student_details=None, error="Student not found")

        except Exception as e:
            print('Error:', e)
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

            return redirect(url_for('adminHome'))
        else:
            return "Student not found"

    except Exception as e:
        print('Error: ', e)
        mydb.rollback()
        return "Error occurred while deleting student"

@app.route('/adminstore')
@roles_required('admin')
def adminstore():
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    mycursor.close()
    return render_template("Store/adminStore.html", products=products)


@app.route('/adminstoreadd', methods=['POST'])
@roles_required('admin')
def adminstoreadd():
    mycursor = mydb.cursor()
    name = request.form['name']
    description = request.form['description']
    price = request.form['price']
    quantity = request.form['quantity']

    # Handle image upload
    file = request.files.get('image')
    if file and allowed_file(file.filename):
        filename = file.filename
        filename = secure_filename(filename)
        filepath = f"{app.config['UPLOAD_FOLDER']}/{filename}"
        # file.save(filepath)
        image_path = f"img/{filename}"  # Store relative path

        mycursor.execute(
            "INSERT INTO storeproducts (name, description, price, quantity, image_path) VALUES (%s, %s, %s, %s, %s)",
            (name, description, price, quantity, image_path))
        mydb.commit()
        mycursor.close()
        return redirect(url_for('adminstore'))

    return "File not allowed or not provided", 400


@app.route('/adminstoredelete', methods=['POST'])
@roles_required('admin')
def adminstoredelete():
    mycursor = mydb.cursor()
    product_id = request.form['product_id']
    mycursor.execute("DELETE FROM storeproducts WHERE id = %s", (product_id,))
    mydb.commit()
    mycursor.close()
    return redirect(url_for('adminstore'))


@app.route('/adminstoreupdate', methods=['POST'])
@roles_required('admin')
def adminstoreupdate():
    mycursor = mydb.cursor()
    product_id = request.form['product_id']
    name = request.form['name']
    description = request.form['description']
    price = request.form['price']
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
            "UPDATE storeproducts SET name = %s, description = %s, price = %s, quantity = %s, image_path = %s WHERE id = %s",
            (name, description, price, quantity, image_path, product_id))
    else:
        # Update the product without changing the image
        mycursor.execute(
            "UPDATE storeproducts SET name = %s, description = %s, price = %s, quantity = %s WHERE id = %s",
            (name, description, price, quantity, product_id))

    mydb.commit()
    mycursor.close()
    return redirect(url_for('adminstore'))

#DONE


@app.route('/blogs')
@roles_required('admin')
def blogs():
    mycursor.execute("SELECT * FROM audit_logs")
    data = mycursor.fetchall()
    print(data)
    return render_template("audit_logs.html", data=data, nameOfPage='Log')