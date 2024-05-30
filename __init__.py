from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
import mysql.connector
from werkzeug.utils import secure_filename

# Configuration is a file containing sensitive information
from Configuration import DB_Config, secret_key, admin_config, email_config, RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY, PEPPER
import re
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_session import Session
from datetime import timedelta
import requests
import psycopg2
import datetime
import urllib.parse

# !!!!!IF THERE IS ANY DB ERROR, CHECK THE CONFIG FILE AND IF THE PASSWORD IS CONFIG PROPERLY!!!!!

# !!!!CHECK THE INPUT FUNCTION BEFORE USING, THERE IS CURRENTLY 1 FUNCTION THAT ADDS IN NEW USERS AS STUDENTS ONLY!!!!
# ALL FUNCTIONS: input_validation(input_string), age_validation(age), update_info(input_string),add_info(username, /password, email, age, address),
# delete_info(),get_info()


app = Flask(__name__)

# Mail configuration
app.config.update(
    MAIL_SERVER=email_config['mail_server'],
    MAIL_PORT=email_config['mail_port'],
    MAIL_USE_TLS=email_config['mail_use_tls'],
    MAIL_USE_SSL=email_config['mail_use_ssl'],
    MAIL_USERNAME=email_config['mail_username'],
    MAIL_PASSWORD=email_config['mail_password']
)
mail = Mail(app)
GOOGLE_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'


mydb = mysql.connector.connect(
    host=DB_Config['host'],
    user=DB_Config['user'],
    password=DB_Config['password'],
    port=DB_Config['port'],
    database=DB_Config['database']
)

mycursor = mydb.cursor(buffered=True)

# Caleb's entire rate limiting, secure session management, https enforcement
# Session Management
app.config['SECRET_KEY'] = secret_key # cryptographic signing, prevent session tampering and various attacks
app.config['SESSION_COOKIE_HTTPONLY'] = True # prevent client side JS access to s.cookie. prevent XSS
app.config['SESSION_COOKIE_SECURE'] = True # restrict to only HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # prevent CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=3600)  # session duration
app.config['SESSION_REFRESH_EACH_REQUEST'] = True # refreshed on request, if user active :)
app.config['SESSION_PROTECTION'] = 'strong' # detect IP address during a sessioon
app.config['SESSION_TYPE'] = 'filesystem' # session data stored on mah server files
app.config['SESSION_PERMANENT'] = False # browser closed? NO MORE SESSION!
app.config['SESSION_USE_SIGNER'] = True # digitally signing the cookie sessions. no tampering by clients
Session(app)


def regenerate_session(): #regenerate session. update session data, ensure security after login or logout.
    session.modified = True
    session.new = True


# Rate limiter to limit rates
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


# Aloysius Portion
def input_validation(input_string):
    # INJECTION, JAVASCRIPT AND PYTHON MALICIOUS CODE USING REGEX
    sql_injection_patterns = [
        r"\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|EXEC|UNION|--|;)\b",
        r"\b(OR|AND)\b\s*?[^\s]*?="
    ]
    javascript_pattern = r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>"
    python_script_pattern = r"\b(import|from|exec|eval|os|sys|subprocess)\b"

    combined_pattern = "|".join(sql_injection_patterns) + "|" + javascript_pattern + "|" + python_script_pattern

    combined_regex = re.compile(combined_pattern, re.IGNORECASE)

    if combined_regex.search(input_string):
        raise ValueError("Invalid input: Harmful input detected")
    return True


def age_validation(age):
    if not isinstance(age, int) or age <= 0:
        raise ValueError("Invalid input: Age must be a positive integer")
    return True


def validate_phone_number(phone_number):
    pattern = r"^\+(?:[0-9] ?){6,14}[0-9]$"
    if re.match(pattern, phone_number) == False:
        raise ValueError("Invalid input: Phone number does not match the requirements")
    return True


def update_info(input_string):
    pass


def check_existing_credentials(username=None, email=None):
    try:
        if username:
            mycursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing_user = mycursor.fetchone()
            if existing_user:
                return True
        if email:
            mycursor.execute(f"SELECT * FROM users WHERE email = %s", (email,))
            existing_email = mycursor.fetchone()
            if existing_email:
                return True
    except mysql.connector.Error as err:
        print(f"Error: {str(err)}")


# READ THIS FIRST!!!!!
# add_info with role default as "student", if you need to change role, cannot use this function
def add_info(username, password, email, name, age, address, phone):
    try:
        # Checking the inputs from the add_info function
        input_validation(username)
        input_validation(password)
        input_validation(email)
        input_validation(name)  # This line checks the input validation for name
        age_validation(int(age))
        input_validation(address)
        validate_phone_number(phone)
        # Checking if the user is in the db or not
        if check_existing_credentials(username, email):
            print("Username or email already in use")

        peppered_password = password + PEPPER

        hashed_password = bcrypt.hashpw(peppered_password.encode('utf-8'), bcrypt.gensalt())
        # Standardized role of "student" for new user
        role = 'student'
        # Parameterized query
        query = """
            INSERT INTO users (username, password, email, name ,age, address, phone, role)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)  # Include 'name' in the query
        """
        # Tuple to make sure the input cannot be changed
        values = (username, hashed_password, email, name, age, address, phone, role)
        # Executing the parameterized query and the tuple as the inputs
        mycursor.execute(query, values)
        mydb.commit()
        print("User added successfully")
    # Exception if the SQL connector has an error
    except mysql.connector.Error as err:
        print(f"error: {str(err)}")
    # Input validation error, means there is malicious code
    except ValueError as e:
        print(f"error: {str(e)}")


def delete_info(username, password):
    try:
        input_validation(username)
        input_validation(password)
        query = "SELECT password FROM users WHERE username = %s"
        mycursor.execute(query, (username,))
        user = mycursor.fetchone()
        if not user:
            print("User not found")

        stored_password = user[0]

        peppered_password = password + PEPPER

        if bcrypt.checkpw(peppered_password.encode('utf-8'), stored_password.encode('utf-8')):
            delete_query = "DELETE FROM users WHERE username = %s"
            mycursor.execute(delete_query, (username,))
            mydb.commit()
            print("User deleted successfully")
        else:
            print("Error, incorrect password")
    except mysql.connector.Error as err:
        print(f"Error: {str(err)}")
    except ValueError as e:
        print(f"Error: {str(e)}")


def get_info():
    pass


# token generation and validation functions

# generate token using user email
def generate_confirm_token(email):
    # URLSafeTimedSerializer is a class in itsdangerous designed to create and verify timed, URL safe tokens
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # The serializer requires a secret key
    # to ensure the tokens are securely generated and can be validated later.
    return serializer.dumps(email, salt=app.config['SECRET_KEY'])  # dumps method serializes the email address into a token


# the salt parameter adds an additional layer of security
# Using the secret key as the salt ensures that the token cannot be tampered with or replicated without the secret key.

def confirm_token(token, expiration=300):
    # a URLSafeTimedSerializer object is created using the same secret key.
    # This ensures that the token can be verified against the same key and salt used to create it.
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        # The loads method deserializes the token to retrieve the original email address.
        email = serializer.loads(token, salt=app.config['SECRET_KEY'], max_age=expiration)  # The salt parameter ensures that the token was generated with the correct secret key.
    except SignatureExpired:  # if token is expired or invalid, it returns false
        return False
    return email


def send_reset_link_email(email, subject, template):  # template is the html content of the email
    msg = Message(subject, recipients=[email], html=template, sender='no-reply')
    mail.send(msg)


# function to verify recaptcha
def verify_response(response):
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response
    }
    response = requests.post(GOOGLE_VERIFY_URL, data=payload)
    data = response.json()
    print(data)
    return data['success']


# Function to update user password
def update_password(email, new_password):
    try:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update the user's password in the database
        update_query = "UPDATE users SET password = %s WHERE email = %s"
        mycursor.execute(update_query, (hashed_password, email))
        mydb.commit()

        print("Password updated successfully")
    except Exception as e:
        print("Error updating password:", e)


# Role-based access control
def roles_required(*roles):
    def wrapper(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if 'user' not in session or session['user']['role'] not in roles:
                return abort(403)  # Forbidden
            return func(*args, **kwargs)

        return decorated_function

    return wrapper


role_redirects = {
    'admin': 'adminHome',
    'teacher': 'teacherHome',
    'student': 'learnerHome'
}

tableCheck = ['users']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'users'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
                    CREATE TABLE IF NOT EXISTS users(
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        email VARCHAR(255) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        age INT NOT NULL,
                        address VARCHAR(255),
                        phone INT NOT NULL,
                        profilePic VARCHAR(600) NULL,
                        role ENUM('student','teacher','admin') NOT NULL
                    )
                    """)
        print(f"Table 'users' Created")

mycursor.execute('SELECT * FROM users')
print(f"Using table 'users' ")

users = mycursor.fetchall()

tableCheck = ['audit_logs']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'audit_logs'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs(
                log_id INT PRIMARY KEY,
                event VARCHAR(100) NULL,
                timestamp DATETIME NULL,
                user_id VARCHAR(45) NULL
                
            )
        """)

    print(f"Table 'audit_logs' Created")

mycursor.execute('SELECT * FROM audit_logs')
print(f"Using Table 'audit_logs'")

audit_log = mycursor.fetchall()


tableCheck = ['storeproducts']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'storeproducts'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
        CREATE TABLE `storeproducts` (
             `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
             `name` VARCHAR(255) NOT NULL,
             `description` VARCHAR(600),
             `price` DECIMAL(10,2) NOT NULL,
            `quantity` INT NOT NULL,
            `image_path` VARCHAR(255) NOT NULL

            )
        """)

    print(f"Table 'storeproducts' Created")

mycursor.execute('SELECT * FROM storeproducts')
print(f"Using Table 'storeproducts'")

storeproducts = mycursor.fetchall()


def log_this(event, user_id="unknown"):
    # We do a select max to get the last log_id in the table
    # the fetchone returns the field in a tuple format
    mycursor.execute("SELECT MAX(log_id) FROM audit_logs")
    actual_id = mycursor.fetchone()
    print(actual_id[0])
    if actual_id[0] is None:
        actual_id = (0,)  # Ensure actual_id is a tuple with the first element as 0
    next_id = actual_id[0] + 1
    # ts1 = timestamp()
    sql = "INSERT INTO audit_logs (log_id, event, timestamp, user_id) VALUES (%s,%s,%s,%s)"
    val = (next_id, event, datetime.datetime.now(), user_id)
    mycursor.execute(sql, val)

    mydb.commit()


def create_admin_user():
    try:
        check_admin_query = "SELECT * FROM users WHERE role = 'admin'"
        mycursor.execute(check_admin_query)
        existing_admin = mycursor.fetchone()

        if existing_admin:
            print("Admin already exists")
        else:
            plain_password = admin_config['password']
            hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

            insert_admin_query = "INSERT INTO users (username, password, email, name, age, address, phone, role) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            admin_user = (
                admin_config['username'], hashed_password, admin_config['email'], admin_config['name'],
                admin_config['age'],
                admin_config['address'], admin_config['phone'], admin_config['role'])

            mycursor.execute(insert_admin_query, admin_user)
            mydb.commit()
            print("Admin user created successfully")
    except mysql.connector.Error as err:
        print(f"Error while inserting admin user: {err}")


@app.before_request
def before_request():
    if 'user' in session:
        session.modified = True
    else:
        session.clear()


@app.route('/')
@limiter.limit("5 per minute")
def home():
    return render_template("home.html")  # need to create template


@app.route('/profile')
@limiter.limit("5 per minute")
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template("profile.html")


# need to make a functional login page
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

    return render_template("login.html")


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

    return render_template("forget_password.html", site_key=RECAPTCHA_SITE_KEY)


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

    return render_template('reset_password.html', token=token)



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
    return render_template('register.html')


@app.route('/adminHome')
@roles_required('admin')
def adminHome():
    return render_template('adminHome.html')

@app.route('/teacherHome')
@roles_required('teacher')
def teacherHome():
    return 'Welcome Teacher'

@app.route('/adminTeacherTable', methods=['GET'])
@roles_required('admin')
def adminTeachersRetrieve():
    select_query = "SELECT * FROM users WHERE role = %s or role = %s"
    mycursor.execute(select_query, ('teacher', 'admin',))
    rows = mycursor.fetchall()
    count = len(rows)
    return render_template('adminTeacherTable.html', nameOfPage='Staff Management System', teachers=rows, count=count)

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
                update_teacher = "UPDATE users SET username = %s, password = %s, email = %s, role = %s WHERE id = %s"
                data = (username, password, email, role, id)
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
                return render_template('updateTeacher.html', teacher_details=teacher_details)
            else:
                return render_template('updateTeacher.html', teacher_details=None, error="Teacher not found")

        except Exception as e:
            print('Error:', e)
            return "Error occurred while fetching teacher details"


@app.route('/learnerHome')
@roles_required('student')
def learnerHome():
    return render_template('profile.html')

@app.route('/adminStudentTable', methods=['GET'])
@roles_required('admin')
def adminUsersRetrieve():
    select_query = "SELECT * FROM users WHERE role = %s"
    mycursor.execute(select_query, ('student',))
    rows = mycursor.fetchall()
    count = len(rows)
    return render_template('adminStudentTable.html', nameOfPage='User Management System', students=rows, count=count)

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
                update_student = "UPDATE users SET username = %s, password = %s, email = %s, role = %s WHERE id = %s"
                data = (username, password, email, role, id)
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
                return render_template('updateStudent.html', student_details=student_details)
            else:
                return render_template('updateStudent.html', student_details=None, error="Student not found")

        except Exception as e:
            print('Error:', e)
            return "Error occurred while fetching student details"


UPLOAD_FOLDER = 'static/img'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


@app.route('/store')
@limiter.limit("5 per minute")
def store():
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    mycursor.close()
    return render_template("store.html", products=products)


@app.route('/adminstore')
@roles_required('admin')
def adminstore():
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    mycursor.close()
    return render_template("adminStore.html", products=products)


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


@app.route('/blogs')
def blogs():
    mycursor.execute("SELECT * FROM audit_logs")
    data = mycursor.fetchall()
    print(data)
    return render_template("audit_logs.html", data=data, nameOfPage='Log')


if __name__ == '__main__':
    # calling create table function
    # Call the function when the application starts
    create_admin_user()
    app.run(debug=True)
