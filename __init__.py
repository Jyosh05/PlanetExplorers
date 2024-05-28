from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
import mysql.connector
# Configuration is a file containing sensitive information
from Configuration import DB_Config, secret_key, admin_config, email_config, RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY, \
    GOOGLE_VERIFY_URL
import re
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import requests
import psycopg2
import datetime

#!!!!!IF THERE IS ANY DB ERROR, CHECK THE CONFIG FILE AND IF THE PASSWORD IS CONFIG PROPERLY!!!!!

#!!!!CHECK THE INPUT FUNCTION BEFORE USING, THERE IS CURRENTLY 1 FUNCTION THAT ADDS IN NEW USERS AS STUDENTS ONLY!!!!
#ALL FUNCTIONS: input_validation(input_string), age_validation(age), update_info(input_string),add_info(username, password, email, age, address),
#delete_info(),get_info()


app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Can also use 'Strict'
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

app.config['SESSION_PROTECTION'] = 'strong'

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

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

mydb = mysql.connector.connect(
    host=DB_Config['host'],
    user=DB_Config['user'],
    password=DB_Config['password'],
    port=DB_Config['port'],
    database=DB_Config['database']
)

mycursor = mydb.cursor(buffered=True)

def regenerate_session():
    session.modified = True


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


# NEED ENCRYPTION OF THE PASSWORD
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

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
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


# NEED DECRYPTION OF THE PASSWORD
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

        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
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
    return serializer.dumps(email,
                            salt=app.config['SECRET_KEY'])  # dumps method serializes the email address into a token


# the salt parameter adds an additional layer of security
# Using the secret key as the salt ensures that the token cannot be tampered with or replicated without the secret key.

def confirm_token(token, expiration=300):
    # a URLSafeTimedSerializer object is created using the same secret key.
    # This ensures that the token can be verified against the same key and salt used to create it.
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        # The loads method deserializes the token to retrieve the original email address.
        email = serializer.loads(token, salt=app.config['SECRET_KEY'],
                                 max_age=expiration)  # The salt parameter ensures that the token was generated with the correct secret key.
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
    return data['success']


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

def log_this(event, user_id = "unknown"):
    # We do a select max to get the last log_id in the table
    # the fetchone returns the field in a tuple format
    mycursor.execute("SELECT MAX(log_id) FROM audit_logs")
    actual_id = mycursor.fetchone()
    print(actual_id[0])
    if actual_id == None:
        actual_id = 0
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
            admin_config['username'], hashed_password, admin_config['email'], admin_config['name'], admin_config['age'],
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


@app.route('/store')
@limiter.limit("5 per minute")
def store():
    return render_template("store.html")


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
                log_this("login successful", user)
                #return render_template("profile.html")
                role = user[9]
                print(f"Logged in user role: {role}")
                return redirect(url_for(role_redirects.get(role, 'home')))
            else:
                log_this("Invalid username or password")
                print("Invalid username or password")
        except ValueError as e:
            print(f"Error: {e}")
            log_this("Runtime error during login")
    return render_template("login.html")


@app.route('/forget_password')
def forget_password():
    return render_template("forget_password.html")


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


@app.route('/learnerHome')
@roles_required('student')
def learnerHome():
    return render_template('profile.html')


'''
@app.route('/store')
@limiter.limit("5 per minute")
def store():
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    return render_template("store.html", products=products)

@app.route('/admin/store')
@role_required('admin')
def admin_store():
    mycursor.execute("SELECT * FROM storeproducts")
    products = mycursor.fetchall()
    return render_template("adminStore.html", products=products)

@app.route('/admin/store/add', methods=['POST'])
@role_required('admin')
def add_product():
    name = request.form['name']
    description = request.form['description']
    price = request.form['price']
    quantity = request.form['quantity']
    mycursor.execute("INSERT INTO storeproducts (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                     (name, description, price, quantity))
    mydb.commit()
    return redirect(url_for('admin_store'))

@app.route('/admin/store/delete', methods=['POST'])
@role_required('admin')
def delete_product():
    product_id = request.form['product_id']
    mycursor.execute("DELETE FROM storeproducts WHERE id = %s", (product_id,))
    mydb.commit()
    return redirect(url_for('admin_store'))

@app.route('/admin/store/update', methods=['POST'])
@role_required('admin')
def update_product():
    product_id = request.form['product_id']
    name = request.form['name']
    description = request.form['description']
    price = request.form['price']
    quantity = request.form['quantity']
    mycursor.execute("UPDATE storeproducts SET name = %s, description = %s, price = %s, quantity = %s WHERE id = %s",
                     (name, description, price, quantity, product_id))
    mydb.commit()
    return redirect(url_for('admin_store'))

'''

@app.route('/blogs')
def blogs():
    mycursor.execute("SELECT * FROM audit_logs")
    data = mycursor.fetchall()
    print(data)
    return render_template("audit_logs.html", data = data)




if __name__ == '__main__':
    # calling create table function
    # Call the function when the application starts
    create_admin_user()
    app.run(debug=True)



