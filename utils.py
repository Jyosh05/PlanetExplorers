
from flask import Flask, session, abort, flash, url_for
import mysql.connector


# Configuration is a file containing sensitive information
from Configuration import DB_Config, secret_key, admin_config, email_config, RECAPTCHA_SECRET_KEY, virusTotal_api,CLIENTID,CLIENTSECRET
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_session import Session
from datetime import timedelta, datetime
import requests
import secrets
import re

from authlib.integrations.flask_client import OAuth


app = Flask(__name__)
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
app.config['SECRET_KEY'] = secret_key  # cryptographic signing, prevent session tampering and various attacks
app.config['SESSION_COOKIE_HTTPONLY'] = True  # prevent client side JS access to s.cookie. prevent XSS
app.config['SESSION_COOKIE_SECURE'] = True  # restrict to only HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # prevent CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=3600)  # session duration
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # refreshed on request, if user active :)
app.config['SESSION_PROTECTION'] = 'strong'  # detect IP address during a session
app.config['SESSION_TYPE'] = 'filesystem'  # session data stored on my server files
app.config['SESSION_PERMANENT'] = False  # browser closed? NO MORE SESSION!
app.config['SESSION_USE_SIGNER'] = True  # digitally signing the cookie sessions. no tampering by clients
Session(app)

app.config['GOOGLE_CLIENT_ID'] = CLIENTID
app.config['GOOGLE_CLIENT_SECRET'] = CLIENTSECRET

oauth = OAuth(app)
google = oauth.register(
    name = 'google',
    client_id = app.config['GOOGLE_CLIENT_ID'],
    client_secret = app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
    authorize_params = None,
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    refresh_token_url = None,
    redirect_url = 'http://127.0.0.1:5000/auth/callback',
    client_kwargs = {'scope':'email profile'}
)


UPLOAD_FOLDER = 'static/img'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

role_redirects = {
    'admin': 'blogs',
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
                        role ENUM('student','teacher','admin') NOT NULL,
                        locked BOOLEAN DEFAULT FALSE,
                        unlock_token VARCHAR(255),
                        failed_login_attempts INT DEFAULT 0,
                        lockout_time DATETIME,
                        explorer_points INT DEFAULT 0,
                        email_verified BOOLEAN
                    )
                    """)
        print(f"Table 'users' Created")

mycursor.execute('SELECT * FROM users')
print(f"Using table 'users' ")

users = mycursor.fetchall()

tableCheck = ['oauth']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'oauth'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
            CREATE TABLE IF NOT EXISTS oauth(
                googleid VARCHAR(255) PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                email_verified BOOLEAN, 
                name VARCHAR(255),
                profilePic VARCHAR(600) NULL,
                role ENUM('student','teacher','admin') NOT NULL,
                explorer_points INT
            )
        """)


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
                id int NOT NULL AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description VARCHAR(600),
                quantity INT NOT NULL,
                image_path VARCHAR(255) NOT NULL,
                price_in_points INT NOT NULL
            )
        """)

    print(f"Table 'storeproducts' Created")

mycursor.execute('SELECT * FROM storeproducts')
print(f"Using Table 'storeproducts'")
storeproducts = mycursor.fetchall()


tableCheck = ['cart']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'cart'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
            CREATE TABLE IF NOT EXISTS cart(
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                total_points INT NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES storeproducts(id)
            )
        """)
        print(f"Table 'cart' Created")

mycursor.execute('SELECT * FROM cart')
print(f"Using Table 'cart'")
cart = mycursor.fetchall()


tableCheck = ['orders']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'orders'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
            CREATE TABLE `orders` (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                total_points INT,
                shipping_option VARCHAR(255),
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(255) DEFAULT 'Pending',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        print(f"Table 'orders' created")

mycursor.execute('SELECT * FROM orders')
print(f"Using Table 'orders'")
orders = mycursor.fetchall()


tableCheck = ['order_items']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'order_items'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
            CREATE TABLE `order_items` (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                order_id INT,
                product_id INT,
                quantity INT,
                price_in_points INT,
                FOREIGN KEY (order_id) REFERENCES orders(id),
                FOREIGN KEY (product_id) REFERENCES storeproducts(id)
            )
        """)
        print(f"Table 'order_items' created")

mycursor.execute('SELECT * FROM order_items')
print(f"Using Table 'order_items'")
order_items = mycursor.fetchall()


tableCheck = ['token_validation']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'token_validation'")
    tableExist = mycursor.fetchone()

    if not tableExist:
        mycursor.execute("""
                    CREATE TABLE IF NOT EXISTS token_validation(
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        email VARCHAR(255) NOT NULL,
                        token VARCHAR(255) UNIQUE NOT NULL,
                        expiration DATETIME NOT NULL,
                        used BOOLEAN DEFAULT FALSE
                    )
                    """)
        print(f"Table 'token_validation' Created")

mycursor.execute('SELECT * FROM token_validation')
print(f"Using table 'token_validation' ")
token_validation = mycursor.fetchall()

tableCheck = ['modules']
for a in tableCheck:
    mycursor.execute(f"SHOW TABLES LIKE 'modules'")
    tableExist = mycursor.fetchone()
    if not tableExist:
        mycursor.execute("""
            CREATE TABLE IF NOT EXISTS modules(
                module_id INT AUTO_INCREMENT PRIMARY KEY,
                module_name VARCHAR(255) NOT NULL,
                teacher_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print(f"Table 'modules' Created")

mycursor.execute('SELECT * FROM modules')
print(f"Using table 'modules'")
modules = mycursor.fetchall()

# Check if the 'questions' table exists, and create it if not
mycursor.execute("SHOW TABLES LIKE 'questions'")
tableExist = mycursor.fetchone()

if not tableExist:
    mycursor.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            question_id INT AUTO_INCREMENT PRIMARY KEY,
            module_id INT,
            question VARCHAR(1024) NOT NULL,
            choice_a VARCHAR(255) NOT NULL,
            choice_b VARCHAR(255) NOT NULL,
            choice_c VARCHAR(255) NOT NULL,
            choice_d VARCHAR(255) NOT NULL,
            answer CHAR(1) NOT NULL,
            explorer_points INT NOT NULL,
            FOREIGN KEY (module_id) REFERENCES modules(module_id)
        )
    """)
    print("Table 'questions' created")
else:
    print("Table 'questions' already exists")

# Verify if the 'questions' table has been created
mycursor.execute('SELECT * FROM questions LIMIT 1')
print("Using table 'questions'")
questions = mycursor.fetchall()
print(questions)


def regenerate_session():  # regenerate session. update session data, ensure security after login or logout.
    session.modified = True


# Rate limiter to limit rates
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"]
)


def input_validation(*input_strings):
    # Patterns for detecting harmful content
    sql_injection_patterns = [
        r"\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|EXEC|UNION|--|;)\b",
        r"\b(OR|AND)\b\s*?[^\s]*?="
    ]
    javascript_pattern = r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>"
    python_script_pattern = r"\b(import|from|exec|eval|os|sys|subprocess)\b"

    # Combine all patterns into one
    combined_pattern = "|".join(sql_injection_patterns) + "|" + javascript_pattern + "|" + python_script_pattern

    # Compile the combined regex pattern
    combined_regex = re.compile(combined_pattern, re.IGNORECASE)

    # Check each input string against the combined regex pattern
    for input_string in input_strings:
        if combined_regex.search(input_string):
            raise ValueError("Invalid input: Harmful input detected")
        # Log harmless input
        log_this("Input validated: No harmful content detected")

    return True


def age_validation(age):
    try:
        age = int(age)
    except ValueError:
        raise ValueError("Invalid input: Age must be a positive integer")

    if age <= 0:
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
        input_validation(username, password, email, name, address)
        age_validation(int(age))
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


def process_payment(card_name, card_number, exp_month, exp_year, cvv):
    try:
        # Validate input for harmful content
        input_validation(card_name, card_number, exp_month, exp_year, cvv)

        # Validate card details
        card_name_valid = validate_card_name(card_name)
        card_number_valid = validate_card_number(card_number)
        expiry_date_valid = validate_expiry_date(exp_month, exp_year)
        cvv_valid = validate_cvc(cvv)

        if card_name_valid and card_number_valid and expiry_date_valid and cvv_valid:
            print("Teacher Added Successfully")
            return True
    except ValueError as e:
        print(f"Payment validation failed: {e}")
    return False


def validate_card_name(name):
    return len(name) > 0

def validate_card_number(number):
    number = number.replace(" ", "")  # Remove spaces
    number = number.replace("-", "")  # removes hyphen
    return re.match(r"^\d{16}$", number) is not None


# Validate Expiry Date
def validate_expiry_date(month, year):
    months = {
        "01": "January", "02": "February", "03": "March", "04": "April", "05": "May",
        "06": "June", "07": "July", "08": "August", "09": "September", "10": "October",
        "11": "November", "12": "December"
    }
    return month in months and year.isdigit() and len(year) == 4


# Validate CVV
def validate_cvc(cvc):
    return re.match(r"^\d{3}$", cvc) is not None

# Update User Role Function
def update_user_role(username, role):
    try:
        query = "UPDATE users SET role = %s WHERE username = %s"
        values = (role, username)
        mycursor.execute(query, values)
        mydb.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Database error: {str(err)}")
        return False

# Add Teacher Information Function
def add_info_teacher(username, password, email, name, age, address, phone):
    try:
        input_validation(username, password, email, name, address)
        age = int(age)
        if age < 0:
            raise ValueError("Invalid age")
        validate_phone_number(phone)

        if check_existing_credentials(username, email):
            print("Username or email already in use")
            return False

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        role = 'teacher'
        query = """
            INSERT INTO users (username, password, email, name, age, address, phone, role)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (username, hashed_password, email, name, age, address, phone, role)
        mycursor.execute(query, values)
        mydb.commit()
        print("Teacher added successfully")
        return True
    except mysql.connector.Error as err:
        print(f"Database error: {str(err)}")
        return False
    except ValueError as e:
        print(f"Validation error: {str(e)}")
        return False


def delete_info(username, password):
    try:
        input_validation(username, password)
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
    token = serializer.dumps(email,
                             salt=app.config['SECRET_KEY'])  # dumps method serializes the email address into a token
    expiration = datetime.utcnow() + timedelta(minutes=5)  # Token expires in 5 minutes
    save_token = 'INSERT INTO token_validation (email, token, expiration) VALUES (%s, %s, %s)'
    mycursor.execute(save_token, (email, token, expiration))
    mydb.commit()

    return token


# the salt parameter adds a layer of security
# Using the secret key as the salt ensures that the token cannot be tampered with or replicated without the secret key.

def confirm_token(token):
    # a URLSafeTimedSerializer object is created using the same secret key.
    # This ensures that the token can be verified against the same key and salt used to create it.
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    retrieve_token = 'SELECT email, expiration,used FROM token_validation WHERE token = %s'
    mycursor.execute(retrieve_token, (token,))
    row = mycursor.fetchone()

    if not row or row[1] < datetime.utcnow():
        return False
    if row[2] == 1:
        return False

    email = row[0]
    try:
        email_from_token = serializer.loads(token, salt=app.config['SECRET_KEY'])
    except (SignatureExpired, BadSignature):
        return False

    if email != email_from_token:
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
    val = (next_id, event, datetime.now(), user_id)
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


def userSession(username):
    query = "SELECT * FROM users WHERE username = %s"
    mycursor.execute(query, (username,))
    user = mycursor.fetchone()
    return user


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


def generate_unlock_token():
    token = secrets.token_urlsafe(32)  # Generate a URL-safe token with 32 bytes of randomness
    return token


def scan_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": virusTotal_api
    }
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            result = response.json()
            file_id = result['data']['id']
            print(response.text)
            return file_id
        else:
            print(f"Error uploading file: {response.text}")
            return None


def get_scan_report(file_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virusTotal_api
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print(response.text)
        return response.json()
    else:
        print(f"Error retrieving scan report: {response.text}")
        return None
