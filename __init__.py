from flask import Flask, render_template,request, jsonify
import mysql.connector
#Configuration is a file containing sensitive information
from Configuration import DB_Config,secret_key, admin_config
import re
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#!!!!!IF THERE IS ANY DB ERROR, CHECK THE CONFIG FILE AND IF THE PASSWORD IS CONFIG PROPERLY!!!!!

#!!!!CHECK THE INPUT FUNCTION BEFORE USING, THERE IS CURRENTLY 1 FUNCTION THAT ADDS IN NEW USERS AS STUDENTS ONLY!!!!
#ALL FUNCTIONS: input_validation(input_string), age_validation(age), update_info(input_string),add_info(username, password, email, age, address),
#delete_info(),get_info()


app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key

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



#Aloysius Portion
def input_validation(input_string):
    #INJECTION, JAVASCRIPT AND PYTHON MALICIOUS CODE USING REGEX
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
    if not isinstance(age, int) or age<=0:
        raise ValueError("Invalid input: Age must be a positive integer")
    return True



def update_info(input_string):
    pass


#READ THIS FIRST!!!!!
#add_info with role default as "student", if need to change role, cannot use this function
def add_info(username, password, email, age, address):
    try:
        #checking the inputs from the add_info function
        input_validation(username)
        input_validation(password)
        input_validation(email)
        age_validation(age)
        input_validation(address)
        #checking if the user is in the db or not
        mycursor.execute(
            "SELECT * FROM users WHERE username = %s OR email = %s",(username,email)
        )
        existing_user = mycursor.fetchone()
        if existing_user:
            print("error: Username or Email already exists")
        #standardized role of "student for new user"
        role = 'student'
        #parameterized query
        query = """
            INSERT INTO users (username, password, email, age, address, role)
            VALUES (%s,%s,%s,%s,%s)
        """
        #tuple to make sure the input cannot be changed
        values = (username, password, email, age, address, role)
        #executing the parameterized query and the tuple as the inputs
        mycursor.execute(query, values)
        mydb.commit()
        print("User added successfully")
    #exception if the sql connector has an error
    except mysql.connector.Error as err:
        print(f"error: {str(err)}")
    #input validation error, means there is malicious code
    except ValueError as e:
        print(f"error:{str(e)}")



def delete_info():
    pass

def get_info():
    pass





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
                        age INT NOT NULL,
                        address VARCHAR(255),
                        role ENUM('student','teacher','admin') NOT NULL
                    )
                    """)
        print(f"Table 'users' Created")




mycursor.execute('SELECT * FROM users')
print(f"Using table 'users' ")

users = mycursor.fetchall()

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

            insert_admin_query = "INSERT INTO users (username, password, email, age, address, role) VALUES (%s, %s, %s, %s, %s, %s)"
            admin_user = (admin_config['username'], hashed_password, admin_config['email'], admin_config['age'], admin_config['address'], admin_config['role'])

            mycursor.execute(insert_admin_query, admin_user)
            mydb.commit()
            print("Admin user created successfully")
    except mysql.connector.Error as err:
        print(f"Error while inserting admin user: {err}")



@app.route('/')
@limiter.limit("5 per minute")
def home():
    return render_template("home.html") # need to create template

@app.route('/store')
@limiter.limit("5 per minute")
def store():
    return render_template("store.html")

@app.route('/profile')
@limiter.limit("5 per minute")
def profile():
    #need to add in authentication to ensure user is logged in before they can access profile page
    return render_template("profile.html")

#need to make a functional login page
@app.route('/login', methods=["GET","POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        try:
            user_input = request.form.get("password")
            input_validation(user_input)
            print("Input is valid")
        except ValueError as e:
            #NEED TO ADD IN LOGGING FUNCTION IF THERE IS AN ERROR
            print(e)
    return render_template("login.html")

@app.route('/forget_password')
def forget_password():
    return render_template("forget_password.html")

@app.route('/register')
def register():
    return render_template("register.html")


if __name__ == '__main__':
    #calling create table function
    # Call the function when the application starts
    create_admin_user()
    app.run()


# @app.route('/blogs')
# def blog():
#     app.logger.info('Info level log')
#     app.logger.warning('Warning level log')
#     return f"Welcome to the Blog"
#
# app.run(host='localhost', debug=True)
