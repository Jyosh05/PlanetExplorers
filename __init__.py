from flask import Flask, render_template,request, jsonify
import mysql.connector
#Configuration is a file containing sensitive information
from Configuration import DB_Config,secret_key
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key

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



def update_info():
    pass

def add_info():
    pass

def delete_info():
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


@app.route('/')
def home():
    return render_template("home.html") # need to create template

@app.route('/store')
def store():
    return render_template("store.html")

@app.route('/profile')
def profile():
    #need to add in authentication to ensure user is logged in before they can access profile page
    return render_template("profile.html")

#need to make a functional login page
@app.route('/login', methods=["GET","POST"])
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


if __name__ == '__main__':
    #calling create table function
    app.run()


# @app.route('/blogs')
# def blog():
#     app.logger.info('Info level log')
#     app.logger.warning('Warning level log')
#     return f"Welcome to the Blog"
#
# app.run(host='localhost', debug=True)
