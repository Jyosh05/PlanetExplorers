from flask import Flask, render_template,request, jsonify
from flask_mysqldb import MySQL
import mysql.connector
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
#Configuration is a file containing sensitive information
from Configuration import DB_Config,secret_key
import logging

app = Flask(__name__)
#Changed the format in which information is not hard coded
app.config['SECRET_KEY'] = secret_key
# app.config['MYSQL_DB_HOST'] = DB_Config['host']
# app.config['MYSQL_DB_USER'] = DB_Config['user']
# app.config['MYSQL_DB_PASSWORD'] = DB_Config['password']
# app.config['MYSQL_DB'] = DB_Config['database']
# app.config['MYSQL_PORT'] = DB_Config['port']

mydb = mysql.connector.connect(
    host=DB_Config['host'],
    user=DB_Config['user'],
    password=DB_Config['password'],
    port=DB_Config['port'],
    database=DB_Config['database']
)

mycursor = mydb.cursor(buffered=True)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per hour"]
)

# mysql = MySQL(app)
#Aloysius Portion
def input_validation():
    pass
def get_info():
    pass


def update_info():
    pass

def add_info():
    pass

def delete_info():
    pass

#Function to create table if table does not exist
# def create_table():
#     try:
#         with app.app_context():
#             conn = mysql.connect()
#             cursor = conn.cursor()
#             query = """
#             CREATE TABLE IF NOT EXISTS users(
#                 id INT AUTO_INCREMENT PRIMARY KEY,
#                 username VARCHAR(255) NOT NULL,
#                 password VARCHAR(255) NOT NULL,
#                 email VARCHAR(255) NOT NULL,
#                 age INT NOT NULL
#                 address VARCHAR(255),
#                 role ENUM('student','teacher','admin') NOT NULL
#             )
#             """
#             cursor.execute(query)
#             conn.commit()
#             cursor.close()
#             conn.close()
#             print("Table created")
#
#     except Exception as e:
#         print(f"Error occurred: {str(e)}")

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

if __name__ == '__main__':
    #calling create table function
    app.run()


@app.route('/blogs')
def blog():
    app.logger.info('Info level log')
    app.logger.warning('Warning level log')
    return f"Welcome to the Blog"
 
app.run(host='localhost', debug=True)
