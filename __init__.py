from flask import Flask, render_template,request, jsonify
from flask_mysqldb import MySQL
#Configuration is a file containing sensitive information
from Configuration import DB_Config,secret_key

app = Flask(__name__)
#Changed the format in which information is not hard coded
app.config['SECRET_KEY'] = secret_key
app.config['MYSQL_DB_HOST'] = DB_Config['host']
app.config['MYSQL_DB_USER'] = DB_Config['user']
app.config['MYSQL_DB_PASSWORD'] = DB_Config['password']
app.config['MYSQL_DB'] = DB_Config['database']

mysql = MySQL(app)
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
def create_table():
    try:
        conn = mysql.connect()
        cursor = conn.cursor()
        query = """
        CREATE TABLE IF NOT EXISTS users(
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            age INT NOT NULL
            address VARCHAR(255),
            role ENUM('student','teacher','admin') NOT NULL
        )
        """
        cursor.execute(query)
        conn.commit()
        cursor.close()
        conn.close()
        print("Table created")

    except Exception as e:
        print(f"Error occurred: {str(e)}")






@app.route('/')
def home():
    return render_template("home.html") # need to create template


if __name__ == '__main__':
    #calling create table function
    create_table()
    app.run()