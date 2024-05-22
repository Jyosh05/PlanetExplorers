from flask import Flask, render_template,request, jsonify
from flaskext.mysql import MySQL

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_super_secret_key'

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
    app.run()