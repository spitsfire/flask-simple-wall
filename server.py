from flask import Flask, render_template, redirect, session, request, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = 'boopboop'
mysql = connectToMySQL('login-reg')
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    mysql = connectToMySQL('login-reg')
    query = "SELECT * FROM users WHERE Email = %(Email)s;"
    data = {'Email': request.form['email']}
    checkEmail = mysql.query_db(query,data)

    errors = 0
    if len(request.form['first_name']) < 2:
        flash("First name must be at least 2 characters long.")
        errors += 1
    if len(request.form['last_name']) < 2:
        flash("Last name must be at least 2 characters long.")
        errors += 1
    if len(request.form['email']) < 1:
        flash("Email address cannot be blank.")
        errors += 1
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email address.")
        errors += 1
    if checkEmail:
        flash("Email address already registered.")
        errors += 1
    if len(request.form['password']) < 1:
        flash("Password cannot be blank.")
        errors += 1
    if request.form['password'] != request.form['confirm_password']:
        flash("Passwords do not match.")
        errors += 1

    if errors:
        return render_template('index.html')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL("login-reg")
        query = "INSERT INTO users (FirstName, LastName, Email, Password, CreatedAt, UpdatedAt) VALUES (%(FirstName)s, %(LastName)s, %(Email)s, %(Password)s, NOW(), NOW());"
        data = {
             'FirstName': request.form['first_name'],
             'LastName':  request.form['last_name'],
             'Email': request.form['email'],
             'Password': pw_hash}
        new_user = mysql.query_db(query, data)
        mysql = connectToMySQL("login-reg")
        userid = mysql.query_db("SELECT Id FROM users WHERE Email = %(Email)s;", data)
        session['userid'] = userid
        return redirect('/wall')

@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL("login-reg")
    query = "SELECT * FROM users WHERE Email = %(Email)s;"
    data = { 'Email' : request.form["login_email"] }
    result = mysql.query_db(query, data)
    if result:
        if bcrypt.check_password_hash(result[0]['Password'], request.form['login_password']):
            session['userid'] = result[0]['Id']
            print(session['userid'])
            return redirect('/wall')

    flash("Email and/or password is incorrect.")
    return render_template('index.html')

@app.route('/wall')
def wall():
    if 'userid' not in session:
        return redirect('/')
    else:
        mysql = connectToMySQL('login-reg')
        data = { 'Id': session['userid'] }
        query = "SELECT Content, messages.CreatedAt, messages.Id, FirstName FROM messages JOIN users ON users.Id = AuthorId WHERE RecipientId = %(Id)s;"
        users_messages = mysql.query_db(query, data)

        mysql = connectToMySQL('login-reg')
        all_users = mysql.query_db("SELECT * FROM users")

        mysql = connectToMySQL('login-reg')
        recip_count = mysql.query_db("SELECT COUNT(*) AS msg_count FROM messages WHERE RecipientId = %(Id)s;", data)

        mysql = connectToMySQL('login-reg')
        auth_count = mysql.query_db("SELECT COUNT(*) AS msg_count FROM messages WHERE AuthorId = %(Id)s;", data)

        return render_template('wall.html', messages=users_messages, users=all_users, recip_count=recip_count[0]['msg_count'], auth_count=auth_count[0]['msg_count'])

@app.route('/create', methods=['POST'])
def create():
    if len(request.form['message_content']) < 1:
        flash("Message cannot be blank.")
        return redirect('/wall')
    else:
        mysql = connectToMySQL('login-reg')
        query = "INSERT INTO messages (Content, CreatedAt, UpdatedAt, AuthorId, RecipientId) VALUES (%(Content)s, NOW(), NOW(), %(AuthorId)s, %(RecipientId)s);"
        data = {
            'Content': request.form['message_content'],
            'AuthorId': session['userid'],
            'RecipientId': request.form['recipient_id']
        }

        new_message = mysql.query_db(query, data)
        return redirect('/wall')

@app.route('/remove/message/<id>')
def delete(id):
    mysql = connectToMySQL('login-reg')
    data = { 'Id': id }
    check = mysql.query_db("SELECT RecipientId FROM messages WHERE Id = %(Id)s;", data)

    if session['userid'] == check[0]['RecipientId']:
        mysql = connectToMySQL('login-reg')
        deleted_message = mysql.query_db("DELETE FROM messages WHERE Id = %(Id)s;", data)
        return redirect('/wall')
    else:
        session['messageid'] = id
        return redirect('/danger')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/danger')
def danger():
    return render_template('danger.html')

if __name__=="__main__":
    app.run(debug=True)