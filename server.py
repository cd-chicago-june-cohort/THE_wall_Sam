from flask import Flask, session, request, redirect, render_template, flash
from mysqlconnection import MySQLConnector
import re 
app = Flask(__name__)
mysql = MySQLConnector(app, 'the_wall')
app.secret_key = 'HVZ5T68AASG783HT'
import md5

@app.route('/')
def login():
    if 'current_user_id' not in session:
        session['current_user_id'] = 0
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def log():
    #check whether email is in database or not
    email = request.form['email']
    password = md5.new(request.form['password']).hexdigest()
    login_data = {'email': email, 'password': password}
    check_query = "SELECT * FROM users WHERE email = :email"
    check = mysql.query_db(check_query, login_data)
    if len(check) == 1:
        #check that password matches that in database
        pw_query = "SELECT password FROM users WHERE email = :email"
        pw = mysql.query_db(pw_query, login_data)
        if password == pw[0]['password']:
            find_id_query = "SELECT id FROM users WHERE email = :email"
            user_id = mysql.query_db(find_id_query, login_data)
            session['current_user_id'] = user_id[0]['id']
            return redirect('/wall')
        else:
            flash('Incorrect password. Please try again')
    else:
        flash('Email not in system. Please register before logging in.')
    return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    firstname = request.form['first_name']
    lastname = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    secure_pw = md5.new(request.form['password']).hexdigest()
    confirmed_pw = request.form['confirm']
    reg_data = {'firstname': firstname, 'lastname': lastname, 'email': email, 'password': secure_pw}
    check_query = "SELECT * FROM users WHERE email = :email"
    check = mysql.query_db(check_query, reg_data)
    if len(check) == 0:
        if password != confirmed_pw:
            flash('Passwords do not match. Please try again')
        elif len(password) < 8:
            flash('Password must be at least 8 characters')
        elif not re.match("^[a-zA-Z0-9_]*$", password):
            flash('Password can only have letters and numbers. Please try again.')
        else:
            query = 'INSERT INTO users(first_name, last_name, email, password, created_at, updated_at) VALUES (:firstname, :lastname, :email, :password, NOW(), NOW())'
            mysql.query_db(query, reg_data)
            flash('Registration successful!')
    else:
        flash('Email is already registered. Use a different email or log in.')
    return redirect('/')

@app.route('/wall')
def make_wall():
    query = 'SELECT first_name, last_name, messages.created_at, message, messages.id FROM users JOIN messages ON users.id=messages.users_id ORDER BY messages.id DESC'
    messages = mysql.query_db(query)
    print '\n'
    print '\n'
    print messages
    print '\n'
    print '\n'
    comment_query = 'SELECT * FROM comments, users WHERE users_id = users.id'
    comments = mysql.query_db(comment_query)
    print comments
    print '\n'
    print '\n'
    return render_template('wall.html', message_board = messages, comment_list = comments)


@app.route('/logout')
def logout():
    session['current_user_id'] = 0
    flash('Logout successful')
    return redirect('/')


#POST STUFF STARTS HERE
@app.route('/message', methods=['POST'])
def post_message():
    message = request.form['msg']
    user = session['current_user_id']
    msg_data = {'message': message, 'user_id': user}
    if len(message) < 0:
        return redirect('/wall')
    query = 'INSERT INTO messages(message, created_at, updated_at, users_id) VALUES (:message, NOW(), NOW(), :user_id)'
    mysql.query_db(query, msg_data)
    return redirect('/wall')

#COMMENT TIME :)
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    message_id = request.form['message_id']
    user = session['current_user_id']
    print '-' * 50
    print request.form['message_id']
    print '-' * 50
    
    com_data = {'comment': comment, 'user_id': user, 'message_id': message_id}
    if len(comment) < 0:
        return redirect('/wall')
    query = 'INSERT INTO comments(comment, created_at, updated_at, users_id, messages_id) VALUES (:comment, NOW(), NOW(), :user_id, :message_id)'
    mysql.query_db(query, com_data)
    return redirect('/wall')

app.run(debug=True)