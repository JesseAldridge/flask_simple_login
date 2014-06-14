import os
import json
import re
import uuid
import hashlib

import flask
from flask import request, session

app = flask.Flask(__name__)

@app.route('/')
def index():
    return flask.render_template('index.html')

# Require login decorator.  Optionally redirect to login page.

def require_login(redirect=False):
    def require_login_(fn):
        def wrapped():
            username = session.get('username', None)
            if not username or username not in user_db['user_info']:
                if redirect:
                    return flask.redirect('/login')
                return 'not logged in', 401
            return fn()
        return wrapped
    return require_login_


# An example route showing how to require login.

@app.route('/get_secret_thing', methods=['GET'])
@require_login(redirect=True)
def get_secret_thing():
    return 'This is the secret thing!'


def load_db(user_db_path='user_db.json'):

    # Load user credentials from a json file.

    global user_db
    user_db = {'hashes':{}, 'salts':{}, 'user_info':{}}
    if os.path.exists(user_db_path):
        with open(user_db_path) as f:
            user_db = json.loads(f.read())


@app.route('/new_user', methods=['POST'])
def new_user():

    # Validate credentials and save a new user.

    username, email, password = (
        request.form['username'], request.form['email'],
        request.form['password'])
    email = email.lower()

    if len(email) > 254 or not re.match('\w+@\w+\.\w+', email):
        return 'bad email', 400
    if len(username) > 30:
        return 'username too long', 400
    if not re.match('[a-zA-Z0-9_\-]+', username):
        return 'illegal character in username', 400
    if len(password) > 100:
        return 'password too long', 400
    if username in user_db['user_info']:
        return 'user already exists', 400
    if email in user_db['salts']:
        return 'email already exists', 400
        
    user_db['salts'][username] = salt = str(uuid.uuid4())
    user_db['hashes'][username] = hashlib.sha224(password + salt).hexdigest()
    user_db['user_info'][username] = {'email':email}

    with open(user_db_path, 'w') as f:
        f.write(json.dumps(user_db, indent=2))

    session['username'] = username
    return 'ok'

@app.route('/login', methods=['GET', 'POST'])
def login():

    # Verify username and password; log the user in.

    if request.method == 'POST':
        username, password = (
            request.form['username'], request.form['password'])
        if username not in user_db['hashes']:
            return 'unknown user', 401
        salt = user_db['salts'][username]
        if(hashlib.sha224(password + salt).hexdigest() != 
           user_db['hashes'][username]):
            return 'Incorrect password.', 401
        session['username'] = username
        return 'ok'
    return flask.render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return flask.redirect('/')



# Generate a secret key like so:  import os; os.urandom(17)
app.secret_key = 'a unique secret string used to encrypt sessions'

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=port==5000)
