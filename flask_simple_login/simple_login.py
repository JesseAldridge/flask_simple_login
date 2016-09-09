import os, json, re, uuid, hashlib, functools

import flask
from flask import request, session

class g:
    user_db = None
    login_manager = None

class LoginManager:

    # Validate credentials and save a new user.

    def new_user(self):
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
        if username in g.user_db['user_info']:
            return 'user already exists', 400
        if email in g.user_db['salts']:
            return 'email already exists', 400

        g.user_db['salts'][username] = salt = str(uuid.uuid4())
        g.user_db['hashes'][username] = hashlib.sha224(password + salt).hexdigest()
        g.user_db['user_info'][username] = {'email':email}

        self.on_login(username)

        session['username'] = username
        with open(g.user_db_path, 'w') as f:
            f.write(json.dumps(g.user_db, indent=2))

        return 'ok'

    # Verify username and password; log the user in.

    def login(self):
        if request.method == 'POST':
            username, password = (
                request.form['username'], request.form['password'])
            if username not in g.user_db['hashes']:
                return 'unknown user', 401
            salt = g.user_db['salts'][username]
            if(hashlib.sha224(password + salt).hexdigest() !=
               g.user_db['hashes'][username]):
                return 'Incorrect password.', 401
            session['username'] = username

            self.on_login(username)

            return 'ok'
        return flask.render_template('login.html')

    def on_login(self, username):
        pass

# A decorator to require login.  Optionally redirect to a login page.

def require_login(redirect=False):
    def decorator(fn):
        @functools.wraps(fn)
        def decorated_function(*a, **kw):
            username = session.get('username', None)
            if not username or username not in g.user_db['user_info']:
                if redirect:
                    return flask.redirect('/login')
                return 'not logged in', 401
            return fn(*a, **kw)
        return decorated_function
    return decorator

def logout():
    session.pop('username', None)
    return flask.redirect('/')


# Add login related routes.  Load user credentials from json file.

def init(app, user_db_path='user_db.json', login_manager=None):
    g.login_manager = login_manager or LoginManager()

    app.add_url_rule('/logout', None, logout)
    app.add_url_rule(
        '/login', None,  g.login_manager.login, methods=['GET', 'POST'])
    app.add_url_rule(
        '/new_user', None, g.login_manager.new_user, methods=['POST'])

    g.user_db = {'hashes':{}, 'salts':{}, 'user_info':{}}
    g.user_db_path = user_db_path
    if os.path.exists(user_db_path):
        with open(user_db_path) as f:
            g.user_db = json.loads(f.read())


if __name__ == '__main__':

    # Run the example app.

    app = flask.Flask(__name__)

    class CustomLogin(LoginManager):
        def on_login(self, username):
            print 'user logged in: ', username

    init(app, login_manager=CustomLogin())

    # Generate a secret key like so:  import os; os.urandom(17)
    app.secret_key = 'a unique secret string used to encrypt sessions'

    @app.route('/')
    def index():
        return flask.render_template('index.html')

    # An example route showing how to require login.

    @app.route('/get_secret_thing', methods=['GET'])
    @require_login(redirect=True)
    def get_secret_thing():
        return 'This is the secret thing!'

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=port==5000)
