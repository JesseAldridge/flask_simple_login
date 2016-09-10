
`pip install flask_simple_login`

```
import flask
from flask import session
import flask_simple_login

app = flask.Flask(__name__)
flask_simple_login.init_login(app)

# Generate a secret key like so:  import os; os.urandom(17)
app.secret_key = 'a unique secret string used to encrypt sessions'

@app.route('/')
@flask_simple_login.require_login(redirect=True)
def index():
    return 'You are logged in as: {}'.format(session.get('username', None))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
```

This is a simple authentication framework for [Flask](http://flask.pocoo.org/).  
It simply read and writes usernames, hashed passwords, and salts to a json file.  
The goal is to handle user signups and logins in a safe and simple way.  
If you want more than that, you should probably use something like [flask-login](https://github.com/maxcountryman/flask-login).
