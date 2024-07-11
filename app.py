from flask import Flask, redirect, url_for, render_template, request, session
from datetime import timedelta

import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from functools import wraps
import jsonify

app = Flask(__name__)
oauth = OAuth(app)
app.secret_key = "apples"
app.debug = True
AUTH_BASE_URL = "https://dev-ddfb33mkn557e8ho.us.auth0.com"

auth0 = oauth.register(
    'auth0',
    client_id = 'ieC6ZZXgffIaV3sdfqoc2qxKmbQG7h4n',
    client_secret = 'ExwEt2Zeg6K0Sar4AIVwHcqFkqX9MsETuOD3w7fWTWryHBlFQdjfgy6Su6osZB1K',
    api_base_url = AUTH_BASE_URL,
    access_token_url = AUTH_BASE_URL + "/oauth/token",
    authorize_url = AUTH_BASE_URL + "/authorize",
    client_kwargs = {
        'scope': 'openid profile email',
    },
    server_meta_url = "https://dev-ddfb33mkn557e8ho.us.auth0.com/.well-known/openid-configuration"
)
metadata = auth0.load_server_metadata()
if 'jwks_uri' not in metadata:
    metadata['jwks_uri'] = AUTH_BASE_URL + "/.well-known/jwks.json"
auth0.client_kwargs['jwks_uri'] = metadata['jwks_uri']


app.config["SESSION_TYPE"]="filesystem"

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.route("/home")
def home():
    print("hello")
    return render_template("home.html")

@app.route("/login")
def login():
    return auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True, _scheme="http"))

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = auth0.authorize_access_token()
    session['user'] = token
    resp = auth0.get("userinfo")
    print(resp)
    return redirect('/dashboard')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print(session)
        if 'profile' not in str(session):
            return redirect('/home')
        return f(*args, **kwargs)
    return decorated

@app.route("/dashboard")
@requires_auth
def dashboard():
    return render_template("dashboard.html", 
                            session = session.get('user'), 
                            pretty = json.dumps(session.get('user'), indent = 4))

@app.route("/settings")
@requires_auth
def settings():
    return render_template("settings.html", 
                                session = session.get('user'), 
                                pretty = json.dumps(session.get('user'), indent = 4))

if __name__ == "__main__": 
    app.run(host="0.0.0.0", debug=True)