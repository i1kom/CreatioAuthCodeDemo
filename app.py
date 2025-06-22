import json
import secrets
import os
import sys
from urllib.parse import urlencode
from functools import wraps
import base64
import hashlib
import hmac
import time
import sqlite3

import requests
import logging

from flask import Flask, redirect, url_for, request, render_template, jsonify, g, session

# Get the directory of the main script
script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

# Change working directory
os.chdir(script_dir)


# Load configuration from appsettings.json
with open('appsettings.json') as f:
    config = json.load(f)

app = Flask(__name__)
app.secret_key = 'replace_with_secure_key'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'users.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            creatio_access_token TEXT,
            creatio_refresh_token TEXT
        )"""
    )
    conn.commit()
    cur = conn.execute('SELECT COUNT(*) FROM users')
    if cur.fetchone()[0] == 0:
        pw_hash = hashlib.sha256('password'.encode()).hexdigest()
        conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            ('admin', pw_hash),
        )
        conn.commit()
    conn.close()


init_db()


def creatio_request(method: str, url: str, **kwargs):
    """Make an HTTP request to Creatio and log the URL and response body."""
    logger.info("Request URL: %s", url)
    try:
        response = requests.request(method, url, **kwargs)
        logger.info("Response body: %s", response.text)
        return response
    except requests.RequestException as exc:
        logger.info("Request to %s failed: %s", url, exc)
        raise


def creatio_get(url: str, **kwargs):
    return creatio_request("GET", url, **kwargs)


def creatio_post(url: str, **kwargs):
    return creatio_request("POST", url, **kwargs)


def clear_tokens(user_id):
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET creatio_access_token=NULL, creatio_refresh_token=NULL WHERE id=?',
        (user_id,),
    )
    conn.commit()
    conn.close()

def encode_segment(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def decode_segment(segment: str) -> bytes:
    padding = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def create_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = encode_segment(json.dumps(header).encode())
    payload_b64 = encode_segment(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(app.secret_key.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = encode_segment(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jwt(token: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        raise ValueError('Bad token')
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(app.secret_key.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, decode_segment(sig_b64)):
        raise ValueError('Bad signature')
    payload = json.loads(decode_segment(payload_b64))
    if payload.get('exp', 0) < int(time.time()):
        raise ValueError('Expired')
    return payload


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            return redirect(url_for('login'))
        try:
            payload = verify_jwt(token)
        except Exception:
            return redirect(url_for('login'))
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id=?', (payload.get('sub'),)).fetchone()
        conn.close()
        if user is None:
            return redirect(url_for('login'))
        g.user = user
        return func(*args, **kwargs)

    return wrapper

openid_config_cache = None

def get_openid_configuration():
    """Retrieve and cache the discovery document."""
    global openid_config_cache
    if openid_config_cache is None:
        try:
            resp = creatio_get(
                f"{config['CreatioBaseUrl']}/.well-known/openid-configuration",
                timeout=5,
            )
            resp.raise_for_status()
            openid_config_cache = resp.json()
        except requests.RequestException:
            # Cache an empty dict so the app keeps running even if Creatio is down
            openid_config_cache = {}
    return openid_config_cache

def get_auth_endpoints():
    """Return authorize, token and revocation endpoints."""
    base = config['CreatioBaseUrl']
    if config.get('UseDiscoveryEndpoint', False):
        data = get_openid_configuration() or {}
        auth = data.get('authorization_endpoint')
        token = data.get('token_endpoint')
        revoke = data.get('revocation_endpoint')
        if auth and token:
            return auth, token, revoke
    return (
        f"{base}/0/connect/authorize",
        f"{base}/0/connect/token",
        f"{base}/0/connect/revocation",
    )

def get_userinfo_endpoint():
    if config.get('UseDiscoveryEndpoint', False):
        data = get_openid_configuration() or {}
        endpoint = data.get('userinfo_endpoint')
        if endpoint:
            return endpoint
    return f"{config['CreatioBaseUrl']}/0/connect/userinfo"


def fetch_user_and_activities():
    """Retrieve user info and recent activities using current access token."""
    access_token = g.user['creatio_access_token']

    if not access_token:
        return None, []
    headers = {'Authorization': f'Bearer {access_token}'}
    user = None
    activities = []
    userinfo_endpoint = get_userinfo_endpoint()
    if userinfo_endpoint:
        try:
            resp = creatio_get(userinfo_endpoint, headers=headers)
            if resp.status_code == 401:
                return 'refresh', []
            resp.raise_for_status()
            user = resp.json()
        except requests.RequestException:
            user = None
    try:
        aresp = creatio_get(
            f"{config['CreatioBaseUrl']}/0/odata/Activity?$top=50",

            headers=headers
        )
        if aresp.status_code == 401:
            return 'refresh', []
        aresp.raise_for_status()
        activities = aresp.json().get('value', [])
    except requests.RequestException:
        activities = []
    return user, activities

def build_login_url():
    """Construct the Creatio authorization URL and store state."""
    authorize_url, _, _ = get_auth_endpoints()
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    params = {
        'client_id': config['ClientId'],
        'redirect_uri': config['RedirectUri'],
        'response_type': 'code',
        'scope': config['Scope'],
        'state': state
    }
    return f"{authorize_url}?{urlencode(params)}"


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        conn.close()
        if user and user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            token = create_jwt({'sub': user['id'], 'exp': int(time.time()) + 3600})
            resp = redirect(url_for('index'))
            resp.set_cookie('auth_token', token, httponly=True)
            return resp
        error = 'Invalid credentials'
    return render_template('login.html', error=error)


@app.route('/')
@login_required
def index():
    login_url = build_login_url()
    return render_template(
        'index.html',
        login_url=login_url,
        user_id=g.user['id'],
        username=g.user['username']
    )


@app.route('/creatio/login')
@login_required
def creatio_login():
    return redirect(build_login_url())

@app.route('/creatio/callback')
@login_required
def creatio_callback():
    error = request.args.get('error')
    if error:
        return render_template('index.html', error=error)
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or state != session.get('oauth_state'):
        return redirect(url_for('index'))

    session.pop('oauth_state', None)

    _, token_url, _ = get_auth_endpoints()
    data = {
        'client_id': config['ClientId'],
        'client_secret': config['ClientSecret'],
        'code': code,
        'redirect_uri': config['RedirectUri'],
        'grant_type': 'authorization_code',
        'scope': config['Scope']
    }
    try:
        resp = creatio_post(token_url, data=data, timeout=5)
        resp.raise_for_status()
        token_data = resp.json()
    except requests.RequestException:
        # If Creatio is unreachable, show an error but keep the app running
        return render_template('index.html', error='Failed to connect to Creatio')

    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET creatio_access_token=?, creatio_refresh_token=? WHERE id=?',
        (
            token_data.get('access_token'),
            token_data.get('refresh_token'),
            g.user['id'],
        ),
    )
    conn.commit()
    conn.close()

    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not g.user['creatio_access_token']:
        return redirect(url_for('index'))
    result = fetch_user_and_activities()
    if result == 'refresh':
        return redirect(url_for('refresh'))
    user, activities = result
    if user is None:
        user = {}

    return render_template('dashboard.html', user=user, activities=activities)


@app.route('/api/activities')
@login_required
def api_activities():
    """Return user info, activities and monthly counts as JSON."""
    if not g.user['creatio_access_token']:
        return jsonify({'authenticated': False}), 401
    result = fetch_user_and_activities()
    if result == 'refresh':
        return jsonify({'authenticated': False}), 401
    user, activities = result
    counts = {}
    for act in activities:
        date_str = act.get('StartDate') or act.get('CreatedOn')
        if not date_str:
            continue
        month = date_str[:7]
        counts[month] = counts.get(month, 0) + 1
    return jsonify({
        'authenticated': True,
        'user': user,
        'activities': activities,
        'counts': counts,
        'localUser': {
            'id': g.user['id'],
            'username': g.user['username']
        }
    })

@app.route('/refresh')
@login_required
def refresh():
    refresh_token = g.user['creatio_refresh_token']

    if not refresh_token:
        return redirect(url_for('index'))
    _, token_url, _ = get_auth_endpoints()
    data = {
        'client_id': config['ClientId'],
        'client_secret': config['ClientSecret'],
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'scope': config['Scope']
    }
    try:
        resp = creatio_post(token_url, data=data, timeout=5)
        if resp.status_code == 200:
            token_data = resp.json()
            conn = get_db_connection()
            conn.execute(
                'UPDATE users SET creatio_access_token=?, creatio_refresh_token=? WHERE id=?',
                (
                    token_data.get('access_token'),
                    token_data.get('refresh_token', refresh_token),
                    g.user['id'],
                ),
            )
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
    except requests.RequestException:
        pass
    clear_tokens(g.user['id'])
    return redirect(url_for('index'))

@app.route('/revoke')
@login_required
def revoke():

    refresh_token = g.user['creatio_refresh_token']
    if not refresh_token:
        clear_tokens(g.user['id'])

        return redirect(url_for('index'))
    _, _, revocation_url = get_auth_endpoints()
    data = {
        'token': refresh_token,
        'token_type_hint': 'refresh_token',
        'client_id': config['ClientId'],
        'client_secret': config['ClientSecret']
    }
    try:
        creatio_post(revocation_url, data=data)
    except requests.RequestException:
        pass

    clear_tokens(g.user['id'])

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    token = request.cookies.get('auth_token')
    if token:
        try:
            payload = verify_jwt(token)
            clear_tokens(payload.get('sub'))
        except Exception:
            pass
    resp = redirect(url_for('login'))
    resp.delete_cookie('auth_token')
    session.pop('oauth_state', None)
    return resp


@app.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    """Create a new local user."""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = 'Username and password required'
        else:
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            conn = get_db_connection()
            try:
                conn.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, pw_hash),
                )
                conn.commit()
                conn.close()
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                error = 'User already exists'
            finally:
                conn.close()
    return render_template('create_user.html', error=error)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
