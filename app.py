import json
import secrets
import os
import sys
from urllib.parse import urlencode
from functools import wraps

import requests

from flask import Flask, session, redirect, url_for, request, render_template, jsonify

# Get the directory of the main script
script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

# Change working directory
os.chdir(script_dir)


# Load configuration from appsettings.json
with open('appsettings.json') as f:
    config = json.load(f)

app = Flask(__name__)
app.secret_key = 'replace_with_secure_key'

# Global storage for access and refresh tokens
TOKENS = {
    'access_token': None,
    'refresh_token': None
}

def clear_tokens():
    """Remove stored tokens."""
    TOKENS['access_token'] = None
    TOKENS['refresh_token'] = None

def login_required(func):
    """Redirect to Auth0 login if no user session."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('auth_login'))
        return func(*args, **kwargs)
    return wrapper

openid_config_cache = None

def get_openid_configuration():
    """Retrieve and cache the discovery document."""
    global openid_config_cache
    if openid_config_cache is None:
        try:
            resp = requests.get(
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
    access_token = TOKENS.get('access_token')

    if not access_token:
        return None, []
    headers = {'Authorization': f'Bearer {access_token}'}
    user = None
    activities = []
    userinfo_endpoint = get_userinfo_endpoint()
    if userinfo_endpoint:
        try:
            resp = requests.get(userinfo_endpoint, headers=headers)
            if resp.status_code == 401:
                return 'refresh', []
            resp.raise_for_status()
            user = resp.json()
        except requests.RequestException:
            user = None
    try:
        aresp = requests.get(
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


@app.route('/auth/login')
def auth_login():
    """Redirect user to Auth0 authorization endpoint."""
    params = {
        'response_type': 'code',
        'client_id': config['Auth0ClientId'],
        'redirect_uri': config['Auth0CallbackUri'],
        'scope': 'openid profile email'
    }
    url = f"https://{config['Auth0Domain']}/authorize?{urlencode(params)}"
    return redirect(url)


@app.route('/auth/callback')
def auth_callback():
    """Handle Auth0 callback and store user info in session."""
    code = request.args.get('code')
    if not code:
        return redirect(url_for('auth_login'))
    token_url = f"https://{config['Auth0Domain']}/oauth/token"
    data = {
        'grant_type': 'authorization_code',
        'client_id': config['Auth0ClientId'],
        'client_secret': config['Auth0ClientSecret'],
        'code': code,
        'redirect_uri': config['Auth0CallbackUri'],
    }
    try:
        resp = requests.post(token_url, json=data, timeout=5)
        resp.raise_for_status()
        access_token = resp.json().get('access_token')
    except requests.RequestException:
        return redirect(url_for('auth_login'))
    userinfo_url = f"https://{config['Auth0Domain']}/userinfo"
    try:
        uresp = requests.get(userinfo_url, headers={'Authorization': f'Bearer {access_token}'})
        uresp.raise_for_status()
        session['user'] = uresp.json()
    except requests.RequestException:
        session['user'] = {}
    return redirect(url_for('index'))


@app.route('/')
@login_required
def index():
    login_url = build_login_url()
    return render_template('index.html', login_url=login_url)


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
        resp = requests.post(token_url, data=data, timeout=5)
        resp.raise_for_status()
        token_data = resp.json()
    except requests.RequestException:
        # If Creatio is unreachable, show an error but keep the app running
        return render_template('index.html', error='Failed to connect to Creatio')

    TOKENS['access_token'] = token_data.get('access_token')
    TOKENS['refresh_token'] = token_data.get('refresh_token')

    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():

    if not TOKENS.get('access_token'):

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
    if not TOKENS.get('access_token'):
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
    return jsonify({'authenticated': True, 'user': user, 'activities': activities, 'counts': counts})

@app.route('/refresh')
@login_required
def refresh():
    refresh_token = TOKENS.get('refresh_token')

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
        resp = requests.post(token_url, data=data, timeout=5)
        if resp.status_code == 200:
            token_data = resp.json()
            TOKENS['access_token'] = token_data.get('access_token')
            TOKENS['refresh_token'] = token_data.get('refresh_token', refresh_token)
            return redirect(url_for('index'))
    except requests.RequestException:
        pass
    clear_tokens()
    return redirect(url_for('index'))

@app.route('/revoke')
@login_required
def revoke():

    refresh_token = TOKENS.get('refresh_token')
    if not refresh_token:
        clear_tokens()

        return redirect(url_for('index'))
    _, _, revocation_url = get_auth_endpoints()
    data = {
        'token': refresh_token,
        'token_type_hint': 'refresh_token',
        'client_id': config['ClientId'],
        'client_secret': config['ClientSecret']
    }
    try:
        requests.post(revocation_url, data=data)
    except requests.RequestException:
        pass

    clear_tokens()

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    clear_tokens()
    session.pop('user', None)
    session.pop('oauth_state', None)
    return redirect(url_for('auth_login'))

if __name__ == '__main__':
    app.run(debug=True)
