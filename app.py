import json
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, session, redirect, url_for, request, render_template

# Load configuration from appsettings.json
with open('appsettings.json') as f:
    config = json.load(f)

app = Flask(__name__)
app.secret_key = 'replace_with_secure_key'

openid_config_cache = None

def get_openid_configuration():
    """Retrieve and cache the discovery document."""
    global openid_config_cache
    if openid_config_cache is None:
        resp = requests.get(f"{config['CreatioBaseUrl']}/.well-known/openid-configuration")
        resp.raise_for_status()
        openid_config_cache = resp.json()
    return openid_config_cache

def get_auth_endpoints():
    """Return authorize, token and revocation endpoints."""
    if config.get('UseDiscoveryEndpoint', False):
        data = get_openid_configuration()
        return (
            data['authorization_endpoint'],
            data['token_endpoint'],
            data.get('revocation_endpoint')
        )
    base = config['CreatioBaseUrl']
    return (
        f"{base}/0/connect/authorize",
        f"{base}/0/connect/token",
        f"{base}/0/connect/revocation"
    )

def get_userinfo_endpoint():
    if config.get('UseDiscoveryEndpoint', False):
        data = get_openid_configuration()
        return data.get('userinfo_endpoint')
    return f"{config['CreatioBaseUrl']}/0/connect/userinfo"

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
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
    return redirect(f"{authorize_url}?{urlencode(params)}")

@app.route('/callback')
def callback():
    error = request.args.get('error')
    if error:
        return render_template('index.html', error=error)
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or state != session.get('oauth_state'):
        return redirect(url_for('index'))
    _, token_url, _ = get_auth_endpoints()
    data = {
        'client_id': config['ClientId'],
        'client_secret': config['ClientSecret'],
        'code': code,
        'redirect_uri': config['RedirectUri'],
        'grant_type': 'authorization_code',
        'scope': config['Scope']
    }
    resp = requests.post(token_url, data=data)
    resp.raise_for_status()
    token_data = resp.json()
    session['access_token'] = token_data.get('access_token')
    session['refresh_token'] = token_data.get('refresh_token')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('index'))
    headers = {'Authorization': f'Bearer {access_token}'}
    activities = []
    user = {}
    # Fetch user info
    userinfo_endpoint = get_userinfo_endpoint()
    if userinfo_endpoint:
        try:
            uresp = requests.get(userinfo_endpoint, headers=headers)
            if uresp.status_code == 401:
                return redirect(url_for('refresh'))
            uresp.raise_for_status()
            user = uresp.json()
        except requests.RequestException:
            user = {}
    # Fetch activities
    try:
        aresp = requests.get(
            f"{config['CreatioBaseUrl']}/0/odata/ActivityCollection?$top=5",
            headers=headers
        )
        if aresp.status_code == 401:
            return redirect(url_for('refresh'))
        aresp.raise_for_status()
        activities = aresp.json().get('value', [])
    except requests.RequestException:
        activities = []
    return render_template('dashboard.html', user=user, activities=activities)

@app.route('/refresh')
def refresh():
    refresh_token = session.get('refresh_token')
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
    resp = requests.post(token_url, data=data)
    if resp.status_code == 200:
        token_data = resp.json()
        session['access_token'] = token_data.get('access_token')
        session['refresh_token'] = token_data.get('refresh_token', refresh_token)
        return redirect(url_for('dashboard'))
    session.clear()
    return redirect(url_for('index'))

@app.route('/revoke')
def revoke():
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        session.clear()
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
    session.clear()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
