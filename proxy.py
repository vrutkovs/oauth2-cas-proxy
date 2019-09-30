from urllib import parse
import logging
from flask import Flask, request, redirect, render_template, Markup, abort
import requests
import environs
import sys

env = environs.Env()
env.read_env()

app = Flask(__name__)

app.config.update(
    # Base URL used for reidrect_uri
    BASE_URL=env.str("BASE_URL"),

    # OAuth2 Client ID
    OAUTH2_CLIENT=env.str('OAUTH2_CLIENT'),

    # OAuth2 Client Secret
    OAUTH2_SECRET=env.str('OAUTH2_SECRET'),

    # OAuth2 Scope
    OAUTH2_SCOPE=env.str('OAUTH2_SCOPE', 'profile:read'),

    # OAuth2 Authorization URL
    OAUTH2_AUTHORIZE=env.str('OAUTH2_AUTHORIZE',
                             'https://sso.hackerspace.pl/oauth/authorize'),

    # OAuth2 Token exchange URL
    OAUTH2_TOKEN=env.str('OAUTH2_TOKEN',
                         'https://sso.hackerspace.pl/oauth/token'),

    # OAuth2 user information API endpoint (JSON, username attribute will be
    # passed as <cas:user>)
    OAUTH2_USERINFO=env.str('OAUTH2_USERINFO',
                            'https://sso.hackerspace.pl/api/1/profile'),

    # Basic service URL verification (proxy will return 403 if provided service
    # argument does not start with this prefix)
    SERVICE_URL=env.str('SERVICE_URL', ''),
)

app.config['REDIRECT_URI'] = '%s/_cas/_callback' % (app.config['BASE_URL'],)


def build_xml(o, parent=''):
    """Build more-or-less CAS-compatible XML from CAS-compatible JSON"""
    t = type(o)
    subs = {
        'proxies': 'proxy',
    }
    if parent in subs:
        parent = subs[parent]

    if t is dict:
        return Markup(''.join(
            Markup('<cas:{0}>{1}</cas:{2}>').format(
                Markup(k), build_xml(v, k), k.partition(' ')[0])
            for k, v in o.items()
        ))
    elif t is list:
        return Markup(''.join(
            Markup('<cas:{0}>{1}</cas:{2}>').format(
                Markup(parent), build_xml(v, parent), parent.partition(' ')[0])
            for v in o
        ))
    else:
        return str(o)


def cas_response(obj):
    """Build CAS-compatible XML HTTP response"""
    return build_xml({
        "serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'": obj
    }), {'content-type': 'application/xml'}


@app.route('/_cas/login')
def login():
    """
    /login CAS endpoint

    request.args.get('service', ''), redirect to OAUTH2_AUTHORIZE
    """
    # scope=profile:read&client_id=registry&response_type=code&redirect_uri=

    service = request.args.get('service', '')

    args = parse.urlencode({
        'scope': app.config['OAUTH2_SCOPE'],
        'client_id': app.config['OAUTH2_CLIENT'],
        'response_type': 'code',
        'redirect_uri': app.config['REDIRECT_URI'],
        'state': service,
    })

    if app.config['SERVICE_URL'] and \
            not service.startswith(app.config['SERVICE_URL']):
        abort(403)

    return redirect('%s?%s' % (app.config['OAUTH2_AUTHORIZE'], args))


@app.route('/_cas/_callback')
def callback():
    """
    OAuth2 redirect callback
    """
    # call OAUTH2_TOKEN, redirect with ?ticket=[access_token]

    print(f'args: \n{request.args}', file=sys.stdout)

    resp = requests.post(app.config['OAUTH2_TOKEN'], params={
        'grant_type': 'authorization_code',
        'client_id': app.config['OAUTH2_CLIENT'],
        'client_secret': app.config['OAUTH2_SECRET'],
        'redirect_uri': app.config['REDIRECT_URI'],
        'code': request.args.get('code', '')
    })
    resp.raise_for_status()
    print(f'response: {resp.json()}', file=sys.stdout)

    # TODO: encrypt/sign access_token to make it unusable outside of cas proxy
    args = parse.urlencode({
        'ticket': resp.json().get('access_token'),
    })
    print(f'args: {args}', file=sys.stdout)

    service = request.args.get('state', '')

    # Callback may have double slashes
    service = service.replace("//", "/")

    return redirect('%s%s%s' % (service, '&' if '?' in service else '?', args))


@app.route('/_cas/serviceValidate')
@app.route('/_cas/proxyValidate')
def validate():
    """
    CAS Token validation endpoint
    """

    app.logger.info(request.args)
    try:
        headers = {"Authorization": f"Bearer {request.args['ticket']}"}
        app.logger.info(headers)
        resp = requests.post(app.config['OAUTH2_USERINFO'], headers=headers)
        resp.raise_for_status()

        attrs = resp.json()
        app.logger.info(attrs)

        return cas_response({
            "authenticationSuccess": {
                "user": attrs['username'],
                "proxyGrantingTicket": "FAKE-TKT-...",
                "attributes": attrs
            }
        })
    except:
        logging.exception('userinfo request failed')
        return cas_response({
            "authenticationFailure": {
                "code": "INVALID_TICKET",
                "description": "Ticket not recognized"
            }
        })
