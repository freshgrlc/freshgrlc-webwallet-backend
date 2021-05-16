import functools
import json
import requests

from binascii import unhexlify
from flask import Flask, Response, abort, request
from flask_cors import CORS
from http import HTTPStatus

from config import WALLET_API_ENDPOINT
from tokens import TokenType, ExistingAddressTokenType, get_token_from_http_header, verify_login_token



webapp = Flask('webwallet-api')
CORS(webapp)


def _json(obj):
    return Response(json.dumps(obj), mimetype='application/json')


def authenticated(api_func):
    @functools.wraps(api_func)
    def wrapper(*args, **kwargs):
        auth_backend, account = verify_login_token(get_token_from_http_header())
        if account == None:
            abort(HTTPStatus.UNAUTHORIZED)

        kwargs['account'] = (auth_backend, account)
        return api_func(*args, **kwargs)
    return wrapper


@webapp.route('/login/<type>/', methods=['POST'])
def login_using_secrethash(type):
    try:
        login_type = TokenType.by_id(type)
    except KeyError:
        abort(HTTPStatus.BAD_REQUEST)

    return login_type.login_handler(request.get_json())


@webapp.route('/challenge/', methods=['GET'])
def get_challenge():
    challenge_type = request.args.get('type')
    if challenge_type not in ExistingAddressTokenType.challenge_types():
        abort(HTTPStatus.BAD_REQUEST)
    challenge, challenge_token = ExistingAddressTokenType.generate_challenge_token(challenge_type, request.args)
    return _json({
        'challenge': challenge,
        'authtoken': challenge_token
    })


@webapp.route('/logininfo/', methods=['GET'])
@authenticated
def logininfo(account):
    return _json({ 'method': account[0], 'accountid': account[1] })


@webapp.route('/', methods=['POST'])
@authenticated
def create_wallet(account):
    request_data = request.get_json() if request.get_json() is not None else {}
    request_data['user'] = account[1]

    auth_token = TokenType.by_id(account[0]).auth_token

    resp = requests.post(WALLET_API_ENDPOINT,
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + auth_token},
        json=request_data,
        allow_redirects=False)

    return Response(resp.content, resp.status_code)


@webapp.route('/', methods=['GET'])
@authenticated
def get_wallet_info(account):
    auth_token = TokenType.by_id(account[0]).auth_token

    resp = requests.get(WALLET_API_ENDPOINT + account[1] + '/',
        headers={'Authorization': 'Bearer ' + auth_token},
        allow_redirects=False)

    return Response(resp.content, resp.status_code)


@webapp.route('/**', methods=['GET', 'POST'])
@authenticated
def proxy_wallet_api(account):
    auth_token = TokenType.by_id(account[0]).auth_token

    # Prevent /account/../../foo/bar shenanigans
    if '.' in request.url.path:
        abort(HTTPStatus.BAD_REQUEST)

    target = WALLET_API_ENDPOINT + account[1] + request.url.full_path
    resp = requests.request(
        method=request.method,
        url=target,
        headers={'Content-Type': request.headers['Content-Type'], 'Authorization': 'Bearer ' + auth_token},
        data=request.get_data(),
        allow_redirects=False)

    return Response(resp.content, resp.status_code)
