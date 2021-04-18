import functools
import json
import requests

from binascii import unhexlify
from flask import Flask, Response, abort, request
from flask_cors import cross_origin
from http import HTTPStatus

from config import WALLET_API_ENDPOINT
from tokens import TokenType, ExistingAddressTokenType, verify_login_token



webapp = Flask('webwallet-api')


def _json(obj):
    return Response(json.dumps(obj), mimetype='application/json')


def authenticated(api_func):
    @functools.wraps(api_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            abort(HTTPStatus.UNAUTHORIZED)
        auth_header = auth_header.split(' ')
        if len(auth_header) != 2 or auth_header[0] != 'Bearer':
            abort(HTTPStatus.UNAUTHORIZED)

        auth_backend, account = verify_login_token(auth_header[1])
        if account == None:
            abort(HTTPStatus.UNAUTHORIZED)

        kwargs['account'] = (auth_backend, account)
        return api_func(*args, **kwargs)
    return wrapper


@webapp.route('/login/<type>/', methods=['POST'])
@cross_origin()
def login_using_secrethash(type):
    try:
        login_type = TokenType.by_id(type)
    except KeyError:
        abort(HTTPStatus.BAD_REQUEST)

    return login_type.login_handler(request.get_json())


@webapp.route('/challenge/', methods=['GET'])
@cross_origin()
def get_challenge():
    challenge_type = request.args.get('type')
    if challenge_type not in ExistingAddressTokenType.challenge_types:
        abort(HTTPStatus.BAD_REQUEST)
    challenge, challenge_token = generate_challenge_token(challenge_type, request.args)
    return _json({
        'challenge': challenge,
        'authtoken': challenge_token
    })


@webapp.route('/logininfo/', methods=['GET'])
@cross_origin()
@authenticated
def logininfo(account):
    return _json({ 'method': account[0], 'accountid': account[1] })


@webapp.route('/', methods=['POST'])
@cross_origin()
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
@cross_origin()
@authenticated
def get_wallet_info(account):
    auth_token = TokenType.by_id(account[0]).auth_token

    resp = requests.get(WALLET_API_ENDPOINT + account[1] + '/',
        headers={'Authorization': 'Bearer ' + auth_token},
        allow_redirects=False)

    return Response(resp.content, resp.status_code)


@webapp.route('/**', methods=['GET', 'POST'])
@cross_origin()
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
