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


def _json(obj, code=200):
    return Response(json.dumps(obj), code, mimetype='application/json')


def exception_handler(error, code):
    try:
        error = error.original_exception
    except AttributeError: pass
    return _json({
        'code': code,
        'error': {
            'type': error.__class__.__name__,
            'message': str(error)
        }
    }, code)

@webapp.errorhandler(HTTPStatus.BAD_REQUEST)
def bad_request_handler(e):
    return exception_handler(e, HTTPStatus.BAD_REQUEST)

@webapp.errorhandler(HTTPStatus.UNAUTHORIZED)
def unauthorized_handler(e):
    return exception_handler(e, HTTPStatus.UNAUTHORIZED)

@webapp.errorhandler(HTTPStatus.INTERNAL_SERVER_ERROR)
def internal_server_error_handler(e):
    return exception_handler(e, HTTPStatus.INTERNAL_SERVER_ERROR)

@webapp.errorhandler(HTTPStatus.NOT_FOUND)
def not_found_handler(_):
    return _json(None, HTTPStatus.NOT_FOUND)



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


@webapp.route('/', methods=['GET'], defaults={'_': None})
@webapp.route('/<path:_>', methods=['GET', 'POST', 'PUT'])
@authenticated
def proxy_wallet_api(account, _):
    auth_token = TokenType.by_id(account[0]).auth_token

    # Prevent /account/../../foo/bar shenanigans
    print(request.path)
    if '.' in request.path:
        abort(HTTPStatus.BAD_REQUEST)

    target = WALLET_API_ENDPOINT + account[1] + request.full_path
    headers = {'Authorization': 'Bearer ' + auth_token}
    if 'Content-Type' in request.headers:
        headers['Content-Type'] = request.headers['Content-Type']

    resp = requests.request(
        method=request.method,
        url=target,
        headers=headers,
        data=request.get_data(),
        allow_redirects=False)

    return Response(resp.content, resp.status_code)
