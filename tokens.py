import jwt

from base58 import b58decode_check as b58decode
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta
from decimal import Decimal
from flask import abort
from http import HTTPStatus
from os import urandom

import config


JWT_ALGORITHM = 'HS256'


class InvalidChallengeTypeException(Exception): pass
class MissingChallengeContextData(Exception): pass


def _encode(payload, ttl):
    payload['iat'] = datetime.utcnow()
    payload['exp'] = datetime.utcnow() + timedelta(seconds=ttl)
    return jwt.encode(payload, config.JWT_SECRET, algorithm=JWT_ALGORITHM)


class TokenType(object):
    _types = {}

    def __init__(self, backend_auth_token):
        self._types[self.ID] = self
        self.auth_token = backend_auth_token

    def generate_login_token(self, account, ttl=3600):
        self.verify_account_id(account)
        return _encode({
            'backend': self.ID,
            'account': account
        }, ttl)

    def login_handler(self, request_data):
        abort(HTTPStatus.NOT_IMPLEMENTED)

    def verify_account_id(self, account_id):
        pass

    @classmethod
    def by_id(cls, id):
        return cls._types[id]


class SecretHashTokenType(TokenType):
    ID = 'secrethash'

    def __init__(self):
        super(SecretHashTokenType, self).__init__(config.PASSPHRASE_LOGIN_WALLET_TOKEN)

    def verify_account_id(self, account_id):
        try:
            if len(unhexlify(account_id)) != 32:
                abort(HTTPStatus.BAD_REQUEST)
        except TypeError:
            abort(HTTPStatus.BAD_REQUEST)

    def login_handler(self, hexhash):
        return self.generate_login_token(hexhash)


class ExistingAddressTokenType(TokenType):
    ID = 'address'
    CHALLENGE_TYPES = {
        'txauth': {
            'ttl':          600,
            'context':      [ 'coin', 'address' ],
            'generator':    lambda: (int(hexlify(urandom(4)), 16) % 99000000 + 1000000) / Decimal(100000000)
        },
        'signatureauth': {
            'ttl':          180,
            'context':      [ 'coin', 'address' ],
            'generator':    lambda: hexlify(urandom(32))
        }
    }

    def __init__(self):
        super(ExistingAddressTokenType, self).__init__(config.ADDRESS_LOGIN_WALLET_TOKEN)

    @classmethod
    @property
    def challenge_types(cls):
        return cls.CHALLENGE_TYPES.keys()

    def verify_account_id(self, account_id):
        try:
            length = len(b58decode(account_id))
        except:
            abort(HTTPStatus.BAD_REQUEST)

        if length != 21:
            abort(HTTPStatus.BAD_REQUEST)

    @classmethod
    def generate_challenge_token(cls, challenge_type, context={}):
        if challenge_type not in cls.challenge_types:
            raise InvalidChallengeTypeException(challenge_type)
        challenge_type = cls.CHALLENGE_TYPES[challenge_type]

        for required in challenge_type['context']:
            if required not in context.keys():
                raise MissingChallengeContextData(required)

        payload = { k: v for k, v in filter(lambda pair: pair[0] in challenge_type['context'], context.items()) }
        payload['challenge'] = challenge_type['generator']()

        return payload['challenge'], _encode(payload, ttl=challenge_type['ttl'])


def verify_login_token(token):
    try:
        decoded = jwt.decode(token, config.JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
        return None, None
    return decoded['backend'], decoded['account']


TOKEN_TYPES = [
    SecretHashTokenType(),
    ExistingAddressTokenType()
]
