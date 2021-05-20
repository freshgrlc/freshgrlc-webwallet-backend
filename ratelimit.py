import functools

from datetime import datetime, timedelta
from flask import request, abort
from http import HTTPStatus



class Type(object):
    def __init__(self, value):
        self.value = value

Type.DISABLED = None
Type.ALL_REQUESTS = Type(1)
Type.ON_ERRORS = Type(2)


class Context(object):
    contexts = {}

    def __init__(self, name, max_hits=10, window=3600):
        self.name = name
        self.max_hits = max_hits
        self.window = window
        self.contexts[name] = self
        print(f'Created rate limit context "{name}", max allowed {max_hits} / {window/60} minutes', flush=True)

    @classmethod
    def get(cls, name):
        if name is None:
            return cls._default
        if isinstance(name, cls):
            return name
        try:
            return cls.contexts[name]
        except KeyError:
            return cls(name)

Context._default = Context(None)


class Limit(object):
    def __init__(self, type, context=None):
        self.type = type
        self.context = Context.get(context)


class ClientState(object):
    blocklist = {}

    def __init__(self, client, context):
        self.client = client
        self.context = context
        self.start = datetime.now()
        self.hits = 0
        self.register()

    def hit(self):
        if self.elapsed:
            self.state = datetime.now()
            self.hits = 1
        else:
            self.hits += 1

    @property
    def blocked(self):
        return self.hits >= self.context.max_hits and not self.elapsed

    @property
    def elapsed(self):
        return self.start + timedelta(seconds=self.context.window) <= datetime.now()

    def register(self):
        if self.client not in self.blocklist:
            self.blocklist[self.client] = [self]
        else:
            self.blocklist[self.client].append(self)

    @classmethod
    def get_all_for(cls, client):
        return cls.blocklist[client] if client in cls.blocklist else []

    @classmethod
    def get_filtered(cls, client, contexts):
        return [ cls.get(client, c) for c in contexts ]

    @classmethod
    def get(cls, client, context):
        if isinstance(context, Limit):
            context = context.context
        elif isinstance(context, Type):
            context = Limit(context).context
        elif type(context) == str:
            context = Context.get(context)

        try:
            return next(filter(lambda s: s.context == context, cls.get_all_for(client)))
        except StopIteration:
            return cls(client, context)


def _client():
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def required(limit, response):
    if isinstance(limit, Type):
        limit = Limit(limit)

    if limit is None or not limit.type:
        return False
    if limit.type == Type.ALL_REQUESTS:
        return True
    return limit.type == Type.ON_ERRORS and response.status_code >= 300


def check(limit, response):
    if required(limit, response):
       ClientState.get(_client(), limit).hit()


def is_blocked(client, contexts=None):
    for state in filter(lambda s: s.blocked, ClientState.get_all_for(client) if contexts is None else ClientState.get_filtered(client, contexts)):
        current_window = int((datetime.now() - state.start).total_seconds())
        window_remaining = int((state.start + timedelta(seconds=state.context.window) - datetime.now()).total_seconds())
        print(f'Client {client} rate limited [context: "{state.context.name}"]: {state.hits} hits in {current_window} seconds, {window_remaining} seconds until release', flush=True)
        return True
    return False


def apply(contexts=None):
    if isinstance(contexts, Context) or type(contexts) == str:
        contexts = contexts,

    def decorator(api_func):
        @functools.wraps(api_func)
        def wrapper(*args, **kwargs):
            if is_blocked(_client(), contexts):
                abort(HTTPStatus.TOO_MANY_REQUESTS)
            return api_func(*args, **kwargs)
        return wrapper
    return decorator
