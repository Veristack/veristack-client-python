"""Hooks, audit record webhook server."""

from __future__ import absolute_import

import os
import base64
import hmac
import json
import hashlib
import random
import logging

from pprint import pprint
from urllib.parse import urlparse, urlunparse

import asyncio
import aiohttp
from aiohttp import web
from aiohttp.formdata import FormData

from docopt import docopt
from schema import Schema, Use, And, Or, SchemaError


LOGGER = logging.getLogger(__name__)

VERIFY_SSL = os.environ.get('VERIFY_SSL_CERTIFICATES', '') \
             not in ('no', 'off', '0')

# TODO: randomize this data ala genny.
ACCOUNT = {
    'service': 'box',
}
EVENTS = {
    'objects': [{
        'id': '827',
        'account': 6721,
        'action': '-',
        'modified': '2017-03-15T19:40:46Z',
        'type': 'add',
        'user_id': 'uc21hcnRmaWxlQHNtYXJ0ZmlsZWRldi5vbm1pY3Jvc29mdC5jb20=',
        'ip': '209.43.28.60',
        'metadata': {
            'account': 6721,
            'ancestors': None,
            'name': 'testing-text.txt',
            'parent': {
                'name': 'Shared Documents',
                'id': 'FogwGVqe2m8jc4iXp532tjjP5bGPGNiqrfvy89eEEpWJedHQr3j0O890L1_KD_jyQUfqntke76fQyNmaN5KHsuGAChju2u98soaE0Fv75PHY='
            },
            'created': None,
            'modified': None,
            'raw_id': 'NewSite:GetFileByServerRelativeUrl(\'/NewSite/Shared Documents/testing-text.txt\')',
            'downloadable': True,
            'path': '/NewSite/Shared Documents/testing-text.txt',
            'type': 'file',
            'id': 'FmVG6AR6NlG4nGWWpB8OUP8-Uj1t4yTmOLQFSXulhh69F191TrXkywlIyJlNFXRR2mX_yKjW_EFxigVCE0A4efdvLhLtF7AcU7Nq2BIge4hPdsINZ2QxrIgMi9U_QV26d',
            'mime_type': 'text/plain',
            'size': None,
        },
    },],
}
USER = {
    'email': 'foo@bar.org',
    'name': 'Foobar',
}
FILE = {
    'size': 100,
}


def kloud_sign(data, key):
    h = hmac.new(key, data, hashlib.sha256).digest()
    h = base64.b64encode(h)
    return h.decode('ascii')


async def send_webhook(session, account_id, opts):
    data = b'account=%i' % account_id
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Kloudless-Signature': kloud_sign(data, opts['--api-key'])
    }

    urlp = urlparse(opts['--host'])
    url = urlunparse((
        urlp.scheme,
        urlp.netloc,
        '/api/1/webhooks/kloudless',
        None,
        None,
        None
    ))

    async with session.post(
        url, headers=headers, data=data, verify_ssl=VERIFY_SSL) as r:
        assert r.status == 200, '%i != 200' % r.status
        text = await r.text()
        assert text == 'ok', '%s != ok' % text


async def send_webhooks(opts):
    async with aiohttp.ClientSession() as session:
        for i in range(opts['--count']):
            account_id = random.randint(1, 1000000)

            await send_webhook(session, account_id, opts)
            LOGGER.debug('Sent webhook')

            asyncio.sleep(opts['--sleep'])


async def handle_account(request):
    LOGGER.debug('GET: %s', request.path)
    return web.Response(
        content_type='application/json', text=json.dumps(ACCOUNT))


async def handle_events(request):
    LOGGER.debug('GET: %s', request.path)
    return web.Response(
        content_type='application/json', text=json.dumps(EVENTS))


async def handle_user(request):
    LOGGER.debug('GET: %s', request.path)
    return web.Response(
        content_type='application/json', text=json.dumps(USER))


async def handle_file(request):
    LOGGER.debug('GET: %s', request.path)
    return web.Response(
        content_type='application/json', text=json.dumps(FILE))


def main(argv):
    """Genny.

    Generates audit data for Veristack. The data is injected into the receiver.
    Receiver adds data to the Hot model, and from there it is ingested into
    Audit model and friends.

    Genny attempts to create coherent random timelines of file activity.
    Events are produced in a manner that yields good timeline data for testing
    the veristack application.

    Usage:
        veristack hooks [--api-key=KEY] [-p PORT] [-H HOST] [-c COUNT]
                        [-s SLEEP] [-S COUNT]

    Options:
        -H --host HOST      Host to connect to [default: localhost]
        -p --port PORT      TCP port to connect to on HOST [default: 443]
        -c --count COUNT    Number of messages to generate/send [default: 0]
        -s --sleep SLEEP    Seconds to sleep between messages [default: 0]
        -S --word-count COUNT   The average size of the hypothetical file being
                                fingerprinted [default: 100000]
    """
    opts = docopt(main.__doc__, argv=argv)

    try:
        opts = Schema({
            '--api-key': And(Use(lambda s: bytes(s, 'ascii')),
                             error='--api-key is required'),
            '--host': str,
            '--port': Use(int),
            '--count': Use(int),
            '--sleep': Use(float),
            '--word-count': Use(int),

            object: object,
        }).validate(opts)

    except SchemaError as e:
        exit(e.args[0])

    LOGGER.addHandler(logging.StreamHandler())
    LOGGER.setLevel(logging.DEBUG)

    # First set up web server to handle requests.
    app = web.Application()

    app.router.add_route(
        'GET', '/v1//accounts/{account_id}', handle_account)
    app.router.add_route(
        'GET', '/v1//accounts/{account_id}/events', handle_events)
    app.router.add_route(
        'GET', '/v1//accounts/{account_id}/team/users/{user_id}', handle_user)
    app.router.add_route(
        'GET', '/v1//accounts/{account_id}/storage/files/{file_id}',
        handle_file)

    loop = asyncio.get_event_loop()

    coro = loop.create_server(app.make_handler(), '0.0.0.0', 8443)
    loop.run_until_complete(coro)

    # Then send hooks to trigger requests.
    loop.run_until_complete(send_webhooks(opts))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    loop.close()
