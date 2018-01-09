"""Hooks, audit record webhook server."""

from __future__ import absolute_import

import os
import base64
import hmac
import hashlib
import random


from pprint import pprint
from urllib.parse import urlparse, urlunparse

import asyncio
import aiohttp
from aiohttp import web
from aiohttp.formdata import FormData

from docopt import docopt
from schema import Schema, Use, And, Or, SchemaError


VERIFY_SSL = os.environ.get('VERIFY_SSL_CERTIFICATES', '') \
             not in ('no', 'off', '0')


def kloud_sign(data, key):
    h = hmac.new(key, data, hashlib.sha256).digest()
    h = base64.b64encode(h)
    return h.decode('ascii')


async def send_webhook(session, number, opts):
    data = b'account=%i' % number
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


class HookServer(object):
    """Async IO server."""

    def __init__(self, opts):
        self.opts = opts
        self.hooks = set()

    async def generate(self):
        """Generate and send webhooks."""
        i = 0
        async with aiohttp.ClientSession() as session:
            while True:
                i += 1

                while True:
                    number = random.randint(1, 1000000)
                    if number not in self.hooks:
                        break
                self.hooks.add(number)
                await send_webhook(session, number, self.opts)

                if i == self.opts['--count']:
                    break

                asyncio.sleep(self.opts['--sleep'])

    async def handle_hooks(self, request):
        """Respond to webhook requests with audit data."""
        return web.Response(text='OK')


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

    server = HookServer(opts)

    loop = asyncio.get_event_loop()

    # First set up web server to handle requests.
    http = web.Server(server.handle_hooks)
    loop.create_server(http, '0.0.0.0', 8443)

    # Then send hooks to trigger requests.
    loop.run_until_complete(server.generate())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    loop.close()
