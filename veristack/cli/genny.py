"""Genny, audit record generator."""

from __future__ import absolute_import

import os
import json
import time
import random

from pprint import pprint

from docopt import docopt
from schema import Schema, Use, And, Or, SchemaError

from veristack import Client
from veristack.__main__ import make_timeline


def handle_rand(clients, opt):
    """Send a bunch of messages."""
    count = 0
    try:
        while True:
            for event in make_timeline(opt=opt):
                pprint(event.to_dict())
                random.choice(clients).send(event)
                count += 1
            if opt['--count'] and count >= opt['--count'] - 1:
                break
            time.sleep(opt['--sleep'])

    except KeyboardInterrupt:
        pass

    return count


def main(argv):
    """Genny.

    Generates audit data for Veristack. The data is injected into the receiver.
    Receiver adds data to the Hot model, and from there it is ingested into
    Audit model and friends.

    Genny attempts to create coherent random timelines of file activity.
    Events are produced in a manner that yields good timeline data for testing
    the veristack application.

    Usage:
        veristack genny [--client-id=ID] [-p PORT] [-H HOST] [-c COUNT]
                        [--client-secret=SECRET|--token=TOKEN] [-S COUNT]
                        [-s SLEEP -o CONNECTIONS -S SIZE] [--token-file=FILE]

    Options:
        -i --client-id=ID      OAuth2 CLIENT_ID
        -e --client-secret=SECRET  OAuth2 CLIENT_SECRET
        -t --token=TOKEN    OAuth2 Token
        -f --token-file=FILE  The file in which to read/write the token.
        -H --host HOST      Host to connect to [default: localhost]
        -p --port PORT      TCP port to connect to on HOST [default: 41666]
        -c --count COUNT    Number of messages to generate/send [default: 0]
        -s --sleep SLEEP    Seconds to sleep between messages [default: 0]
        -o --connections=CONNECTIONS    Number of clients to send messages
                                        [default: 1]
        -S --word-count COUNT   The average size of the hypothetical file being
                                fingerprinted [default: 100000]
    """
    opts = docopt(main.__doc__, argv=argv)

    try:
        opts = Schema({
            '--client-id': And(str, error='--client-id is required'),
            '--token-file': Or(None,
                               Use(str, error='--token-file should be path')),
            '--host': str,
            '--port': Use(int),
            '--count': Use(int),
            '--sleep': Use(float),
            '--connections': Use(int),
            '--word-count': Use(int),

            object: object,
        }).validate(opts)

    except SchemaError as e:
        exit(e.args[0])

    kwargs = {
        'client_id': opts['--client-id'],
        'url': opts['--host'],
        'uid': 'genny',
    }
    if opts['--client-secret']:
        kwargs['client_secret'] = opts['--client-secret']

    if opts['--token-file']:
        try:
            with open(opts['--token-file'], 'r') as f:
                kwargs['token'] = json.loads(f.read())
        except IOError:
            pass

    if opts['--token']:
        kwargs['token'] = opts['--token']

    if 'client_secret' not in kwargs and 'token' not in kwargs:
        exit('Client secret or token required.')

    if os.environ.get('VERIFY_SSL_CERTIFICATES',
                      None) in ('no', 'false', 'off'):
        kwargs['verify'] = False

    client = Client(**kwargs)

    if 'token' not in kwargs:
        client.fetch_token()

    if opts['--token-file']:
        with open(opts['--token-file'], 'w') as f:
            f.write(json.dumps(client.token))

    # Create (potentially) a lot of connections.
    clients = [
        client.get_event_writer() for _ in range(opts['--connections'])
    ]

    print("Clients Connected: %s" % len(clients))

    start = time.time()
    count = handle_rand(clients, opts)
    print('Sent %s messages in %.3fs' % (count, time.time() - start))

    # Close all of those connections.
    for client in clients:
        client.close()
