"""Veristack CLI program."""

from __future__ import absolute_import

import os
from os.path import join as pathjoin

import hashlib
import json
import struct
import random
import copy
import time
import zlib

from base64 import b64encode
from pprint import pprint

from docopt import docopt
from faker import Faker
from schema import Schema, Use, And, Or, SchemaError

from six import PY3

import msgpack

from veristack import (
    Client, DeviceDetails, PersonDetails, FileDetails, Event,
    DEV_CLOUD, DEVICE_TYPES, ACT_CREATE, ACT_WRITE, ACT_MOVE, ACT_COPY,
    ACT_READ, ACT_DELETE,
)
from veristack.cli import genny
from veristack.cli import hooks


if not PY3:
    def bytes(d, enc=None):  # noqa
        return d


MAXINT = 2147483647
FAKE = Faker()

PATH_PARTS = (
    'Documents',
    'Private',
    'Share',
    'New',
    'Downloads', )

USERS = [
    PersonDetails(**{
        'username': 'btimby',
        'email': 'btimby@smartfile.com',
        'fullname': 'Ben Timby',
    }), PersonDetails(**{
        'username': 'tcunningham',
        'email': 'tcunningham@smartfile.com',
        'fullname': 'Travis Cunningham',
    }), PersonDetails(**{
        'username': 'tbrazelton',
        'email': 'tbrazelton@smartfile.com',
        'fullname': 'Taylor Brazelton',
    }), PersonDetails(**{
        'username': 'dlund',
        'email': 'dlund@smartfile.com',
        'fullname': 'David Lund',
    }), PersonDetails(**{
        'username': 'dgalitsky',
        'email': 'dgalitsky@smartfile.com',
        'fullname': 'David Galitsky',
    }), PersonDetails(**{
        'username': 'cbarnes',
        'email': 'cbarnes@smartfile.com',
        'fullname': 'Clifton Barnes',
    }), PersonDetails(**{
        'username': 'jemery',
        'email': 'jemery@smartfile.com',
        'fullname': 'Jennifer Emery',
    }), PersonDetails(**{
        'username': 'tspelde',
        'email': 'tspelde@smartfile.com',
        'fullname': 'Tony Spelde',
    }),
]

DEVICES = [
    DeviceDetails(**{
        'device_type': DEV_CLOUD,
        'name': 'dropbox',
        'addr': '10.0.1.2',
        'os': 'Winders',
    }), DeviceDetails(**{
        'device_type': DEV_CLOUD,
        'name': 'gdrive',
        'addr': '10.0.1.2',
        'os': 'Winders',
    }), DeviceDetails(**{
        'device_type': random.choice(DEVICE_TYPES),
        'name': 'Diet Pepsi',
        'addr': '10.0.1.2',
        'os': 'Winders',
    }), DeviceDetails(**{
        'device_type': random.choice(DEVICE_TYPES),
        'name': 'Diet Dew',
        'addr': '10.0.1.3',
        'os': 'Mac OS X',
    }), DeviceDetails(**{
        'device_type': random.choice(DEVICE_TYPES),
        'name': 'Mtn Dew',
        'addr': '192.168.1.12',
        'os': 'Linux',
    }), DeviceDetails(**{
        'device_type': random.choice(DEVICE_TYPES),
        'name': 'DrPepper',
        'addr': '192.168.1.12',
        'os': 'Linux',
    }),
]


def make_path():
    """Generate a random path."""
    path = '/' + '/'.join(
        random.sample(PATH_PARTS, random.randint(0, len(PATH_PARTS))))
    return path


# Create 100 random paths to work with.
PATHS = [make_path() for _ in range(10)]


def make_fp(f, wordcount=0):
    """Generate fake fingerprint data."""
    wordcount = wordcount if wordcount is not None else 1000
    nums = [(
        random.randint(1, MAXINT), random.randint(1, 1024))
        for _ in range(0, wordcount)
    ]
    d = {
        'f': f.name, 'y': 'application/genny', 's': f.size, '5': f.md5, 'h': 0,
        'c': time.time(), 'm': time.time(), 'w': nums,
    }
    m = msgpack.packb(d, use_bin_type=True)
    m = b''.join([struct.pack('<B', 2), zlib.compress(m)])
    return b64encode(m).decode('ascii')


def make_file(opt=None):
    """Generate a file resource."""
    # Don't make paths completely random, we want some overlap.
    directory = random.choice(PATHS)
    name = FAKE.file_name()
    path = pathjoin(directory, name)
    # TODO: this was used with fingerprinting, but to remove the dependency
    # on duster, I excluded this. For fingerprint support, generate some
    # bodies/fingerprints and embed them as constants above.
    # body =
    # '\r\n\r\n'.join([FAKE.text() for i in range(random.randint(1, 10))])
    size = random.randint(0, 1024 ** 3)
    try:
        wordcount = opt['--word-count']
    except (AttributeError, KeyError):
        wordcount = None
    wordcount = wordcount if wordcount is not None else 10000
    wordcount = random.randint(wordcount / 2, wordcount)
    # The UID is derived from the path unless the platform provides a unique
    # identifier (google drive does, onedrive does, genny uses the path).
    uid = hashlib.md5(bytes(path, 'ascii')).hexdigest()
    f = FileDetails(uid=uid, name=name, directory=directory, size=size,
                    md5=FAKE.md5(raw_output=False))
    f.fingerprint = [make_fp(f, wordcount)]
    return f


def make_event(action_type, device, file, timestamp, opt=None):
    """Create an audit event."""
    if action_type == ACT_WRITE:
        # Simulate writing data to the file. Create a new randomized file and
        # copy _some_ of it's attributes.
        mutation = make_file(opt=opt)
        file.size = mutation.size
        file.md5 = mutation.md5
        file.fingerprint = mutation.fingerprint

    fake_event = Event(
        action_type=action_type,
        device=device,
        timestamp=timestamp,
        person=random.choice(USERS),
        files=[file],
        extra={
            "extra_dict": {
                "ip": FAKE.ipv4(network=False),
                "company_email": FAKE.company_email()
            },
            "extra_key": FAKE.free_email_domain(),
        }
    )

    if action_type in (ACT_MOVE, ACT_COPY):
        # For some actions we need a similar file with a different path.
        file2 = copy.deepcopy(file)
        fake_event.files.append(file2)
        src_dir = file2.directory
        while True:
            dst_dir = random.choice(PATHS)
            if src_dir != dst_dir:
                break
        # Destination is a different directory, which means the UID will be
        # different.
        dst_path = pathjoin(dst_dir, fake_event.files[0].name)
        file2.directory = dst_dir
        file2.uid = hashlib.md5(bytes(dst_path, 'ascii')).hexdigest()

    # Append extra data into person
    fake_event.person.extra = {'mac_address': FAKE.mac_address()}
    return fake_event


def make_timeline(device=None, file=None, timestamp=None, opt=None):
    """Create a timeline of audit activity."""
    if not device:
        device = random.choice(DEVICES)
    if not file:
        # Create a random file.
        file = make_file(opt=opt)
    if not timestamp:
        # Pick a start time, we will increment this as we move forward.
        timestamp = random.randint(int(time.time()) - 31536000,
                                   int(time.time()))
    # And a create action.
    yield make_event(ACT_CREATE, device, file, timestamp, opt=opt)
    # Create a series of events:
    for _ in range(random.randint(5, 8)):
        # Increment time by 10s-4d
        timestamp += random.randint(10, 345600)
        # Only a subset of actions make sense here.
        action = random.choice((ACT_READ, ACT_WRITE, ACT_COPY))
        event = make_event(action, device, file, timestamp, opt=opt)
        yield event
        if action == ACT_COPY:
            yield make_event(
                ACT_CREATE, device, event.files[1], timestamp, opt=opt)
    # Increment time by 10s-4d
    timestamp += random.randint(10, 345600)
    # Half the time, end with a terminal action
    terminal_action = random.choice((ACT_MOVE, ACT_DELETE, None, None))
    if terminal_action:
        event = make_event(terminal_action, device, file, timestamp, opt=opt)
        yield event
        if terminal_action == ACT_MOVE:
            yield make_event(
                ACT_CREATE, device, event.files[1], timestamp, opt=opt)


def main(opts, argv):
    """Veristack.

    Veristack CLI program.

    Usage:
        veristack <command> [<args>...]

    Commands:
        genny  Generates audit data for receiver.
        hooks  Generates audit data for webhooks.
    """
    if opts['<command>'] == 'genny':
        genny.main(argv)

    elif opts['<command>'] == 'hooks':
        hooks.main(argv)

    else:
        exit("%r is not a veristack command. See 'veristack help'." %
             opts['<command>'])


if __name__ == '__main__':
    opts = docopt(main.__doc__, options_first=True)

    argv = [opts['<command>']] + opts['<args>']

    main(opts, argv)
