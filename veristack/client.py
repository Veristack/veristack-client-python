"""Veristack integration client."""

from __future__ import absolute_import

import hashlib
import json
import platform
import socket
import ssl
import time

import os
from os.path import join as pathjoin
from os.path import dirname, basename, getsize

import getpass
import jwt
import requests

from six.moves.urllib.parse import urljoin  # noqa
from six.moves.urllib.parse import urlparse  # noqa
from six.moves.urllib.parse import urlencode  # noqa

from oauthlib.oauth2 import TokenExpiredError
from oauthlib.oauth2.rfc6749.clients.base import Client as _Client
from oauthlib.oauth2.rfc6749.parameters import prepare_token_request

from requests_oauthlib import OAuth2Session as _OAuth2Session


GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
GEO_URL = 'https://geo.getfilehub.com/'
OS = platform.system()
HOSTNAME = socket.gethostname()
USERNAME = getpass.getuser()

ACT_CREATE = 1
ACT_READ = 2
ACT_WRITE = 3
ACT_DELETE = 4
ACT_MOVE = 5
ACT_COPY = 6

ACTION_TYPES = (
    ACT_CREATE,
    ACT_READ,
    ACT_WRITE,
    ACT_DELETE,
    ACT_MOVE,
    ACT_COPY, )

DEV_CLOUD = 1
DEV_DESKTOP = 2

DEVICE_TYPES = (
    DEV_CLOUD,
    DEV_DESKTOP, )


def hash_path(path):
    """Perform an MD5 sum of the given path."""
    md5 = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            block = f.read()
            if not block:
                break
            md5.update(block)
    return md5.hexdigest()


class AuthenticationError(IOError):
    """Authentication failed exception."""

    pass


class JWTApplicationClient(_Client):
    """Handle OAuth2 JWT Grant.

    Passes a signed JWT to the provider in order to obtain OAuth2 tokens.
    """

    def prepare_request_uri(self, *args, **kwargs):
        """Create request URIs."""
        pass

    def prepare_request_body(self, body='', scope=None, **kwargs):
        """Prepare request body.

        Overridden.

        This passes our JWT token grant type parameter.
        """
        return prepare_token_request(GRANT_TYPE, body=body, scope=scope,
                                     client_id=self.client_id, **kwargs)


class FileDetails(object):
    """File details.

    Provides validation and serialization.
    """

    def __init__(self, path=None, uid=None, directory=None, name=None,
                 size=None, md5=None, fingerprint=None, extra=None):
        """Instantiate FileDetails."""
        self.path = path
        self.uid = uid
        self.directory = directory
        self.name = name
        self.size = size
        self.md5 = md5
        self.fingerprint = fingerprint
        self.extra = extra or {}

    @staticmethod
    def from_path(path):
        """Instantiate a FileDetails class given a file system path."""
        kwargs = {
            'uid': hashlib.md5(path.encode('ascii')).hexdigest(),
            'size': getsize(path),
            'md5': hash_path(path),
        }
        event = FileDetails(**kwargs)
        event.path = path
        return event

    @property
    def path(self):
        """Full path of the file."""
        return pathjoin(self.directory, self.name)

    @path.setter
    def path(self, value):
        if value is None:
            return
        self.directory = dirname(value)
        self.name = basename(value)

    def to_dict(self):
        """Convert to dictionary."""
        assert self.uid, 'uid must be set'
        assert self.size >= 0, 'size must be set'
        assert self.directory, 'directory must be set'
        assert self.name, 'name must be set'
        d = {
            'uid': self.uid,
            'directory': self.directory,
            'name': self.name,
            'size': self.size,
        }
        # Deleted or moved files don't necessarily have an md5 anymore.
        if self.md5:
            d['md5'] = self.md5
        if self.fingerprint:
            d['fingerprint'] = self.fingerprint
        if self.extra:
            d.update(self.extra)
        return d

    def to_json(self):
        """Convert to json."""
        d = self.to_dict()
        return json.dumps(d)


class PersonDetails(object):
    """Person details.

    Provides validation and serialization. Detects username.
    """

    def __init__(self, username=None, fullname=None, email=None, extra=None):
        """Instantiate PersonDetails."""
        self.username = username or USERNAME
        self.fullname = fullname
        self.email = email
        self.extra = extra or {}

    def to_dict(self):
        """Convert to dictionary."""
        assert self.username, 'username must be set'
        assert self.fullname, 'fullname must be set'
        assert self.email, 'email must be set'
        d = {
            'username': self.username,
            'fullname': self.fullname,
            'email': self.email,
        }
        if self.extra:
            d.update(self.extra)
        return d

    def to_json(self):
        """Convert to json."""
        d = self.to_dict()
        return json.dumps(d)


class DeviceDetails(object):
    """Device details.

    Provides valiation and serialization. Detects the hostname and os details.
    """

    def __init__(self, device_type=None, name=None, addr=None, os=None,  # noqa
                 extra=None):
        """Instantiate DeviceDetails."""
        self.device_type = device_type
        self.name = name or HOSTNAME
        self.addr = addr
        self.os = os or OS
        self.extra = extra or {}

    def to_dict(self):
        """Convert to dictionary."""
        assert self.device_type in DEVICE_TYPES, 'invalid device_type'
        assert self.name, 'name must be set'
        assert self.addr, 'addr must be set'
        assert self.os, 'os must be set'
        d = {
            'type': self.device_type,
            'name': self.name,
            'addr': self.addr,
            'os': self.os
        }
        if self.extra:
            d.update(self.extra)
        return d

    def to_json(self):
        """Convert to json."""
        d = self.to_dict()
        return json.dumps(d)


class LocationDetails(object):
    """Geographic location details.

    Can call the FileHub geo service to obtain lat/long. Provides validation
    and serialization.
    """

    def __init__(self, latitude=None, longitude=None):
        """Instantiate LocationDetails."""
        self.latitude = latitude
        self.longitude = longitude

    @staticmethod
    def from_geo(ip=None):
        """Call the FileHub geolocator service."""
        url = GEO_URL
        if ip:
            url += '?' + urlencode({'ip': ip})

        try:
            geo = requests.get(url).json()
        except:
            raise IOError('Unable to obtain location from geolocator service')

        return LocationDetails(latitude=geo.get('latitude'),
                               longitude=geo.get('longitude'))

    def to_dict(self):
        """Convert to dictionary."""
        assert self.latitude, 'latitude must be set'
        assert self.longitude, 'longitude must be set'
        return {
            'latitude': self.latitude,
            'longitude': self.longitude,
        }

    def to_json(self):
        """Convert to json."""
        d = self.to_dict()
        return json.dumps(d)


class Event(object):
    """Represent an individual audit event.

    Provides validation and serialization of event message.
    """

    def __init__(self, action_type=None, device=None, timestamp=None,
                 person=None, location=None, files=None, extra=None):
        """Instantiate Event."""
        self.action_type = action_type
        self.device = device
        self.timestamp = timestamp or time.time()
        self.person = person
        self.location = location
        self.files = list(files) if files else []
        self.extra = extra or {}

    def to_dict(self):
        """Convert to dictionary."""
        assert len(self.files) in (1, 2), 'must provide one or two files'
        assert all(map(lambda f: callable(getattr(f, 'to_dict', None)),
                       self.files)), 'all files must have `.to_dict()` method'
        assert self.action_type, 'action_type must be set'
        assert self.device, 'device must be set'
        assert callable(getattr(self.device, 'to_dict', None)), \
            'device must have `to_dict()` method'
        assert self.timestamp, 'timestamp must be set'
        assert self.person, 'person must be set'
        assert callable(getattr(self.person, 'to_dict', None)), \
            'person must have `to_dict()` method'
        assert (self.location is None or
                callable(getattr(self.location, 'to_dict', None))), \
            'location must be LocationDetails or None'
        d = {
            'timestamp': self.timestamp,
            'device': self.device.to_dict(),
            'person': self.person.to_dict(),
            'action_type': self.action_type,
        }
        if self.location:
            d.update(self.location.to_dict())
        d['file1'] = self.files[0].to_dict()
        if len(self.files) == 2:
            d['file2'] = self.files[1].to_dict()
        if self.extra:
            d.update(self.extra)
        return d

    def to_json(self):
        """Convert to json."""
        d = self.to_dict()
        return json.dumps(d)


class EventWriter(object):
    """Stream events to FileHub.

    Maintains a persistent connection for sending events. Can be used as a
    context manager to ensure the connection is closed. Checks server response
    and raises `IOError` for any protocol errors.
    """

    def __init__(self, client, url=None, verify=None, token=None):
        """Instantiate EventWriter."""
        self.url = url if url is not None else client.url
        self.verify = verify if verify is not None else client.verify
        self.token = token if token is not None else client.token
        self._sock = None

    def __enter__(self):
        """Handle enter."""
        return self

    def __exit__(self, *args):
        """Handle exit."""
        self.close()

    def open(self):
        """Open the connection to the receiver."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if not self.verify:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            except AttributeError:
                raise AssertionError('SSL verification cannot be disabled')
            ctx.verify_mode = ssl.CERT_NONE
            ctx.check_hostname = False
            self._sock = ctx.wrap_socket(self._sock)
        else:
            self._sock = ssl.wrap_socket(self._sock)

        self._sock.connect((urlparse(self.url).netloc, 41677))
        self._sock = self._sock.makefile('rw')

        # Receive server banner.
        server_banner = self._sock.readline().strip()
        if not server_banner:
            self.close()
            raise IOError('Server banner not received')

        # Send client banner.
        self._sock.write(
            'HELO 1.0 client.js %s Bearer %s\r\n' %
            (time.time(), self.token['access_token']))
        self._sock.flush()

        response = self._sock.readline().strip()
        if response.startswith('200 OK'):
            return

        self.close()
        if response.startswith('401 Unauthorized'):
            raise AuthenticationError('Authentication failed: %s' % response)
        else:
            raise IOError('Connect failed: %s' % response)

    def send(self, event):
        """Send the event to the receiver."""
        assert isinstance(event, Event), 'Must send Event'
        self._sock.write('PUT %s\r\n' % event.to_json())
        self._sock.flush()
        response = self._sock.readline().strip()

        if not response.startswith('200 OK'):
            raise IOError('Event send failed: %s' % response)

    def close(self):
        """Close the connection to the receiver."""
        if self._sock is None:
            raise IOError('Already closed')

        try:
            try:
                self._sock.write('QUIT\r\n')
            except IOError:
                # We are closing, I think it is safe to ignore this.
                pass
            self._sock.close()
        finally:
            self._sock = None


class Client(_OAuth2Session):
    """Client for communicating to Veristack."""

    def __init__(self, *args, **kwargs):
        """Instantiate Client."""
        self.client_secret = kwargs.pop('client_secret', None)
        if self.client_secret is None and 'token' not in kwargs:
            raise AssertionError('Must provide token or client_secret')
        self.url = kwargs.pop('url')
        self.uid = kwargs.pop('uid')
        self.refresh_token_callback = kwargs.pop('refresh_token_callback',
                                                 None)
        self.verify = kwargs.pop('verify', True)
        super(Client, self).__init__(
            *args[2:], client=JWTApplicationClient(kwargs['client_id']),
            **kwargs)
        # Set this after the super() call, as our superclass's superclass sets
        # this indiscriminately to True.
        if not self.verify:
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

    def fetch_token(self, **kwargs):
        kwargs.setdefault('verify', self.verify)
        payload = {'device': {'uid': self.uid}}
        if self.url.endswith('/'):
            url = self.url + 'oauth2/token/'
        else:
            url = self.url + '/oauth2/token/'
        token = super(Client, self).fetch_token(
            url,
            headers={
                'Authorization': b'Bearer %s' %
                jwt.encode(payload, self.client_secret)
            },
            **kwargs)
        return token

    def refresh_token(self, **kwargs):
        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('client_id', self.client_id)
        kwargs.setdefault('refresh_token',
                          self.token.get('refresh_token', None))
        kwargs.setdefault('access_token',
                          self.token.get('access_token', None))
        payload = {'device': {'uid': self.uid}}
        if self.url.endswith('/'):
            url = self.url + 'oauth2/token/'
        else:
            url = self.url + '/oauth2/token/'
        return super(Client, self).refresh_token(
            url,
            client_secret=self.client_secret,
            headers={
                'Authorization': b'Bearer %s' %
                jwt.encode(payload, self.client_secret)
            },
            **kwargs)

    def request(self, method, url, **kwargs):
        """Overridden to do token refresh."""
        kwargs.setdefault('verify', self.verify)
        tried_refresh = False
        while True:
            try:
                return super(Client, self).request(
                    method, url, **kwargs)
            except TokenExpiredError:
                if tried_refresh:
                    raise
                token = self.refresh_token(
                    refresh_token=self.token.get('refresh_token'))
                if callable(self.refresh_token_callback):
                    self.refresh_token_callback(token)
                tried_refresh = True

    def fetch_authorizations(self):
        """Fetch list of authorizations."""
        url = urljoin(self.url, '/api/authorizations/')
        return self.get(url, verify=self.verify).json().get('results')

    def get_event_writer(self, **kwargs):
        """Return a persistent connection to the receiver."""
        writer = EventWriter(self, **kwargs)
        try:
            writer.open()
        except AuthenticationError:
            writer.token = self.refresh_token()
            writer.open()

        return writer

    def send_events(self, events, **kwargs):
        """Send the list of events to the receiver."""
        with self.get_event_writer(**kwargs) as writer:
            for event in events:
                writer.send(event)
