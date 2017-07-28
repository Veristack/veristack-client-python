"""FileHub integration client."""

from __future__ import absolute_import

import base64
import hashlib
import json
import platform
import socket
import ssl
import time

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
    with open(path, 'r') as f:
        while True:
            block = f.read().encode('utf-8')
            if not block:
                break
            md5.update(block)
    return md5.hexdigest()


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

    def __init__(self, uid=None, directory=None, name=None, size=None,
                 md5=None, fingerprint=None, extra=None):
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
            'uid': hashlib.md5(bytes(path, 'ascii')).hexdigest(),
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
        self.directory = dirname(value)
        self.name = basename(value)

    def to_json(self):
        """Convert to json."""
        assert self.uid, 'uid must be set'
        assert self.size, 'size must be set'
        assert self.directory, 'directory must be set'
        assert self.name, 'name must be set'
        assert self.md5, 'md5 must be set'
        d = {
            'uid': self.uid,
            'directory': self.directory,
            'name': self.name,
            'size': self.size,
            'md5': self.md5,
        }
        if self.fingerprint:
            d['fingerprint'] = self.fingerprint
        if self.extra:
            d.update(self.extra)
        return json.dumps(d)


class PersonDetails(object):
    """Person details.

    Provides validation and serialization. Detects username.
    """

    def __init__(self, username=None, fullname=None, email=None, extra=None):
        self.username = username or USERNAME
        self.fullname = fullname
        self.email = email
        self.extra = extra or {}

    def to_json(self):
        """Convert to json."""
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
        return json.dumps(d)


class DeviceDetails(object):
    """Device details.

    Provides valiation and serialization. Detects the hostname and os details.
    """

    def __init__(self, device_type=None, name=None, addr=None, os=None,
                 extra=None):
        self.device_type = device_type
        self.name = name or HOSTNAME
        self.addr = addr
        self.os = os or OS
        self.extra = extra or {}

    def to_json(self):
        """Convert to json."""
        assert self.device_type in DEVICE_TYPES, 'invalid device_type'
        assert self.name, 'name must be set'
        assert self.addr, 'addr must be set'
        assert self.os, 'os must be set'
        d = {
            'device_type': self.device_type,
            'name': self.name,
            'addr': self.addr,
            'os': self.os
        }
        if self.extra:
            d.update(self.extra)
        return json.dumps(d)


class LocationDetails(object):
    """Geographic location details.

    Can call the FileHub geo service to obtain lat/long. Provides validation
    and serialization.
    """

    def __init__(self, latitude=None, longitude=None):
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

    def to_json(self):
        """Convert to json."""
        assert self.latitude, 'latitude must be set'
        assert self.longitude, 'longitude must be set'
        return json.dumps({
            'latitude': self.latitude,
            'longitude': self.longitude,
        })


class Event(object):
    """Represent an individual audit event.

    Provides validation and serialization of event message.
    """

    def __init__(self, action_type=None, device=None, timestamp=None,
                 person=None, location=None, files=None, extra=None):
        self.action_type = action_type
        self.device = device
        self.timestamp = timestamp or time.time()
        self.person = person
        self.location = location
        self.files = list(files) if files else []
        self.extra = extra or {}

    def to_json(self):
        """Convert to json."""
        assert len(self.files) in (1, 2), 'must provide one or two files'
        assert all(map(lambda f: callable(getattr(f, 'to_json', None)),
                       self.files)), 'all files must have `.to_json()` method'
        assert self.action_type, 'action_type must be set'
        assert self.device, 'device must be set'
        assert callable(getattr(self.device, 'to_json', None)), \
            'device must have `to_json()` method'
        assert self.timestamp, 'timestamp must be set'
        assert self.person, 'person must be set'
        assert callable(getattr(self.person, 'to_json', None)), \
            'person must have `to_json()` method'
        assert (self.location is None or
                callable(getattr(self.location, 'to_json', None))), \
            'location must be LocationDetails or None'
        d = {
            'timestamp': self.timestamp,
            'device': self.device.to_json(),
            'person': self.person.to_json(),
            'action_type': self.action_type,
        }
        if self.location:
            d['location'] = self.location.to_json()
        d['file1'] = self.files[0].to_json()
        if len(self.files) == 2:
            d['file2'] = self.files[1].to_json()
        if self.extra:
            d.update(self.extra)
        return json.dumps(d)


class EventWriter(object):
    """Stream events to FileHub.

    Maintains a persistent connection for sending events. Can be used as a
    context manager to ensure the connection is closed. Checks server response
    and raises `IOError` for any protocol errors.
    """

    def __init__(self, client):
        self.token = client.token
        self.url = client.url
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
        ssl.wrap_socket(self._sock)
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
            (time.time(), base64.b64encode(self.token['access_token'])))
        self._sock.flush()

        response = self._sock.readline().strip()
        if response.startswith('200 OK'):
            return

        self.close()
        if response.startswith('401 Unauthorized'):
            raise IOError('Authentication failed: %s' % response)
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
    """Client for communicating to FileHub 2.0 (Govern) API."""

    def __init__(self, url, uid, refresh_token_callback=None,
                 *args, **kwargs):
        self.client_secret = kwargs.pop('client_secret', None)
        if self.client_secret is None and 'token' not in kwargs:
            raise AssertionError('Must provide token or client_secret')
        self.url = url
        self.uid = uid
        self.refresh_token_callback = refresh_token_callback
        super(Client, self).__init__(
            *args, client=JWTApplicationClient(kwargs['client_id']), **kwargs)

    def fetch_token(self, **kwargs):
        payload = {'device': {'uid': self.uid}}
        token = super(Client, self).fetch_token(
            urljoin(self.url, '/oauth2/token/'),
            headers={
                'Authorization': b'Bearer %s' %
                jwt.encode(payload, self.client_secret)
            },
            **kwargs)
        return token

    def refresh_token(self, **kwargs):
        kwargs.setdefault('client_id', self.client_id)
        payload = {'device': {'uid': self.uid}}
        return super(Client, self).refresh_token(
            urljoin(self.url, '/oauth2/token/'),
            client_secret=self.client_secret,
            headers={
                'Authorization': b'Bearer %s' %
                jwt.encode(payload, self.client_secret)
            },
            **kwargs)

    def request(self, method, url, **kwargs):
        """Overridden to do token refresh."""
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
        return self.get(url).json().get('results')

    def get_event_writer(self):
        """Return a persistent connection to the receiver."""
        writer = EventWriter(self)
        try:
            writer.open()
        except IOError as e:
            if 'Authentication failed' not in e.args[0]:
                raise
            writer.token = self.refresh_token()
            writer.open()
        return writer

    def send_events(self, events):
        """Send the list of events to the receiver."""
        with self.get_event_writer() as writer:
            for event in events:
                writer.send(event)
