"""FileHub integration client."""
import base64
import json
import socket
import ssl
import time

import jwt

from six.moves.urllib.parse import urljoin  # noqa

from oauthlib.oauth2 import TokenExpiredError
from oauthlib.oauth2.rfc6749.clients.base import Client
from oauthlib.oauth2.rfc6749.parameters import prepare_token_request

from requests_oauthlib import OAuth2Session as _OAuth2Session


GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


class JWTApplicationClient(Client):
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


# TODO: add some niceties like url handling etc. to DRY things out.
class FileHubClient(_OAuth2Session):
    """Client for communicating to FileHub 2.0 (Govern) API."""

    def __init__(self, client_secret, uid, url, refresh_token_callback=None,
                 *args, **kwargs):
        self.url = url
        self.client_secret = client_secret
        self.uid = uid
        self.refresh_token_callback = refresh_token_callback
        self.token_url = urljoin(self.url, '/oauth2/token/')
        super(FileHubClient, self).__init__(
            *args, client=JWTApplicationClient(kwargs['client_id']), **kwargs)

    def _connect_receiver(self):
        """Connect to the receiver on FileHub 2.0 (Govern)."""
        receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl.wrap_socket(receiver)
        receiver.connect((self.url, 41677))
        receiver = receiver.makefile('rw')

        # Receive server banner.
        server_banner = receiver.readline()
        if not server_banner:
            raise IOError('Server banner not received')

        # Send client banner.
        receiver.write(
            'HELO 1.0 client.js %s Bearer %s\r\n' %
            (time.time(), base64.b64encode(self.token['access_token'])))
        receiver.flush()

        response = receiver.readline()
        if not response.startswith('200 OK'):
            raise IOError('Connect failed: %s' % response.strip())

        return receiver

    def fetch_token(self, **kwargs):
        payload = {'device': {'uid': self.uid}}
        token = super(FileHubClient, self).fetch_token(
            self.token_url,
            headers={
                'Authorization': b'Bearer %s' %
                jwt.encode(payload, self.client_secret)
            },
            **kwargs)
        return token

    def refresh_token(self, **kwargs):
        kwargs.setdefault('client_id', self.client_id)
        payload = {'device': {'uid': self.uid}}
        return super(FileHubClient, self).refresh_token(
            self.token_url,
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
                return super(FileHubClient, self).request(
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

    def send_events(self, events):
        """Send the list of events to the receiver."""
        receiver = self._connect_receiver()

        for event in events:
            receiver.write('PUT ' + json.dumps(event) + '\r\n')

        receiver.close()
