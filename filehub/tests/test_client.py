"""FileHub 2.0 (Govern) client tests."""
import ssl

import requests
import tempfile
import unittest

from io import StringIO
from mock.mock import patch
from mock.mock import Mock, MagicMock
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth2Session

from filehub.client import (
    AuthenticationError, Client, EventWriter, FileDetails, GEO_URL,
    hash_path, JWTApplicationClient, LocationDetails,
)

from filehub.__main__ import make_timeline


class HashPathTest(unittest.TestCase):
    """Test hash_path."""

    def test_hash_path(self):
        """Test hashing the file."""
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'hello world')
            f.flush()
            h = hash_path(f.name)

        self.assertEqual('5eb63bbbe01eeed093cb22bb8f5acdc3', h)


class JWTApplicationClientTest(unittest.TestCase):
    """Test JWTApplicationClient."""

    @patch('filehub.client.prepare_token_request')
    def test_client(self, mock_request):
        """Test the client."""
        client = JWTApplicationClient('client123')

        client.prepare_request_body()

        self.assertTrue(mock_request.called)
        self.assertEqual(
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
            mock_request.call_args[0][0])
        self.assertEqual('client123', mock_request.call_args[1]['client_id'])
        self.assertIsNone(client.prepare_request_uri())


class FileDetailsTest(unittest.TestCase):
    """Test FileDetails."""

    @patch('filehub.client.hash_path')
    @patch('filehub.client.getsize')
    def test_file_details(self, mock_size, mock_hash):
        """Test file details."""
        mock_size.return_value = 1024
        mock_hash.return_value = '7a654c5b54645'

        fd = FileDetails.from_path('/folder/file.txt')

        self.assertEquals('/folder/file.txt', fd.path)
        try:
            fd.to_json()
        except:
            self.fail('Should not raise an exception')

    @patch('filehub.client.hash_path')
    @patch('filehub.client.getsize')
    def test_file_details_with_extra(self, mock_size, mock_hash):
        """Test file details with an extra field."""
        mock_size.return_value = 1024
        mock_hash.return_value = '7a654c5b54645'

        fd = FileDetails.from_path('/folder/file.txt')
        fd.extra = {'hidden': True}

        self.assertEquals('/folder/file.txt', fd.path)
        try:
            data = fd.to_dict()
        except:
            self.fail('Should not raise an exception')

        self.assertTrue(data.get('hidden'))


class ClientTest(unittest.TestCase):
    """Test Client."""

    def setUp(self):
        self.client = Client(
            client_id='abc123',
            client_secret='1234',
            uid='abcd',
            url='https://filehub.com/',
        )

    def test_invalid_init(self):
        """Test construction with missing parameters."""
        with self.assertRaises(AssertionError):
            Client(url='https://filehub.com/', uid='abcd')

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    def test_connect_receiver(self, mock_wrap, mock_socket):
        """Test connecting to receiver."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.side_effect = ['Banner', '200 OK']
        mock_socket.return_value = None
        mock_wrap.return_value.connect.return_value = None
        mock_wrap.return_value.makefile.return_value = mock_file

        self.client.token['access_token'] = b'token123'

        receiver = self.client.get_event_writer()

        self.assertIsNotNone(receiver._sock)
        self.assertTrue(mock_wrap.return_value.connect.called)
        self.assertEqual(
            'filehub.com',
            mock_wrap.return_value.connect.call_args[0][0][0])
        self.assertTrue(mock_file.write.called)
        self.assertIn('token123', mock_file.write.call_args[0][0])

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    @patch.object(Client, 'refresh_token')
    def test_connect_receiver_no_banner(self, mock_refresh, mock_wrap,
                                        mock_socket):
        """Test connecting to receiver with no banner."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.return_value = ''
        mock_socket.return_value = None
        mock_wrap.return_value.connect.return_value = None
        mock_wrap.return_value.makefile.return_value = mock_file

        with self.assertRaises(IOError) as e:
            self.client.get_event_writer()

        self.assertEqual('Server banner not received', str(e.exception))

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    @patch.object(Client, 'refresh_token')
    def test_connect_receiver_bad_auth(self, mock_refresh, mock_wrap,
                                       mock_socket):
        """Test connecting to receiver with bad authentication."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.side_effect = [
            'Banner', '401 Unauthorized',
            'Banner', '401 Unauthorized'
        ]
        mock_socket.return_value = None
        mock_wrap.return_value.connect.return_value = None
        mock_wrap.return_value.makefile.return_value = mock_file

        self.client.token['access_token'] = b'token123'

        with self.assertRaises(AuthenticationError) as e:
            self.client.get_event_writer()

        self.assertEqual(
            'Authentication failed: 401 Unauthorized',
            str(e.exception))

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    @patch.object(Client, 'refresh_token')
    def test_connect_receiver_error_response(self, mock_refresh, mock_wrap,
                                             mock_socket):
        """Test connecting to receiver with error response."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.side_effect = ['Banner', '400 BAD REQUEST']
        mock_socket.return_value = None
        mock_wrap.return_value.connect.return_value = None
        mock_wrap.return_value.makefile.return_value = mock_file

        self.client.token['access_token'] = b'token123'

        with self.assertRaises(IOError) as e:
            self.client.get_event_writer()

        self.assertEqual('Connect failed: 400 BAD REQUEST', str(e.exception))

    @patch.object(OAuth2Session, 'request')
    def test_request(self, mock_request):
        """Test making a request."""
        response = Mock(spec=requests.Response)
        response.status_code = 200
        mock_request.return_value = response

        r = self.client.get('https://filehub.com/api/endpoint/')

        self.assertEqual(200, r.status_code)

    @patch.object(OAuth2Session, 'refresh_token')
    @patch.object(OAuth2Session, 'request')
    def test_request_refresh(self, mock_request, mock_refresh_token):
        """Test making a request when token needs to be refreshed."""
        callback = Mock()
        response = Mock(spec=requests.Response)
        response.status_code = 200
        mock_request.side_effect = [TokenExpiredError(), response]
        new_token = {
            'access_token': '789',
            'refresh_token': '456',
            'expires_in': '3600',
        }
        mock_refresh_token.return_value = new_token

        client = Client(
            client_id='abc123',
            client_secret='1234',
            uid='abcd',
            url='https://filehub.com/',
            refresh_token_callback=callback,
        )

        r = client.get('https://filehub.com/api/endpoint/')

        self.assertEqual(200, r.status_code)
        self.assertTrue(callback.called)
        self.assertEqual(new_token, callback.call_args[0][0])

    @patch.object(OAuth2Session, 'refresh_token')
    @patch.object(OAuth2Session, 'request')
    def test_request_refresh_fail(self, mock_request, mock_refresh_token):
        """Test making a request when token fails to be refreshed."""
        mock_request.side_effect = [TokenExpiredError(), TokenExpiredError()]
        mock_refresh_token.return_value = None

        with self.assertRaises(TokenExpiredError):
            self.client.get('https://filehub.com/api/endpoint/')

    @patch.object(OAuth2Session, 'fetch_token')
    def test_fetch_token(self, mock_fetch_token):
        """Test fetching the tokens."""
        token = {
            'access_token': '789',
            'refresh_token': '456',
            'expires_in': '3600',
        }
        mock_fetch_token.return_value = token

        t = self.client.fetch_token()

        self.assertEqual(token, t)

    @patch.object(OAuth2Session, 'get')
    def test_fetch_authorizations(self, mock_get):
        """Test fetching the authorizations."""
        results = ['result1', 'result2']
        response = Mock(spec=requests.Response)
        response.json.return_value = {
            'results': results
        }
        response.status_code = 200
        mock_get.return_value = response

        auth = self.client.fetch_authorizations()

        self.assertEqual(auth, results)

    @patch.object(EventWriter, 'open')
    @patch('requests.get')
    def test_event_writer_send(self, mock_get, mock_open):
        """Test sending events with the event writer."""
        response = Mock(spec=requests.Response)
        response.json.return_value = {
            u'latitude': 39.8227,
            u'state/province': u'Indiana',
            u'ip': u'209.43.28.60',
            u'longitude': -86.145,
            u'country': u'United States'
        }
        mock_get.return_value = None
        mock_open.return_value = None

        with self.client.get_event_writer() as writer:
            writer._sock = MagicMock()
            writer._sock.write.return_value = None
            writer._sock.flush.return_value = None
            writer._sock.readline.return_value = '200 OK'

            events = list(make_timeline())
            event_count = len(events)

            loc_err = events.pop()
            with self.assertRaises(IOError):
                loc_err.location = LocationDetails.from_geo('209.43.28.60')

            writer.send(loc_err)

            self.assertEqual(
                '%s?ip=209.43.28.60' % GEO_URL,
                mock_get.call_args[0][0])

            mock_get.return_value = response

            for event in events:
                event.location = LocationDetails.from_geo()
                writer.send(event)

            self.assertEqual(event_count, writer._sock.write.call_count)

        self.assertEqual(event_count, mock_get.call_count)
        self.assertEqual(GEO_URL, mock_get.call_args[0][0])

    @patch.object(Client, 'get_event_writer')
    def test_send_events(self, mock_get_event_writer):
        """Test sending events to the receiver."""
        mock_event_writer = MagicMock()
        mock_event_writer.__enter__.return_value = mock_event_writer
        mock_get_event_writer.return_value = mock_event_writer

        events = list(make_timeline())

        self.client.send_events(events)

        self.assertTrue(mock_event_writer.send.called)
        for i, e in enumerate(events):
            self.assertEqual(e, mock_event_writer.send.call_args_list[i][0][0])
        self.assertTrue(mock_event_writer.__exit__.called)

    @patch.object(OAuth2Session, 'refresh_token')
    @patch.object(Client, 'get_event_writer')
    def test_send_events_failure(self, mock_connect, mock_refresh_token):
        """Test sending events with a failure."""
        mock_connect.side_effect = [IOError(), IOError()]
        new_token = {
            'access_token': '789',
            'refresh_token': '456',
            'expires_in': '3600',
        }
        mock_refresh_token.return_value = new_token

        events = list(make_timeline())

        with self.assertRaises(IOError):
            self.client.send_events(events)

    @patch('ssl.SSLContext')
    def test_nosslverify(self, mock_ssl_context):
        """Ensure that SSLContext is used when available."""
        token = {
            'access_token': '789',
            'refresh_token': '456',
            'expires_in': '3600',
        }

        with self.client.get_event_writer(verify=False, token=token) as writer:
            writer._sock = MagicMock()
            writer._sock.write.return_value = None
            writer._sock.flush.return_value = None
            writer._sock.readline.return_value = '200 OK'

            event = next(make_timeline())
            writer.send(event)

        self.assertTrue(mock_ssl_context.return_value.wrap_socket.called)
        self.assertEqual(False, mock_ssl_context.return_value.check_hostname)
        self.assertEqual(ssl.CERT_NONE,
                         mock_ssl_context.return_value.verify_mode)

    @patch('ssl.SSLContext')
    def test_nosslverify_py2(self, mock_ssl_context):
        """Ensure that older versions of ssl module are handled by raising."""
        mock_ssl_context.side_effect = AttributeError()

        with self.assertRaises(AssertionError):
            self.client.get_event_writer(verify=False)
