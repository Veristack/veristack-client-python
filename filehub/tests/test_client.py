"""FileHub 2.0 (Govern) client tests."""
import requests
import tempfile
import unittest

from io import StringIO
from mock.mock import patch
from mock.mock import Mock, MagicMock
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth2Session

from filehub.client import Client
from filehub.client import EventWriter
from filehub.client import FileDetails
from filehub.client import GEO_URL
from filehub.client import hash_path
from filehub.client import JWTApplicationClient
from filehub.client import LocationDetails
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


class FileHubClientTest(unittest.TestCase):
    """Test FileHubClient."""

    def setUp(self):
        self.client = Client(
            client_id='abc123',
            client_secret='1234',
            uid='abcd',
            url='https://filehub.com/',
        )

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    def test_connect_receiver(self, mock_wrap, mock_socket):
        """Test connecting to receiver."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.side_effect = ['Banner', '200 OK']
        mock_socket.return_value.makefile.return_value = mock_file
        mock_wrap.return_value = None

        self.client.token['access_token'] = b'token123'

        receiver = self.client.get_event_writer()

        self.assertIsNotNone(receiver._sock)
        self.assertTrue(mock_socket.return_value.connect.called)
        self.assertEqual(
            'filehub.com',
            mock_socket.return_value.connect.call_args[0][0][0])
        self.assertTrue(mock_file.write.called)
        self.assertIn('dG9rZW4xMjM=', mock_file.write.call_args[0][0])

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    def test_connect_receiver_no_banner(self, mock_wrap, mock_socket):
        """Test connecting to receiver with no banner."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.return_value = ''
        mock_socket.return_value.makefile.return_value = mock_file
        mock_wrap.return_value = None

        with self.assertRaises(IOError) as e:
            self.client.get_event_writer()

        self.assertEqual('Server banner not received', str(e.exception))

    @patch('socket.socket')
    @patch('ssl.wrap_socket')
    def test_connect_receiver_error_response(self, mock_wrap, mock_socket):
        """Test connecting to receiver with error response."""
        mock_file = Mock(spec=StringIO)
        mock_file.readline.side_effect = ['Banner', '400 BAD REQUEST']
        mock_socket.return_value.makefile.return_value = mock_file
        mock_wrap.return_value = None

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

            mock_get.return_value = response

            for event in events:
                event.location = LocationDetails.from_geo('209.43.28.60')
                writer.send(event)

            self.assertEqual(event_count, writer._sock.write.call_count)

        self.assertEqual(event_count, mock_get.call_count)
        self.assertEqual(
            '%s?ip=209.43.28.60' % GEO_URL,
            mock_get.call_args[0][0])

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
