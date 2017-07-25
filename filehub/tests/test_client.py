"""FileHub 2.0 (Govern) client tests."""
import json
import requests
import unittest

from io import StringIO
from mock.mock import patch
from mock.mock import Mock
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth2Session

from filehub.client import FileHubClient


class FileHubClientTest(unittest.TestCase):
    """Test FileHubClient."""

    def setUp(self):
        self.client = FileHubClient(
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

        receiver = self.client._connect_receiver()

        self.assertIsInstance(receiver, StringIO)
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
            self.client._connect_receiver()

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
            self.client._connect_receiver()

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

        client = FileHubClient(
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

    @patch.object(OAuth2Session, 'refresh_token')
    @patch.object(FileHubClient, '_connect_receiver')
    def test_send_events(self, mock_connect, mock_refresh_token):
        """Test sending events."""
        mock_file = Mock(spec=StringIO)
        mock_connect.side_effect = [IOError(), mock_file]
        new_token = {
            'access_token': '789',
            'refresh_token': '456',
            'expires_in': '3600',
        }
        mock_refresh_token.return_value = new_token

        events = [
            {
                'device': {
                    'name': 'laptop1',
                    'type': 1
                }
            },
            {
                'device': {
                    'name': 'laptop2',
                    'type': 1
                }
            }
        ]

        self.client.send_events(events)

        self.assertTrue(mock_file.write.called)
        self.assertEqual(
            'PUT ' + json.dumps(events[0]) + '\r\n',
            mock_file.write.call_args_list[0][0][0])
        self.assertEqual(
            'PUT ' + json.dumps(events[1]) + '\r\n',
            mock_file.write.call_args_list[1][0][0])
        self.assertTrue(mock_file.close.called)

    @patch.object(OAuth2Session, 'refresh_token')
    @patch.object(FileHubClient, '_connect_receiver')
    def test_send_events_failure(self, mock_connect, mock_refresh_token):
        """Test sending events with a failure."""
        mock_connect.side_effect = [IOError(), IOError()]
        new_token = {
            'access_token': '789',
            'refresh_token': '456',
            'expires_in': '3600',
        }
        mock_refresh_token.return_value = new_token

        events = [
            {
                'device': {
                    'name': 'laptop1',
                    'type': 1
                }
            },
            {
                'device': {
                    'name': 'laptop2',
                    'type': 1
                }
            }
        ]

        with self.assertRaises(IOError):
            self.client.send_events(events)
