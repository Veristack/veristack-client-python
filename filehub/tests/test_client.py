"""FileHub 2.0 (Govern) client tests."""
import requests
import unittest

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
