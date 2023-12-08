import unittest
import requests
import json
import threading
from http.server import HTTPServer
from JWKSBulk.py import MyServer

class TestMyServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the HTTP server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        # Shutdown the HTTP server after the tests
        cls.server.shutdown()

    @classmethod
    def start_server(cls):
        cls.server = HTTPServer(('localhost', 8081), MyServer)
        cls.server.serve_forever()

    def test_register_user(self):
        # Test user registration
        url = 'http://localhost:8081/register'
        data = {'username': 'test_user', 'email': 'test@example.com'}

        response = requests.post(url, json=data)
        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertIn('password', result)

    def test_authenticate_user(self):
        # Test user authentication
        register_url = 'http://localhost:8081/register'
        auth_url = 'http://localhost:8081/auth'

        # Register a user
        register_data = {'username': 'test_user', 'email': 'test@example.com'}
        register_response = requests.post(register_url, json=register_data)
        self.assertEqual(register_response.status_code, 201)
        password = register_response.json()['password']

        # Authenticate the user
        auth_data = {'username': 'test_user', 'password': password}
        auth_response = requests.post(auth_url, json=auth_data)
        self.assertEqual(auth_response.status_code, 200)

    def test_jwks_endpoint(self):
        # Test the /.well-known/jwks.json endpoint
        url = 'http://localhost:8081/.well-known/jwks.json'

        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('keys', result)
        self.assertTrue(isinstance(result['keys'], list))

if __name__ == '__main__':
    unittest.main()
