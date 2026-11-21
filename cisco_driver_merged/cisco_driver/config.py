import os

BASE_URL = os.getenv('CISCO_MOCK_URL', 'http://127.0.0.1:8765')
TOKEN = os.getenv('CISCO_MOCK_TOKEN', 'local-demo-token')
TIMEOUT = 5
MAX_TTL = 86400
