# filehub-2.0-client
Client for interfacing to FileHub 2.0

# Usage
```python
from filehub.client import FileHubClient

client = FileHubClient(
    client_id='8ee21be2-3284-48e7-ac07-c4dc33769014',
    client_secret='9ed2cd6a-14d5-432a-9518-b59043adde0a',
    uid='abcd',
    url='https://filehub.com/')
client.fetch_token()

client.get('https://filehub.com/api/accounts/')

event = {
   'device': {
       'name': 'Someone\'s Desktop',
       'type': 1
   },
   'person': {
       'username': 'someone',
       'email': 'someone@somewhere.org',
       'fullname': 'One, S. Ome'
   },
   'timestamp': 1501075021,
   'action_type': 1,
   'file1': {
      'uid': 'b3d5884f2b7a0151c1e480d16ea96963',
      'name': 'Resume.doc',
      'directory': 'C:\\Users\\Someone\\Documents',
      'size': 12345,
      'md5': 'acbd18db4cc2f85cedef654fccc4a4d8',
   }
}

client.send_events([event])
```

# Testing

### Install required dependencies:
```
pip install -r test.txt
```
### Run tests and generate coverage report:
```
python -m pytest
```
