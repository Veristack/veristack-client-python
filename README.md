# Govern Python Client
Client for interfacing to Govern

# Usage
```python
from filehub import (
    Client, Event, DeviceDetails, PersonDetails, FileDetails, ACT_READ,
)

client = Client(
    client_id='8ee21be2-3284-48e7-ac07-c4dc33769014',
    client_secret='9ed2cd6a-14d5-432a-9518-b59043adde0a',
    uid='abcd',
    url='https://filehub.com/')
client.fetch_token()

client.get('https://filehub.com/api/accounts/')

event = Event(
    action_type=ACT_READ,
    device=DeviceDetails(),
    person=PersonDetails(username='foo', email='foo@bar.org',
                         fullname='Foo B. Bar'),
    files=[
        FileDetails.from_path('/path/to/file.txt'),
    ],
)

client.send_events([event])
```

If the server fails to process the event, an IOError is raised. If sending many
messages at once (as shown above), it is hard to trace the error back to the
individual event, also, only a portion of the events will have been sent.
Further, this method opens and closes a connection for each batch being sent.

For a streaming interface (a persistent connection), you can use a slightly
different method of writing events.

```python
with client.get_event_writer() as writer:
    for e in events:
        writer.write(e)
```

This may be more suitable when dispatching events from a queue (so that they
can be left in queue until accepted by the server.)

# Generating test data

This package also provides an event generating tool named Genny. This tool will
produce event streams for testing purposes. To use this tool, simply do:

```bash
VERIFY_SSL_CERTIFICATES=no python -m filehub --client-id=<id> --client-secret=<secret> --host=https://localhost/ --token-file=oauth.token
```

The above will disable SSL certificate checks, connect to the event receiver
and send some events. The `--token-file` parameter saves the token to a file
after it is obtained, reusing it on subsequent runs (instead of fetching a new
token each time).

# Testing

### Install required dependencies:
```
pip install -r test.txt
```
### Run tests and generate coverage report:
```
python -m pytest
```
