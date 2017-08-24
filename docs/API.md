# API

For security reasons (see [Architecture.md](Architecture.md)), all HackerOne API requests go through the `api` container. The API runs on the `api` container on port 8080. It uses basic authentication with a shared secret between the ```bot``` box and the ```api``` container. 

The `api` container hosts 5 different endpoints: 

## ```/v1/sendMessage```

Posting an internal message on the report with ID 0. 

```python
requests.post('http://api:8080/v1/sendMessage', 
              json={'message': 'Internal message!', 'internal': True, 'id': '0'}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

Posting a public message on the report with ID 1:

```python
requests.post('http://api:8080/v1/sendMessage', 
              json={'message': 'Internal message!', 'internal': False, 'id': '1'}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

## ```/v1/changeStatus```

Changing the status of the report with ID 0 to triaged:

```python
requests.post('http://api:8080/v1/changeStatus', 
              json={'message': 'Message!', 'status': 'triaged', 'id': '0'}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

Changing the status of the report with ID 1 to closed:

```python
requests.post('http://api:8080/v1/changeStatus', 
              json={'message': 'Message!', 'status': 'closed', 'id': '1'}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

Changing the status of the report with ID 2 to duplicate:

```python
requests.post('http://api:8080/v1/changeStatus', 
              json={'message': 'Message!', 'status': 'duplicate', 'id': '2'}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

## ```/v1/getReport```

Get a serialized representation of the report with ID 0:

```python
requests.post('http://api:8080/v1/getReport', 
              json={'id': '0'}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

## ```/v1/getReportIDs```

Get a list of all of the report IDs created after ```2017-08-01T22:00:00.000000+00:00``` (a date in ISO8601 format with a timezone):

```python
requests.post('http://api:8080/v1/getReportIDs', 
              json={'time': "2017-08-01T22:00:00.000000+00:00", "openOnly": False}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

Get a list of all of the report IDs created after ```2017-08-01T22:00:00.000000+00:00``` that are currently open:

```python
requests.post('http://api:8080/v1/getReportIDs', 
              json={'time': "2017-08-01T22:00:00.000000+00:00", "openOnly": True}, 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```

## ```/v1/getReports```

Get a list of all the reports on the program. Note that this is strictly different from `[getReport(id) for id in getReportIDs(0)]` because this endpoint returns all of the reports at once, but the comments are not included. So if you need access to the comments, use getReport(id). But if you only need the report body and care about speed, then getReports is faster since it does not make a request for each report. 

```python
requests.post('http://api:8080/v1/getReports', 
              auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
```
