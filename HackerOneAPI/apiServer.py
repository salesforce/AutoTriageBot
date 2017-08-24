"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from flask import Flask, request, Response
import json
import requests
from requests.auth import HTTPBasicAuth
from HackerOneAPI import config
from HackerOneAPI import secrets
from AutoTriageBot.ReportWrapper import ReportWrapper, parseTime
from typing import Mapping, List, Callable, Union
from functools import wraps

app = Flask(__name__)


def validAuth(username: str, password: str) -> bool:
    """ Whether the username and password are correct """
    return username == 'AutoTriageBot' and password == secrets.apiBoxToken


def authFailure():
    """ Authentication failure --> 401 """
    return Response("Authentication failed!", 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


def authed(func: Callable[[], str]) -> Callable[[], Union[Response, str]]:
    """ Given a function returns one that requires basic auth """
    @wraps(func)
    def decorator():
        auth = request.authorization
        if auth and validAuth(auth.username, auth.password):
            return func()
        return authFailure()
    return decorator


@app.route('/v1/sendMessage', methods=['POST'])
@authed
def sendMessage() -> str:
    """ Send a message (internal or external) to the HackerOne report identified by the given ID"""
    data = request.get_json(force=True)
    message = data['message']
    internal = data['internal']
    id = data['id']

    if config.DEBUG:
        print("/v1/sendMessage: id=%s, internal=%s" % (id, internal))
    if config.DEBUGVERBOSE:
        print("message=%s" % message)

    h1Data = {'data': {'type': 'activity-comment',
                       'attributes': {'message': message,
                                      'internal': internal}}}
    headers = {'Content-Type': 'application/json'}
    resp = requests.post('https://api.hackerone.com/v1/reports/%s/activities' % id,
                         headers=headers,
                         data=json.dumps(h1Data).encode('utf-8'),
                         auth=(config.apiName, secrets.apiToken))
    return json.dumps(resp.json())


@app.route('/v1/changeStatus', methods=['POST'])
@authed
def changeStatus() -> str:
    """ Change the status of the report at the given ID to the given status """
    data = request.get_json(force=True)
    status = data['status']
    message = data['message']
    id = data['id']

    if config.DEBUG:
        print("/v1/changeStatus: id=%s, status=%s" % (id, status))
    if config.DEBUGVERBOSE:
        print("message=%s" % message)

    h1Data = {'data': {'type': 'state-change',
                       'attributes': {'message': message,
                                      'state': status}}}
    headers = {'Content-Type': 'application/json'}
    resp = requests.post('https://api.hackerone.com/v1/reports/%s/state_changes' % id,
                         headers=headers,
                         data=json.dumps(h1Data).encode('utf-8'),
                         auth=(config.apiName, secrets.apiToken))
    return json.dumps(resp.json())


@app.route('/v1/getReport', methods=['POST'])
@authed
def getReport() -> str:
    """ Get the serialized version of the report at the given ID """
    data = request.get_json(force=True)
    id = data['id']

    if config.DEBUGVERBOSE:
        print("/v1/getReport: id=%s" % id)

    j = getEndpoint("https://api.hackerone.com/v1/reports/%s" % id)
    return ReportWrapper(j['data']).serialize()


@app.route('/v1/getReportIDs', methods=['POST'])
@authed
def getReportIDs() -> str:
    """ Get a list of report IDs created after the given time of openOnly is true, then only the IDs of open reports """
    data = request.get_json(force=True)
    startTime = parseTime(data['time'])
    openOnly = data['openOnly']

    if config.DEBUGVERBOSE:
        print("/v1/getReportIDs: time=%s, openOnly=%s" % (startTime.isoformat(), str(openOnly)))

    if openOnly:
        allIDs = []
        for state in ['new', 'triaged', 'needs-more-info']:
            url = "https://api.hackerone.com/v1/reports?filter[program][]=%s&page[size]=100&filter[state][]=%s" % \
                  (config.programName, state)
            ids = [report['id'] for report in getEndpointPaginated(url)
                   if parseTime(report['attributes']['created_at']) > startTime]
            allIDs.extend(ids)
        return json.dumps(allIDs)
    else:
        url = "https://api.hackerone.com/v1/reports?filter[program][]=%s&page[size]=100" % config.programName
        return json.dumps([report['id'] for report in getEndpointPaginated(url)
                           if parseTime(report['attributes']['created_at']) > startTime])


@app.route('/v1/getReports', methods=['POST'])
@authed
def getReports() -> str:
    """ Get all of the reports on the program
         - For H1, getReports *is* different from [getReport(id) for id in getReportIDs(0)] because the
           /v1/getReports API endpoint returns all the reports at once, but the comments are not included.
           So if you need access to the comments, use getReport(id). But if you only need the report body
           then getReports is faster since it does not make as many requests.

         Returns string encoded JSON that is a list of serialized ReportWrappers """
    if config.DEBUGVERBOSE:
        print("/v1/getReports")

    url = "https://api.hackerone.com/v1/reports?filter[program][]=%s&page[size]=100" % config.programName
    return json.dumps([ReportWrapper(j).serialize() for j in getEndpointPaginated(url)])


def getEndpoint(url: str) -> Mapping:
    """ Make an authenticated (to hackerone) request to the given URL and parse it into json """
    return requests.get(url, auth=HTTPBasicAuth(config.apiName, secrets.apiToken)).json()


def getEndpointPaginated(url: str, cnt=0) -> List[Mapping]:
    """ Get the given endpoint and paginate """
    cur = getEndpoint(url)
    if 'next' not in cur['links'].keys():
        return []
    else:
        return cur['data'] + getEndpointPaginated(cur['links']['next'], cnt=cnt+1)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, threaded=True)
