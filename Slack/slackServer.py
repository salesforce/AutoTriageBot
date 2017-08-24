"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from flask import Flask, request
import json
import requests
from requests.auth import HTTPBasicAuth
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot import secrets
from threading import Thread
from urllib.parse import urlparse
from urllib.error import URLError

app = Flask(__name__)

verificationToken = open('/run/secrets/SlackVerificationToken', 'r').read().strip()


@app.route('/slack', methods=['POST'])
def inbound():
    try:
        # If the message verifies
        if json.loads(request.form.get('payload'))['token'] == verificationToken:
            reportID = json.loads(request.form.get('payload'))['callback_id'].split('_')[1]
            data = json.loads(request.form.get('payload'))
            t = Thread(target=sendResponse, args=(reportID, data['actions'][0]['name'], data['response_url']))
            t.start()
            return '', 200
        else:
            return ('Nice try! Your verification token didn\'t match. Good luck with the bug hunting and let us know '
                    'if you find anything. :)'), 200
    except KeyError:
        return 'Not a valid slack payload!', 200


def sendResponse(reportID: str, actionName: str, respURL: str) -> None:
    if actionName == 'body':
        text = getBody(reportID)
    elif actionName == 'metadata':
        text = getMetadata(reportID)
    else:
        raise ValueError("Button %s not defined!" % actionName)
    ephemeralJson = {'response_type': 'ephemeral',
                     'replace_original': False,
                     'text': text}
    # Even if an attacker gets the verification token, we will still refuse to post the data to non-slack.com URLs
    if urlparse(respURL).hostname.endswith('slack.com'):
        requests.post(respURL, json.dumps(ephemeralJson).encode('utf-8'))
    else:
        ephemeralJson['text'] = (('Failed URL check, respURL=%s which is not on the slack.com domain name! This check '
                                  'is theoretically not required (since we verify the verification token), but done as '
                                  'an extra defensive step. To disable this, edit slackServer.py in the project root.')
                                 % respURL)
        requests.post(respURL, json.dumps(ephemeralJson).encode('utf-8'))
        raise URLError("respURL=%s not on slack.com domain!" % respURL)


def getMetadata(id: str):
    ser = requests.post('http://api:8080/v1/getReport',
                        json={'id': id},
                        auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text
    metadataComment = ReportWrapper().deserialize(ser).extractMetadata()  # type: ignore
    firstLine = metadataComment.splitlines()[0].replace('# ', '*')+'*'
    return '\n'.join([firstLine] + metadataComment.splitlines()[1:])


def getBody(id: str):
    ser = requests.post('http://api:8080/v1/getReport',
                        json={'id': id},
                        auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text
    return ReportWrapper().deserialize(ser).getReportBody()  # type: ignore


if __name__ == "__main__":
    app.run(port=8080, host='0.0.0.0', threaded=True)
