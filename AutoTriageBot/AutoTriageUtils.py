"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import re
import socket
import string
from random import SystemRandom
from typing import Mapping, Tuple, TypeVar, Union, cast
from urllib.parse import urlparse, parse_qsl
import requests
from requests.auth import HTTPBasicAuth
from . import config
from . import secrets
from AutoTriageBot import constants
from AutoTriageBot.DataTypes import VulnTestInfo, URLParts
from AutoTriageBot.ReportWrapper import ReportWrapper, Serialized
from AutoTriageBot.slack import postMessage


def extractDataFromJson(data: Mapping) -> Tuple[str, Mapping[str, str], str, Mapping[str, str]]:
    """ Extract the requisite data from the given mapping while filling in any missing data as much as possible
         - Returns (url, cookies, type, data) """
    url = getCaseInsensitive(data, 'URL', default='')
    cookies = getCaseInsensitive(data, 'COOKIES', default={})
    type = getCaseInsensitive(data, 'TYPE', default='GET')
    data = getCaseInsensitive(data, 'DATA', default={})
    assert isinstance(url, str)
    assert isinstance(cookies, dict)
    assert isinstance(type, str)
    assert isinstance(data, dict)
    return url, cast(Mapping[str, str], cookies), type, cast(Mapping[str, str], data)


T = TypeVar('T')
U = TypeVar('U')


def getCaseInsensitive(data: Mapping[str, T], key: str, default: U=None) -> Union[T, U]:
    """ Get the data at the given key in a case insensitive manner """
    try:
        return data[key.upper()]
    except KeyError:
        try:
            return data[key.lower()]
        except KeyError:
            return default


def parseURL(url: str) -> URLParts:
    """ Parse the given URL into a URLParts named tuple and normalize any relevant domain names """
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            hostname = parsed.hostname
        else:
            hostname = ''
        if config.hostnameSanitizers:
            for regex, result in config.hostnameSanitizers.items():
                if re.compile(regex).match(hostname):
                    domain = result
                    break
            else:
                domain = hostname
        else:
            domain = hostname

        return URLParts(domain=domain,
                        path=parsed.path,
                        queries=dict(parse_qsl(parsed.query)))
    except ValueError:
        return None


def isProgramURL(url: str, acceptAll=True) -> bool:
    """ Whether the given url is a program URL """
    domain = urlparse(url).netloc.split(':')[0].lower()
    if not config.domains:
        return True
    if config.domains or (not acceptAll):
        try:
            ip = socket.gethostbyname(domain)
        except (socket.gaierror, UnicodeError):
            ip = None
        if domain and isinstance(config.domains, list):
            return (any([domain.endswith(hostname.lower()) for hostname in config.domains]) and
                    ip != '127.0.0.1')
        return False
    if acceptAll:
        return True


def generateToken() -> str:
    """ Generate a random 8 character long uppercase ascii token """
    return ''.join([SystemRandom().choice(string.ascii_uppercase) for _ in range(8)])


def postComment(id: str, vti: VulnTestInfo, internal=False, addStopMessage=False) -> Mapping:
    """ Post a comment to the report with the given ID using the information in the given VulnTestInfo
          - Set internal=True in order to post an internal comment
          - Set addStopMessage=True in order to add the stop message """
    if config.DEBUG:
        print("Posting comment: internal=%s, reproduced=%s, id=%s" % (str(internal), str(vti.reproduced), id))

    if addStopMessage:
        message = vti.message + '\n\n' + constants.disableMessage
    else:
        message = vti.message

    postMessage("Posting Message: \n\n%s" % message)  # TODO: Delete this

    resp = requests.post('http://api:8080/v1/sendMessage',
                         json={'message': message, 'internal': internal, 'id': id},
                         auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))

    if config.triageOnReproduce and vti.reproduced:
        changeStatus(id, 'triaged')

    return resp.json()


def changeStatus(id: str, status: str, msg='') -> Mapping:
    """ Change the status of the report with the given ID to the given status
          - Set msg=str to post a message in the same action """
    if config.DEBUG:
        print("Changing status: status=%s, id=%s" % (status, id))

    resp = requests.post('http://api:8080/v1/changeStatus',
                         json={'message': msg, 'status': status, 'id': id},
                         auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
    return resp.json()


def getReport(id: str) -> ReportWrapper:
    """ Get the ReportWrapper describing the report with the given ID number """
    resp = requests.post('http://api:8080/v1/getReport', json={'id': id},
                         auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken))
    return ReportWrapper().deserialize(Serialized(resp.text))
