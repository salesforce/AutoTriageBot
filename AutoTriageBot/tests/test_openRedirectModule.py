"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot.modules import openRedirect
from AutoTriageBot import constants
from AutoTriageBot.AutoTriageUtils import VulnTestInfo
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot import sqlite
import pytest


openRedirectReproJson = {'id': '239981', 'type': 'report', 'attributes': {'title': 'open redirect', 'state': 'new', 'created_at': '2017-06-14T23:03:51.775Z', 'vulnerability_information': 'blah open_redirect\n\n[some](http://example.com/redir.php?QUERY_STRING=https://google.com)', 'triaged_at': None, 'closed_at': None, 'last_reporter_activity_at': '2017-06-14T23:03:51.843Z', 'first_program_activity_at': '2017-06-14T23:03:51.843Z', 'last_program_activity_at': '2017-06-14T23:03:51.843Z', 'bounty_awarded_at': None, 'swag_awarded_at': None, 'disclosed_at': None, 'last_public_activity_at': '2017-06-14T23:03:51.843Z', 'last_activity_at': '2017-06-14T23:03:51.843Z'}, 'relationships': {'reporter': {'data': {'id': '174347', 'type': 'user', 'attributes': {'username': 'reporter_username', 'name': 'John Doe', 'disabled': False, 'created_at': '2017-06-08T20:58:21.626Z', 'profile_picture': {'62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}}}}, 'program': {'data': {'id': '21806', 'type': 'program', 'attributes': {'handle': 'bot_testing_environment', 'created_at': '2017-06-14T21:22:38.050Z', 'updated_at': '2017-06-14T21:42:03.850Z'}}}, 'swag': {'data': []}, 'attachments': {'data': []}, 'weakness': {'data': {'id': '53', 'type': 'weakness', 'attributes': {'name': 'Open Redirect', 'description': 'A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.', 'created_at': '2017-01-05T01:51:19.000Z'}}}, 'activities': {'data': []}, 'bounties': {'data': []}, 'summaries': {'data': []}}}  # noqa
openRedirectUnreproJson = {'id': '240035', 'type': 'report', 'attributes': {'title': 'malformed open redirect', 'state': 'new', 'created_at': '2017-06-14T23:39:08.069Z', 'vulnerability_information': 'this is detected as an open redirect but there is no markdown link to it\n\nhttps://example.com/redir.php?QUERY_STRING=https://google.com', 'triaged_at': None, 'closed_at': None, 'last_reporter_activity_at': '2017-06-14T23:39:08.132Z', 'first_program_activity_at': '2017-06-14T23:39:08.132Z', 'last_program_activity_at': '2017-06-14T23:39:08.132Z', 'bounty_awarded_at': None, 'swag_awarded_at': None, 'disclosed_at': None, 'last_public_activity_at': '2017-06-14T23:39:08.132Z', 'last_activity_at': '2017-06-14T23:39:09.175Z'}, 'relationships': {'reporter': {'data': {'id': '174347', 'type': 'user', 'attributes': {'username': 'reporter_username', 'name': 'John Doe', 'disabled': False, 'created_at': '2017-06-08T20:58:21.626Z', 'profile_picture': {'62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}}}}, 'program': {'data': {'id': '21806', 'type': 'program', 'attributes': {'handle': 'bot_testing_environment', 'created_at': '2017-06-14T21:22:38.050Z', 'updated_at': '2017-06-14T21:42:03.850Z'}}}, 'swag': {'data': []}, 'attachments': {'data': []}, 'weakness': {'data': {'id': '53', 'type': 'weakness', 'attributes': {'name': 'Open Redirect', 'description': 'A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.', 'created_at': '2017-01-05T01:51:19.000Z'}}}, 'activities': {'data': [{'type': 'activity-comment', 'id': '1756745', 'attributes': {'message': 'Hey there! [I am Hackbot](https://support.hackerone.com/hc/en-us/articles/204952469-What-is-Hackbot-), I help find possible duplicates and related reports. Here are my top suggestions:\n\n* (52%) Report [#239981](/reports/239981) by [reporter_username](/reporter_username) (new): open redirect (Jun 2017 - 35 minutes)\n\n', 'created_at': '2017-06-14T23:39:09.175Z', 'updated_at': '2017-06-14T23:39:09.175Z', 'internal': True}, 'relationships': {'actor': {'data': {'type': 'user', 'id': '20889', 'attributes': {'username': 'hackbot', 'name': '', 'disabled': False, 'created_at': '2015-04-21T14:15:00.516Z', 'profile_picture': {'62x62': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/d4e1fd3399b43d7555eba2cc7b21c48fa4ffb4ae_small.png?1429625702', '82x82': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/dd4834fa15b3684705d2af84f8f3acd23a52cd29_medium.png?1429625702', '110x110': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/8afcf976d18ed73dc799259ac5f80ab0f81f1f22_large.png?1429625702', '260x260': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/7df97703a6b5797e4e64373b9ee6b31a04f2e273_xtralarge.png?1429625702'}}}}}}]}, 'bounties': {'data': []}, 'summaries': {'data': []}}}  # noqa


@pytest.mark.openRedirect
@pytest.mark.fast
def test_match():
    r = ReportWrapper(openRedirectReproJson)
    assert openRedirect.match(r.getReportBody(), r.getReportWeakness())
    r = ReportWrapper(openRedirectUnreproJson)
    assert openRedirect.match(r.getReportBody(), r.getReportWeakness())


@pytest.mark.openRedirect
@pytest.mark.integration
def test_processUnstructured(monkeypatch):
    from AutoTriageBot.modules import openRedirect  # to clear out any monkey patching
    monkeypatch.setattr(openRedirect, 'isProgramURL', lambda u: True)
    monkeypatch.setattr(openRedirect.config, 'apiName', 'triagebot_username')
    monkeypatch.setattr(openRedirect.config, 'timeout', 1)  # To make the tests run faster
    report = ReportWrapper()
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    monkeypatch.setattr(report, 'botHasCommented', lambda: False)
    monkeypatch.setattr(openRedirect.AutoTriageUtils, 'generateToken', lambda: 'ABCDE')
    assert openRedirect.process(report) == VulnTestInfo(reproduced=False,
                                                        message=constants.initialMessage('ABCDE',
                                                                                         'redirect to a domain',
                                                                                         'Open Redirect'),
                                                        type='Open Redirect',
                                                        info={})
    monkeypatch.setattr(report, 'botHasCommented', lambda: True)
    monkeypatch.setattr(report, 'shouldBackoff', lambda: True)
    monkeypatch.setattr(report, 'hasPostedBackoffComment', lambda: False)
    monkeypatch.setattr(report, 'getReporterUsername', lambda: 'TestFailureUser')
    monkeypatch.setattr(report, 'getReportID', lambda: '-1')
    oldCount = sqlite.countFailures("TestFailureUser")
    assert openRedirect.process(report) == VulnTestInfo(reproduced=False,
                                                        message=('Automatic verification of vulnerability has failed, '
                                                                 'Backing off! '
                                                                 'Falling back to human verification. '),
                                                        type='Open Redirect',
                                                        info={})
    assert sqlite.countFailures("TestFailureUser") == (oldCount + 1)
    monkeypatch.setattr(report, 'hasPostedBackoffComment', lambda: True)
    assert openRedirect.process(report) is None
    monkeypatch.setattr(report, 'shouldBackoff', lambda: False)
    monkeypatch.setattr(report, 'getLatestActivity', lambda: "")
    monkeypatch.setattr(report, 'getToken', lambda: "XYZ")
    monkeypatch.setattr(report, 'isVerified', lambda: True)
    assert openRedirect.process(report) is None
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    assert (openRedirect.process(report) ==
            openRedirect.processUnstructured(report, token=report.getToken()) ==
            VulnTestInfo(reproduced=False,
                         message=constants.failedToFindURLsMessage,
                         type='Open Redirect',
                         info={'method': 'unstructured'}))
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/redir.php?q=http://XYZ.example.com/\n"
                                                              "```"))
    vti = openRedirect.process(report)
    assert vti.reproduced is True
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/noVulnerability.html"
                                                              "```\n"
                                                              "```\n"
                                                              "http://vulnserver/redir.php?q=http://XYZ.example.com/\n"
                                                              "```"))
    vti = openRedirect.process(report)
    assert openRedirect.process(report) == openRedirect.processUnstructured(report, token=report.getToken()) == vti
    assert vti.reproduced is True
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/redir.php?q=http://example.com/\n"
                                                              "```"))
    vti = openRedirect.process(report)
    assert vti.reproduced is False
    assert vti.message == (openRedirect.tokenNotFoundMessage %
                           ("http://vulnserver/redir.php?q=http://example.com/", 'http://example.com/', 'XYZ', 'XYZ'))


@pytest.mark.openRedirect
@pytest.mark.integration
def test_processStructured(monkeypatch):
    monkeypatch.setattr(openRedirect, 'isProgramURL', lambda u: True)
    monkeypatch.setattr(openRedirect.config, 'timeout', 1)  # To make the tests run faster
    report = ReportWrapper()
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    monkeypatch.setattr(openRedirect.AutoTriageUtils, 'generateToken', lambda: 'XYZ')
    monkeypatch.setattr(report, 'botHasCommented', lambda: True)
    monkeypatch.setattr(report, 'shouldBackoff', lambda: False)
    monkeypatch.setattr(report, 'getToken', lambda: "XYZ")
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{No JSON!}\n'
                                                              '```'))
    vti = openRedirect.process(report)
    assert vti.reproduced is False
    assert 'Failed to parse JSON! Please try again.' in vti.message
    monkeypatch.setattr(openRedirect, 'isProgramURL', lambda u: False)
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/redirIfCookie.php?q='
                                                              'http://XYZ.example.com/",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "get" \n'
                                                              '}\n'
                                                              '```\n\n'))
    vti = openRedirect.process(report)
    assert vti.reproduced is False
    assert 'is not a program URL!' in vti.message
    monkeypatch.setattr(openRedirect, 'isProgramURL', lambda u: True)
    vti = openRedirect.process(report)
    assert vti.reproduced is True
    assert 'Successfully found and confirmed an open redirect from' in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/redirIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "post", \n'
                                                              '    "data": {"q": "http://XYZ.example.com/"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = openRedirect.process(report)
    assert vti.reproduced is True
    assert 'Successfully found and confirmed an open redirect from' in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/redirIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "INVALID", \n'
                                                              '    "data": {"q": "http://XYZ.example.com/"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = openRedirect.process(report)
    assert vti.reproduced is False
    assert 'Found an invalid value' in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/redirIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "post", \n'
                                                              '    "data": {"q": "http://NOTOKEN.example.com/"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = openRedirect.process(report)
    assert vti.reproduced is False
    assert "Please resubmit with a link that will redirect to a URL containing the token" in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/redirIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "INCORRECT"}, \n'
                                                              '    "type": "post", \n'
                                                              '    "data": {"q": "http://XYZ.example.com/"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = openRedirect.process(report)
    assert vti.reproduced is False
    assert "wait for manual review of your bug" in vti.message
