"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot.modules import xss
from AutoTriageBot.AutoTriageUtils import VulnTestInfo
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot import constants
from AutoTriageBot import AutoTriageUtils
from AutoTriageBot import sqlite
import pytest

domXSSInitReport = {'id': '241366', 'attributes': {'last_reporter_activity_at': '2017-06-19T17:48:29.391Z', 'swag_awarded_at': None, 'first_program_activity_at': '2017-06-19T17:48:29.391Z', 'triaged_at': None, 'created_at': '2017-06-19T17:48:29.339Z', 'bounty_awarded_at': None, 'vulnerability_information': 'DOM XSS Report', 'last_public_activity_at': '2017-06-19T17:48:29.391Z', 'closed_at': None, 'last_program_activity_at': '2017-06-19T17:48:29.391Z', 'title': 'DOM XSS Report', 'disclosed_at': None, 'state': 'new', 'last_activity_at': '2017-06-19T17:48:30.763Z'}, 'type': 'report', 'relationships': {'reporter': {'data': {'id': '174347', 'attributes': {'name': 'John Doe', 'profile_picture': {'260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}, 'disabled': False, 'username': 'reporter_username', 'created_at': '2017-06-08T20:58:21.626Z'}, 'type': 'user'}}, 'summaries': {'data': []}, 'bounties': {'data': []}, 'attachments': {'data': []}, 'program': {'data': {'id': '21806', 'attributes': {'handle': 'bot_testing_environment', 'updated_at': '2017-06-15T05:01:01.528Z', 'created_at': '2017-06-14T21:22:38.050Z'}, 'type': 'program'}}, 'activities': {'data': [{'id': '1765874', 'attributes': {'message': 'Hey there! [I am Hackbot](https://support.hackerone.com/hc/en-us/articles/204952469-What-is-Hackbot-), I help find possible duplicates and related reports. Here are my top suggestions:\n\n* (73%) Report [#240625](/reports/240625) by [reporter_username](/reporter_username) (new): xss report (Jun 2017 - 3 days)\n* (55%) Report [#240853](/reports/240853) by [reporter_username](/reporter_username) (new): auth xss report (Jun 2017 - 3 days)\n\n', 'internal': True, 'updated_at': '2017-06-19T17:48:30.763Z', 'created_at': '2017-06-19T17:48:30.763Z'}, 'type': 'activity-comment', 'relationships': {'actor': {'data': {'id': '20889', 'attributes': {'name': '', 'profile_picture': {'260x260': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/7df97703a6b5797e4e64373b9ee6b31a04f2e273_xtralarge.png?1429625702', '62x62': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/d4e1fd3399b43d7555eba2cc7b21c48fa4ffb4ae_small.png?1429625702', '82x82': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/dd4834fa15b3684705d2af84f8f3acd23a52cd29_medium.png?1429625702', '110x110': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/8afcf976d18ed73dc799259ac5f80ab0f81f1f22_large.png?1429625702'}, 'disabled': False, 'username': 'hackbot', 'created_at': '2015-04-21T14:15:00.516Z'}, 'type': 'user'}}}}]}, 'weakness': {'data': {'id': '63', 'attributes': {'name': 'Cross-site Scripting (XSS) - DOM', 'description': 'In DOM-based XSS, the client performs the injection of XSS into the page; in the other types, the server performs the injection. DOM-based XSS generally involves server-controlled, trusted script that is sent to the client, such as Javascript that performs sanity checks on a form before the user submits it. If the server-supplied script processes user-supplied data and then injects it back into the web page (such as with dynamic HTML), then DOM-based XSS is possible.', 'created_at': '2017-01-05T01:51:19.000Z'}, 'type': 'weakness'}}, 'swag': {'data': []}}}  # noqa
genericXSSInitReport = {'id': '241367', 'attributes': {'last_reporter_activity_at': '2017-06-19T17:51:22.427Z', 'swag_awarded_at': None, 'first_program_activity_at': '2017-06-19T17:51:22.427Z', 'triaged_at': None, 'created_at': '2017-06-19T17:51:22.383Z', 'bounty_awarded_at': None, 'vulnerability_information': 'Generic ___ Report', 'last_public_activity_at': '2017-06-19T17:51:22.427Z', 'closed_at': None, 'last_program_activity_at': '2017-06-19T17:51:22.427Z', 'title': 'Generic ___ Report', 'disclosed_at': None, 'state': 'new', 'last_activity_at': '2017-06-19T17:51:22.427Z'}, 'type': 'report', 'relationships': {'reporter': {'data': {'id': '174347', 'attributes': {'name': 'John Doe', 'profile_picture': {'260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}, 'disabled': False, 'username': 'reporter_username', 'created_at': '2017-06-08T20:58:21.626Z'}, 'type': 'user'}}, 'summaries': {'data': []}, 'bounties': {'data': []}, 'attachments': {'data': []}, 'program': {'data': {'id': '21806', 'attributes': {'handle': 'bot_testing_environment', 'updated_at': '2017-06-15T05:01:01.528Z', 'created_at': '2017-06-14T21:22:38.050Z'}, 'type': 'program'}}, 'activities': {'data': []}, 'weakness': {'data': {'id': '60', 'attributes': {'name': 'Cross-site Scripting (XSS) - Generic', 'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.', 'created_at': '2017-01-05T01:51:19.000Z'}, 'type': 'weakness'}}, 'swag': {'data': []}}}  # noqa
reflectedXSSInitReport = {'relationships': {'summaries': {'data': []}, 'weakness': {'data': {'attributes': {'description': "The server reads data directly from the HTTP request and reflects it back in the HTTP response. Reflected XSS exploits occur when an attacker causes a victim to supply dangerous content to a vulnerable web application, which is then reflected back to the victim and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or e-mailed directly to the victim. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces a victim to visit a URL that refers to a vulnerable site. After the site reflects the attacker's content back to the victim, the content is executed by the victim's browser.", 'name': 'Cross-site Scripting (XSS) - Reflected', 'created_at': '2017-01-05T01:51:19.000Z'}, 'id': '61', 'type': 'weakness'}}, 'bounties': {'data': []}, 'reporter': {'data': {'attributes': {'disabled': False, 'name': 'John Doe', 'created_at': '2017-06-08T20:58:21.626Z', 'username': 'reporter_username', 'profile_picture': {'260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}}, 'id': '174347', 'type': 'user'}}, 'activities': {'data': []}, 'attachments': {'data': []}, 'swag': {'data': []}, 'program': {'data': {'attributes': {'handle': 'bot_testing_environment', 'created_at': '2017-06-14T21:22:38.050Z', 'updated_at': '2017-06-15T05:01:01.528Z'}, 'id': '21806', 'type': 'program'}}}, 'attributes': {'triaged_at': None, 'title': 'Reflected ___ Report', 'state': 'new', 'created_at': '2017-06-19T17:56:18.970Z', 'last_program_activity_at': '2017-06-19T17:56:19.005Z', 'last_reporter_activity_at': '2017-06-19T17:56:19.005Z', 'bounty_awarded_at': None, 'last_activity_at': '2017-06-19T17:56:19.005Z', 'disclosed_at': None, 'vulnerability_information': 'Reflected __ Report', 'swag_awarded_at': None, 'last_public_activity_at': '2017-06-19T17:56:19.005Z', 'first_program_activity_at': '2017-06-19T17:56:19.005Z', 'closed_at': None}, 'id': '241368', 'type': 'report'}  # noqa
storedXSSInitReport = {'relationships': {'summaries': {'data': []}, 'weakness': {'data': {'attributes': {'description': "The application stores dangerous data in a database, message forum, visitor log, or other trusted data store. At a later time, the dangerous data is subsequently read back into the application and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user. For example, the attacker might inject XSS into a log message, which might not be handled properly when an administrator views the logs.", 'name': 'Cross-site Scripting (XSS) - Stored', 'created_at': '2017-01-05T01:51:19.000Z'}, 'id': '62', 'type': 'weakness'}}, 'bounties': {'data': []}, 'reporter': {'data': {'attributes': {'disabled': False, 'name': 'John Doe', 'created_at': '2017-06-08T20:58:21.626Z', 'username': 'reporter_username', 'profile_picture': {'260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}}, 'id': '174347', 'type': 'user'}}, 'activities': {'data': []}, 'attachments': {'data': []}, 'swag': {'data': []}, 'program': {'data': {'attributes': {'handle': 'bot_testing_environment', 'created_at': '2017-06-14T21:22:38.050Z', 'updated_at': '2017-06-15T05:01:01.528Z'}, 'id': '21806', 'type': 'program'}}}, 'attributes': {'triaged_at': None, 'title': 'Stored ___ Report', 'state': 'new', 'created_at': '2017-06-19T17:57:50.342Z', 'last_program_activity_at': '2017-06-19T17:57:50.395Z', 'last_reporter_activity_at': '2017-06-19T17:57:50.395Z', 'bounty_awarded_at': None, 'last_activity_at': '2017-06-19T17:57:50.395Z', 'disclosed_at': None, 'vulnerability_information': 'Stored ___ Report', 'swag_awarded_at': None, 'last_public_activity_at': '2017-06-19T17:57:50.395Z', 'first_program_activity_at': '2017-06-19T17:57:50.395Z', 'closed_at': None}, 'id': '241369', 'type': 'report'}  # noqa


@pytest.mark.xss
@pytest.mark.fast
def test_match():
    assert xss.match(ReportWrapper(domXSSInitReport).getReportBody(),
                     ReportWrapper(domXSSInitReport).getReportWeakness())
    assert xss.match(ReportWrapper(genericXSSInitReport).getReportBody(),
                     ReportWrapper(genericXSSInitReport).getReportWeakness())
    assert xss.match(ReportWrapper(reflectedXSSInitReport).getReportBody(),
                     ReportWrapper(reflectedXSSInitReport).getReportWeakness())
    assert xss.match(ReportWrapper(storedXSSInitReport).getReportBody(),
                     ReportWrapper(storedXSSInitReport).getReportWeakness())


@pytest.mark.xss
@pytest.mark.integration
def test_processUnstructured(monkeypatch):
    monkeypatch.setattr(xss.AutoTriageUtils, 'isProgramURL', lambda u: True)
    r = ReportWrapper(domXSSInitReport)
    monkeypatch.setattr(r, 'isVerified', lambda: False)
    monkeypatch.setattr(AutoTriageUtils, 'generateToken', lambda: 'ABCDE')
    assert xss.process(r) == VulnTestInfo(reproduced=False,
                                          info={},
                                          message=constants.initialMessage('ABCDE', 'pop up an alert box', 'XSS'),
                                          type='XSS')
    report = ReportWrapper()
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    monkeypatch.setattr(report, 'botHasCommented', lambda: False)
    assert xss.process(report) == VulnTestInfo(reproduced=False,
                                               message=constants.initialMessage('ABCDE', 'pop up an alert box', 'XSS'),
                                               type='XSS',
                                               info={})
    monkeypatch.setattr(report, 'botHasCommented', lambda: True)
    monkeypatch.setattr(report, 'shouldBackoff', lambda: True)
    monkeypatch.setattr(report, 'hasPostedBackoffComment', lambda: False)
    monkeypatch.setattr(report, 'getReporterUsername', lambda: 'TestFailureUser')
    monkeypatch.setattr(report, 'getReportID', lambda: '-1')
    oldCount = sqlite.countFailures("TestFailureUser")
    assert xss.process(report) == VulnTestInfo(reproduced=False,
                                               message=('Automatic verification of vulnerability has failed, Backing '
                                                        'off! Falling '
                                                        'back to human verification. '),
                                               type='XSS',
                                               info={})
    assert sqlite.countFailures("TestFailureUser") == (oldCount + 1)
    monkeypatch.setattr(report, 'hasPostedBackoffComment', lambda: True)
    assert xss.process(report) is None
    monkeypatch.setattr(report, 'shouldBackoff', lambda: False)
    monkeypatch.setattr(report, 'getLatestActivity', lambda: "")
    monkeypatch.setattr(report, 'getToken', lambda: "ABCDE")
    monkeypatch.setattr(report, 'isVerified', lambda: True)
    assert xss.process(report) is None
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    assert (xss.process(report) == xss.processUnstructured(report, token=report.getToken()) ==
            VulnTestInfo(reproduced=False,
                         message=constants.failedToFindURLsMessage,
                         type='XSS',
                         info={'method': 'unstructured'}))
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```"
                                                              "http://vulnserver/xss.php?q="
                                                              "<script>alert(\"ABCDE\")</script>"
                                                              "```"))
    vti = xss.process(report)
    assert xss.process(report) == xss.processUnstructured(report, token=report.getToken()) == vti
    assert vti.reproduced is True
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/noVulnerability.html"
                                                              "```\n"
                                                              "```\n"
                                                              "http://vulnserver/xss.php?q="
                                                              "<script>alert(\"ABCDE\")</script>\n"
                                                              "```"))
    vti = xss.process(report)
    assert xss.process(report) == xss.processUnstructured(report, token=report.getToken()) == vti
    assert vti.reproduced is True
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/xss.php?q="
                                                              "<script>alert(\"WRONG\")</script>\n"
                                                              "```"))
    vti = xss.process(report)
    assert vti.reproduced is False
    assert 'Failed to confirm the vulnerability! Detected an alert' in vti.message


@pytest.mark.xss
@pytest.mark.integration
def test_processStructured(monkeypatch):
    monkeypatch.setattr(xss.AutoTriageUtils, 'isProgramURL', lambda u: True)
    r = ReportWrapper()
    monkeypatch.setattr(r, 'isVerified', lambda: False)
    monkeypatch.setattr(r, 'botHasCommented', lambda: False)
    monkeypatch.setattr(xss.AutoTriageUtils, 'generateToken', lambda: 'ABCDE')
    vti = xss.process(r)
    assert vti.reproduced is False
    assert 'We have detected that this report is about' in vti.message
    monkeypatch.setattr(r, 'botHasCommented', lambda: True)
    monkeypatch.setattr(r, 'shouldBackoff', lambda: True)
    monkeypatch.setattr(r, 'hasPostedBackoffComment', lambda: False)
    monkeypatch.setattr(r, 'getReporterUsername', lambda: 'TestFailureUser')
    monkeypatch.setattr(r, 'getReportID', lambda: '-1')
    vti = xss.process(r)
    assert vti.reproduced is False
    assert vti.message == ('Automatic verification of vulnerability has failed, Backing off! '
                           'Falling back to human verification. ')
    monkeypatch.setattr(r, 'hasPostedBackoffComment', lambda: True)
    vti = xss.process(r)
    assert vti is None
    monkeypatch.setattr(r, 'shouldBackoff', lambda: False)
    monkeypatch.setattr(r, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                         '{Not Json!}'))
    monkeypatch.setattr(r, 'getToken', lambda: 'ABCDE')
    vti = xss.process(r)
    assert vti.reproduced is False
    assert 'Failed to parse JSON! Please try again.' in vti.message
    monkeypatch.setattr(r, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                         '```\n'
                                                         '{\n'
                                                         '    "URL": "http://vulnserver/xssIfCookie.php?q='
                                                         '<script>alert(\'ABCDE\')</script>",\n'
                                                         '    "cookies": {"NAME":   "VALUE"}, \n'
                                                         '    "type": "get" \n'
                                                         '}\n'
                                                         '```\n\n'))
    monkeypatch.setattr(xss.AutoTriageUtils, 'isProgramURL', lambda u: False)
    vti = xss.process(r)
    assert vti.reproduced is False
    assert 'not a program URL!' in vti.message
    monkeypatch.setattr(xss.AutoTriageUtils, 'isProgramURL', lambda u: True)
    assert (xss.testGETXSS('http://vulnserver/xssIfCookie.php?q=<script>alert(\'ABCDE\')</script>',
                           {'NAME': 'VALUE'}) ==
            {'Firefox': 'ABCDE', 'Chrome': None})
    vti = xss.process(r)
    assert vti.reproduced is True
    assert 'Successfully found and confirmed an XSS' in vti.message
    assert 'XSS confirmed working!' in vti.message
    monkeypatch.setattr(r, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                         '```\n'
                                                         '{\n'
                                                         '    "URL": "http://vulnserver/xssIfCookie.php?q='
                                                         '<script>alert(\'ABCDE\')</script>",\n'
                                                         '    "cookies": {"NAME":   "VALUE"}, \n'
                                                         '    "type": "INVALID" \n'
                                                         '}\n'
                                                         '```\n\n'))
    vti = xss.process(r)
    assert vti.reproduced is False
    assert 'Found an invalid value' in vti.message
    monkeypatch.setattr(r, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                         '```\n'
                                                         '{\n'
                                                         '    "URL": "http://vulnserver/xssIfCookiePost.php",\n'
                                                         '    "cookies": {"NAME": "VALUE"}, \n'
                                                         '    "type": "post", \n'
                                                         '    "data": {"q": "<script>alert(\'ABCDE\')</script>"} \n'
                                                         '}\n'
                                                         '```\n'))
    vti = xss.process(r)
    assert vti.reproduced is True
    assert 'Successfully found and confirmed an XSS' in vti.message
    assert 'XSS confirmed working!' in vti.message
    monkeypatch.setattr(r, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                         '```\n'
                                                         '{\n'
                                                         '    "URL": "http://vulnserver/xssIfCookiePost.php",\n'
                                                         '    "cookies": {"NAME": "VALUE"}, \n'
                                                         '    "type": "post", \n'
                                                         '    "data": {"q": "<script>alert(\'NOTOKEN\')</script>"} \n'
                                                         '}\n'
                                                         '```\n'))
    vti = xss.process(r)
    assert vti.reproduced is False
    assert 'Failed to confirm the vulnerability! Detected an alert box but the token' in vti.message
    monkeypatch.setattr(r, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                         '```\n'
                                                         '{\n'
                                                         '    "URL": "http://vulnserver/xssIfCookiePost.php",\n'
                                                         '    "cookies": {"NAME": "WRONG"}, \n'
                                                         '    "type": "post", \n'
                                                         '    "data": {"q": "<script>alert(\'ABCDE\')</script>"} \n'
                                                         '}\n'
                                                         '```\n'))
    vti = xss.process(r)
    assert vti.reproduced is False
    assert "Either try again or wait for manual review of your bug" in vti.message


@pytest.mark.fast
def test_makeMarkdownTable():
    results = {'Browser A': 'ABC',
               'Browser B': 'XYZ',
               'Browser C': None}
    token = 'ABC'
    reproduced, alertBox, message, confirmedBrowsers, alertBrowsers = xss.makeMarkdownTable(results, token)
    assert reproduced is True
    assert alertBox is True
    assert confirmedBrowsers == ['Browser A']
    assert 'Browser B' in alertBrowsers and 'Browser A' in alertBrowsers
    assert 'XSS confirmed working!' in message
    assert 'Found an alert box, but no token found!' in message
    assert 'No alert box found' in message

    results = {'Browser B': 'XYZ',
               'Browser C': None}
    reproduced, alertBox, message, confirmedBrowsers, alertBrowsers = xss.makeMarkdownTable(results, token)
    assert reproduced is False
    assert alertBox is True
    assert confirmedBrowsers == []
    assert alertBrowsers == ['Browser B']
    assert 'XSS confirmed working!' not in message
    assert 'Found an alert box, but no token found!' in message
    assert 'No alert box found' in message

    results = {'Browser C': None}
    reproduced, alertBox, message, confirmedBrowsers, alertBrowsers = xss.makeMarkdownTable(results, token)
    assert reproduced is False
    assert alertBox is False
    assert confirmedBrowsers == []
    assert alertBrowsers == []
    assert 'XSS confirmed working!' not in message
    assert 'Found an alert box, but no token found!' not in message
    assert 'No alert box found' in message
