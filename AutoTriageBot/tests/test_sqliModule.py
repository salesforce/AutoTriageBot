"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot.modules import sqli
from AutoTriageBot import constants
from AutoTriageBot.AutoTriageUtils import VulnTestInfo
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot import sqlite
import pytest


@pytest.mark.sqli
@pytest.mark.fast
def test_match():
    assert not sqli.match("", "")
    assert sqli.match("sqli", "")
    assert sqli.match("", "SQL Injection")
    assert sqli.match("sql injection", "")


@pytest.mark.sqli
@pytest.mark.integration
def test_processUnstructured(monkeypatch):
    monkeypatch.setattr(sqli, 'isProgramURL', lambda u: True)
    report = ReportWrapper()
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    monkeypatch.setattr(report, 'botHasCommented', lambda: False)
    monkeypatch.setattr(sqli, 'getRandInt', lambda: '12')
    assert sqli.process(report) == VulnTestInfo(reproduced=False,
                                                message=sqli.initialMessage % ('12', '12', '12'),
                                                type='SQLi',
                                                info={})
    monkeypatch.setattr(report, 'botHasCommented', lambda: True)
    monkeypatch.setattr(report, 'shouldBackoff', lambda: True)
    monkeypatch.setattr(report, 'hasPostedBackoffComment', lambda: False)
    monkeypatch.setattr(report, 'getReporterUsername', lambda: 'TestFailureUser')
    monkeypatch.setattr(report, 'getReportID', lambda: '-1')
    oldCount = sqlite.countFailures("TestFailureUser")
    assert sqli.process(report) == VulnTestInfo(reproduced=False,
                                                message=('Automatic verification of vulnerability has failed, Backing '
                                                         'off! Falling '
                                                         'back to human verification. '),
                                                type='SQLi',
                                                info={})
    assert sqlite.countFailures("TestFailureUser") == (oldCount + 1)
    monkeypatch.setattr(report, 'hasPostedBackoffComment', lambda: True)
    assert sqli.process(report) is None
    monkeypatch.setattr(report, 'shouldBackoff', lambda: False)
    monkeypatch.setattr(report, 'getLatestActivity', lambda: "")
    monkeypatch.setattr(report, 'getToken', lambda: "12")
    monkeypatch.setattr(report, 'isVerified', lambda: True)
    assert sqli.process(report) is None
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    assert (sqli.process(report) == sqli.processUnstructured(report, token=report.getToken()) ==
            VulnTestInfo(reproduced=False,
                         message=constants.failedToFindURLsMessage,
                         type='SQLi',
                         info={'method': 'unstructured'}))
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/sqli.php?q=12\n"
                                                              "```"))
    vti = sqli.process(report)
    assert vti.reproduced is True
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/noVulnerability.html"
                                                              "```\n"
                                                              "```\n"
                                                              "http://vulnserver/sqli.php?q=12\n"
                                                              "```"))
    vti = sqli.process(report)
    assert sqli.process(report) == sqli.processUnstructured(report, token=report.getToken()) == vti
    assert vti.reproduced is True
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ("```\n"
                                                              "http://vulnserver/sqli.php?q=15\n"
                                                              "```"))
    vti = sqli.process(report)
    assert vti.reproduced is False
    assert vti.message == (sqli.wrongDelayMessage % ('15', '12', '12'))


@pytest.mark.sqli
@pytest.mark.integration
def test_processStructured(monkeypatch):
    monkeypatch.setattr(sqli, 'isProgramURL', lambda u: True)
    report = ReportWrapper()
    monkeypatch.setattr(report, 'isVerified', lambda: False)
    monkeypatch.setattr(sqli, 'getRandInt', lambda: '12')
    monkeypatch.setattr(report, 'botHasCommented', lambda: True)
    monkeypatch.setattr(report, 'shouldBackoff', lambda: False)
    monkeypatch.setattr(report, 'getLatestActivity', lambda: "")
    monkeypatch.setattr(report, 'getToken', lambda: "12")
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{No JSON!}'
                                                              '```\n\n'))
    vti = sqli.process(report)
    assert vti.reproduced is False
    assert 'Failed to parse JSON! Please try again.' in vti.message
    monkeypatch.setattr(sqli, 'isProgramURL', lambda u: False)
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/sqliIfCookie.php?q=12",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "get" \n'
                                                              '}\n'
                                                              '```\n\n'))
    vti = sqli.process(report)
    assert vti.reproduced is False
    assert 'is not a program URL!' in vti.message
    monkeypatch.setattr(sqli, 'isProgramURL', lambda u: True)
    assert 12 < sqli.testGETSQLDelay('http://vulnserver/sqliIfCookie.php?q=12', {'NAME': 'VALUE'}) < 13
    vti = sqli.process(report)
    assert vti.reproduced is True
    assert 'Successfully found and confirmed SQLi at' in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/sqliIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "post", \n'
                                                              '    "data": {"q": "12"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = sqli.process(report)
    assert vti.reproduced is True
    assert 'Successfully found and confirmed SQLi at' in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/sqliIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "INVALID", \n'
                                                              '    "data": {"q": "12"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = sqli.process(report)
    assert vti.reproduced is False
    assert 'Found an invalid value' in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/sqliIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "VALUE"}, \n'
                                                              '    "type": "post", \n'
                                                              '    "data": {"q": "18"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = sqli.process(report)
    assert vti.reproduced is False
    assert "In order to verify the vulnerability, it must have delayed for" in vti.message
    monkeypatch.setattr(report, 'getLatestActivity', lambda: ('# AutoTriage Structured Data: \n'
                                                              '```\n'
                                                              '{\n'
                                                              '    "URL": "http://vulnserver/sqliIfCookiePost.php",\n'
                                                              '    "cookies": {"NAME": "WRONG"}, \n'
                                                              '    "type": "post", \n'
                                                              '    "data": {"q": "12"} \n'
                                                              '}\n'
                                                              '```\n'))
    vti = sqli.process(report)
    assert vti.reproduced is False
    assert "Failed to validate SQLi at" in vti.message
