"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import pytest
from AutoTriageBot.ReportWrapper import ReportWrapper
import datetime
from AutoTriageBot.tests.testUtils import Counter
from AutoTriageBot.DataTypes import VulnTestInfo
from AutoTriageBot.ReportWrapper import extractJson


@pytest.mark.fast
def test_verifyProcess(monkeypatch):
    from AutoTriageBot import verify
    time = datetime.datetime.now()
    monkeypatch.setattr(verify, 'postComment', Counter())
    report = ReportWrapper()
    monkeypatch.setattr(report, 'needsBotReply', lambda: False)
    assert verify.postComment.count == 0
    assert verify.processReport(report, time) is None
    assert verify.postComment.count == 0
    monkeypatch.setattr(report, 'needsBotReply', lambda: True)
    monkeypatch.setattr(report, 'getReportedTime', lambda: datetime.datetime.now())
    monkeypatch.setattr(verify.config, 'genesis', datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc))
    monkeypatch.setattr(verify.config, 'DEBUG', False)
    monkeypatch.setattr(report, 'getReportBody', lambda: "XSS report")
    monkeypatch.setattr(report, 'getReportTitle', lambda: "XSS report")
    monkeypatch.setattr(report, 'getReportWeakness', lambda: "XSS")
    monkeypatch.setattr(report, 'getReportID', lambda: '-1')
    vti = VulnTestInfo(reproduced=False,
                       message="VTI",
                       info={},
                       type='type')
    for module in verify.modules:
        monkeypatch.setattr(module, 'process', lambda r: vti)
        monkeypatch.setattr(module, 'match', lambda u, v: True)
    monkeypatch.setattr(report, 'needsBotReply', lambda: True)
    assert report.needsBotReply()
    assert verify.postComment.count == 0
    assert verify.processReport(report, time) == vti
    assert verify.postComment.count == 1
    assert verify.postComment.lastCall == (('-1', vti), {'addStopMessage': True})
    for module in verify.modules:
        monkeypatch.setattr(module, 'match', lambda b, w: False)
    assert verify.postComment.count == 1
    assert verify.processReport(report, time) is None
    assert verify.postComment.count == 1


@pytest.mark.fast
def test_metadataLogging(monkeypatch):
    from AutoTriageBot import verify
    mvti = VulnTestInfo(reproduced=True,
                        message='',
                        type='XSS',
                        info={'src': 'AAA',
                              'method': 'BBB',
                              'confirmedBrowsers': 'CCC',
                              'alertBrowsers': 'DDD',
                              'httpType': 'EEE',
                              'cookies': 'FFF'})
    r = ReportWrapper()
    monkeypatch.setattr(r, 'getReportID', lambda: 'GGG')
    monkeypatch.setattr(r, 'getReportTitle', lambda: 'HHH')
    monkeypatch.setattr(r, 'getReportedTime', lambda: 'III')
    ivti = verify.generateMetadataVTI(r, mvti)
    j = extractJson(ivti.message)

    def standardAsserts(j):
        assert j['id'] == 'GGG'
        assert j['title'] == 'HHH'
        assert j['reportedTime'] == 'III'
        assert 'verifiedTime' in j.keys()  # we can't monkeypatch datetime, so just checking that it exists
        assert j['exploitURL'] == 'AAA'
        assert j['method'] == 'BBB'
        assert j['httpType'] == 'EEE'
        assert j['cookies'] == 'FFF'
    # XSS:
    standardAsserts(j)
    assert j['type'] == 'XSS'
    assert j['confirmedBrowsers'] == 'CCC'
    assert j['alertBrowsers'] == 'DDD'
    # SQLi:
    mvti = VulnTestInfo(reproduced=True,
                        message='',
                        type='SQLi',
                        info={'src': 'AAA',
                              'method': 'BBB',
                              'delay': '12',
                              'httpType': 'EEE',
                              'cookies': 'FFF'})
    ivti = verify.generateMetadataVTI(r, mvti)
    j = extractJson(ivti.message)
    standardAsserts(j)
    assert j['type'] == 'SQLi'
    assert j['delay'] == '12'
    # Open Redirect:
    mvti = VulnTestInfo(reproduced=True,
                        message='',
                        type='Open Redirect',
                        info={'src': 'AAA',
                              'method': 'BBB',
                              'redirect': 'CCC',
                              'httpType': 'EEE',
                              'cookies': 'FFF'})
    ivti = verify.generateMetadataVTI(r, mvti)
    j = extractJson(ivti.message)
    standardAsserts(j)
    assert j['type'] == 'Open Redirect'
    assert j['redirect'] == 'CCC'
