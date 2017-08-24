"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot import AutoTriageBot
# from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot import sqlite
import pytest
from AutoTriageBot.tests.conftest import backupDB


@pytest.mark.fast
def test_shouldProcessReport(monkeypatch):
    pass
    # report = ReportWrapper()
    # monkeypatch.setattr(report, 'getReporterUsername', lambda: 'ReporterName')
    #
    # monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', False)
    # monkeypatch.setattr(AutoTriageBot.config, 'whitelistedUsernames', False)
    # assert AutoTriageBot.shouldProcessReport(report) is True
    # monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', [])
    # assert AutoTriageBot.shouldProcessReport(report)


@pytest.mark.fast
def test_shouldProcess_blacklist(monkeypatch):
    monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', [])
    assert AutoTriageBot.shouldProcess_blacklist('ReporterName') is True
    monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', ['JohnDoe'])
    assert AutoTriageBot.shouldProcess_blacklist('ReporterName') is True
    monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', ['ReporterName'])
    assert AutoTriageBot.shouldProcess_blacklist('ReporterName') is False
    monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', ['REPORTERNAME'])
    assert AutoTriageBot.shouldProcess_blacklist('ReporterName') is False
    monkeypatch.setattr(AutoTriageBot.config, 'blacklistedUsernames', False)
    assert AutoTriageBot.shouldProcess_blacklist('ReporterName') is True


@pytest.mark.fast
def test_shouldProcess_whitelist(monkeypatch):
    monkeypatch.setattr(AutoTriageBot.config, 'whitelistedUsernames', [])
    assert AutoTriageBot.shouldProcess_whitelist('ReporterName') is False
    monkeypatch.setattr(AutoTriageBot.config, 'whitelistedUsernames', ['JohnDoe'])
    assert AutoTriageBot.shouldProcess_whitelist('ReporterName') is False
    monkeypatch.setattr(AutoTriageBot.config, 'whitelistedUsernames', ['ReporterName'])
    assert AutoTriageBot.shouldProcess_whitelist('ReporterName') is True
    monkeypatch.setattr(AutoTriageBot.config, 'whitelistedUsernames', ['REPORTERNAME'])
    assert AutoTriageBot.shouldProcess_whitelist('ReporterName') is True
    monkeypatch.setattr(AutoTriageBot.config, 'whitelistedUsernames', False)
    assert AutoTriageBot.shouldProcess_whitelist('ReporterName') is True


@pytest.mark.fast
def test_shouldProcess_failures(monkeypatch):
    backupDB()
    monkeypatch.setattr(AutoTriageBot.config, 'allowedFailures', 3)
    assert sqlite.countFailures("ReporterName") == 0
    assert AutoTriageBot.shouldProcess_failures("ReporterName") is True
    sqlite.addFailureToDB("ReporterName", '1')
    sqlite.addFailureToDB("REPORTERNAME", '2')
    assert sqlite.countFailures("reportername") == 2
    assert AutoTriageBot.shouldProcess_failures("ReporterName") is True
    sqlite.addFailureToDB("reportername", '3')
    assert sqlite.countFailures("reportername") == 3
    assert AutoTriageBot.shouldProcess_failures("ReporterName") is False
    monkeypatch.setattr(AutoTriageBot.config, 'allowedFailures', False)
    assert isinstance(AutoTriageBot.config.allowedFailures, bool)
    assert AutoTriageBot.shouldProcess_failures("ReporterName") is True
