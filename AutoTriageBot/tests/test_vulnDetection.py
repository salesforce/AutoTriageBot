"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot.modules import sqli, openRedirect, xss
import pytest


@pytest.mark.xss
@pytest.mark.integration
def test_xss():
    # Get:
    assert (xss.testGETXSS('http://vulnserver/xss.php?q=<script>alert("TEXT")</script>', {}) ==
            {'Firefox': 'TEXT', 'Chrome': None})
    assert (xss.testGETXSS('http://vulnserver/xss.php?q=<script>alert("ABCDE")</script>', {}) ==
            {'Firefox': 'ABCDE', 'Chrome': None})
    assert (xss.testGETXSS('http://vulnserver/xssIfCookie.php?q=<script>alert("TEXT")</script>', {'NAME': 'VALUE'}) ==
            {'Firefox': 'TEXT', 'Chrome': None})
    assert (xss.testGETXSS('http://vulnserver/xssIfCookie.php?q=<script>alert("TEXT")</script>', {'NAME': 'OTHER'}) ==
            {'Firefox': None, 'Chrome': None})
    assert xss.testGETXSS('http://vulnserver/noVulnerability.html', {}) == {'Firefox': None, 'Chrome': None}
    # Post:
    assert (xss.testPOSTXSS('http://vulnserver/xssPost.php', {}, {'q': '<script>alert("TEXT")</script>'}) ==
            {'Firefox': 'TEXT', 'Chrome': None})
    assert (xss.testPOSTXSS('http://vulnserver/xssPost.php', {}, {'q': '<script>alert("OTHER")</script>'}) ==
            {'Firefox': 'OTHER', 'Chrome': None})
    assert (xss.testPOSTXSS('http://vulnserver/xssPost.php', {}, {'q': '<b>HTML</b>'}) ==
            {'Firefox': None, 'Chrome': None})
    assert (xss.testPOSTXSS('http://vulnserver/xssIfCookiePost.php',
                            {'NAME': 'VALUE'},
                            {'q': '<script>alert("TEXT")</script>'}) ==
            {'Firefox': 'TEXT', 'Chrome': None})
    assert (xss.testPOSTXSS('http://vulnserver/xssIfCookiePost.php',
                            {'NAME': 'OTHER'},
                            {'q': '<script>alert("TEXT")</script>'}) ==
            {'Firefox': None, 'Chrome': None})
    # Prompt:
    assert (xss.testGETXSS('http://vulnserver/xss.php?q=<script>prompt("TEXT")</script>', {}) ==
            {'Firefox': 'TEXT', 'Chrome': None})


@pytest.mark.openRedirect
@pytest.mark.integration
def test_openRedirect(monkeypatch):
    monkeypatch.setattr(openRedirect.config, 'timeout', 1)  # Make the tests run faster
    # Get:
    assert (openRedirect.testGETOpenRedirect('http://vulnserver/redir.php?q=http://example.com/', {}) ==
            'http://example.com/')
    assert (openRedirect.testGETOpenRedirect('http://vulnserver/redir.php?q=http://example.org/', {}) ==
            'http://example.org/')
    assert (openRedirect.testGETOpenRedirect('http://vulnserver/redirIfCookie.php?q=http://example.com/',
                                             {'NAME': 'VALUE'})
            == 'http://example.com/')
    assert (openRedirect.testGETOpenRedirect('http://vulnserver/redirIfCookie.php?q=http://example.com/',
                                             {'NAME': 'OTHER'})
            is None)
    assert (openRedirect.testGETOpenRedirect('http://vulnserver/xss.php?q=<script>window.location = '
                                             '\'http://example.com\'</script>', {})
            == 'http://example.com/')
    assert openRedirect.testGETOpenRedirect('http://vulnserver/noVulnerability.html', {}) is None
    # Post:
    assert (openRedirect.testPOSTOpenRedirect('http://vulnserver/redirPost.php', {}, {'q': 'http://example.com/'}) ==
            'http://example.com/')
    assert (openRedirect.testPOSTOpenRedirect('http://vulnserver/redirPost.php', {}, {'q': 'http://example.org/'}) ==
            'http://example.org/')
    assert (openRedirect.testPOSTOpenRedirect('http://vulnserver/xssPost.php',
                                              {},
                                              {'q': '<script>window.location = \'http://example.com\'</script>'})
            == 'http://example.com/')
    assert openRedirect.testPOSTOpenRedirect('http://vulnserver/redirIfCookiePost.php',
                                             {'NAME': 'VALUE'},
                                             {'q': 'http://example.org/'}) == 'http://example.org/'
    assert openRedirect.testPOSTOpenRedirect('http://vulnserver/redirIfCookiePost.php',
                                             {'NAME': 'OTHER'},
                                             {'q': 'http://example.org/'}) is None


@pytest.mark.sqli
@pytest.mark.integration
def test_sqli():
    # Get:
    delay = sqli.testGETSQLDelay('http://vulnserver/sqli.php?q=10', {})
    assert delay > 10 and delay < 11
    delay = sqli.testGETSQLDelay('http://vulnserver/sqli.php?q=15', {})
    assert delay > 15 and delay < 16
    delay = sqli.testGETSQLDelay('http://vulnserver/sqliIfCookie.php?q=17', {'NAME': 'VALUE'})
    assert delay > 17 and delay < 18
    delay = sqli.testGETSQLDelay('http://vulnserver/sqliIfCookie.php?q=19', {'NAME': 'OTHER'})
    assert delay is None
    delay = sqli.testGETSQLDelay('http://vulnserver/sqli.php?q=0', {})
    assert delay is None
    delay = sqli.testGETSQLDelay('http://vulnserver/noVulnerability.html', {})
    assert delay is None
    # Post:
    delay = sqli.testPOSTSQLDelay('http://vulnserver/sqliPost.php', {}, {'q': '17'})
    assert delay > 17 and delay < 18
    delay = sqli.testPOSTSQLDelay('http://vulnserver/noVulnerability.html', {}, {'q': '17'})
    assert delay is None
    delay = sqli.testPOSTSQLDelay('http://vulnserver/sqliPost.php', {}, {'q': '0'})
    assert delay is None
    delay = sqli.testPOSTSQLDelay('http://vulnserver/sqliIfCookiePost.php',
                                  {'NAME': 'VALUE'},
                                  {'q': '8'})
    assert delay > 8 and delay < 9
    delay = sqli.testPOSTSQLDelay('http://vulnserver/sqliIfCookiePost.php',
                                  {'NAME': 'OTHER'},
                                  {'q': '8'})
    assert delay is None
