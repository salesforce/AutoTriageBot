"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import pytest
from AutoTriageBot.config import domains
from AutoTriageBot import AutoTriageUtils
from AutoTriageBot.AutoTriageUtils import extractDataFromJson, generateToken
from AutoTriageBot.DataTypes import URLParts


@pytest.mark.fast
def test_extractDataFromJson():
    assert extractDataFromJson({}) == ('', {}, 'GET', {})
    assert extractDataFromJson({'url': 'ABC'}) == ('ABC', {}, 'GET', {})
    assert extractDataFromJson({'URL': 'ABC'}) == ('ABC', {}, 'GET', {})
    assert extractDataFromJson({'cookies': {1: 2}}) == ('', {1: 2}, 'GET', {})
    assert extractDataFromJson({'COOKIES': {1: 2}}) == ('', {1: 2}, 'GET', {})
    assert extractDataFromJson({'type': 'ABC'}) == ('', {}, 'ABC', {})
    assert extractDataFromJson({'TYPE': 'ABC'}) == ('', {}, 'ABC', {})
    assert extractDataFromJson({'data': {1: 2}}) == ('', {}, 'GET', {1: 2})
    assert extractDataFromJson({'DATA': {1: 2}}) == ('', {}, 'GET', {1: 2})


@pytest.mark.fast
def test_isProgramURL(monkeypatch):
    if domains:
        for domain in domains:
            assert AutoTriageUtils.isProgramURL('http://%s/' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://subdomain.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://a.b.c.d.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('https://a.b.c.d.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('ftp://a.b.c.d.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://a.b.c.d.%s:8080/test/test.test?t=t' % domain, acceptAll=True)
            assert not AutoTriageUtils.isProgramURL('http://%s.example.com/test/test.test?t=t' % domain, acceptAll=True)
            assert not AutoTriageUtils.isProgramURL('http://localhost/test/test.test?t=t', acceptAll=True)
    else:
        monkeypatch.setattr(AutoTriageUtils.config, 'domains', ['test.test', 'example.test'])
        for domain in ['test.test', 'example.test']:
            assert AutoTriageUtils.isProgramURL('http://%s/' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://subdomain.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://a.b.c.d.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('https://a.b.c.d.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('ftp://a.b.c.d.%s/test/test.test?t=t' % domain, acceptAll=True)
            assert AutoTriageUtils.isProgramURL('http://a.b.c.d.%s:8080/test/test.test?t=t' % domain, acceptAll=True)
            assert not AutoTriageUtils.isProgramURL('http://%s.example.com/test/test.test?t=t' % domain, acceptAll=True)
            assert not AutoTriageUtils.isProgramURL('http://localhost/test/test.test?t=t', acceptAll=True)


@pytest.mark.fast
def test_generateToken():
    assert generateToken() != generateToken()


@pytest.mark.fast
def test_parseURL(monkeypatch):
    monkeypatch.setattr(AutoTriageUtils.config, 'hostnameSanitizers', {})
    assert AutoTriageUtils.parseURL("/justapath") == URLParts(domain='', path='/justapath', queries={})
    assert AutoTriageUtils.parseURL("http://user:pass@example.com/path?a=b&c=d#123") == URLParts(domain='example.com',
                                                                                                 path='/path',
                                                                                                 queries={'a': 'b',
                                                                                                          'c': 'd'})
    monkeypatch.setattr(AutoTriageUtils.config, 'hostnameSanitizers', {r'\d\.example\.com': 'NUM.example.com'})
    assert AutoTriageUtils.parseURL("https://1.example.com") == URLParts(domain='NUM.example.com',
                                                                         path='',
                                                                         queries={})
