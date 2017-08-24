"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import pytest
from AutoTriageBot.ReportWrapper import ReportWrapper, extractJson, fuzzyJsonParse, isStructured, extractURLs, getLinks
from typing import List, Any, Tuple

openRedirectReproJson = {'id': '239981', 'type': 'report', 'attributes': {'title': 'open redirect', 'state': 'new', 'created_at': '2017-06-14T23:03:51.775Z', 'vulnerability_information': 'blah open_redirect\n\n[some](http://example.com/redir.php?QUERY_STRING=https://google.com)', 'triaged_at': None, 'closed_at': None, 'last_reporter_activity_at': '2017-06-14T23:03:51.843Z', 'first_program_activity_at': '2017-06-14T23:03:51.843Z', 'last_program_activity_at': '2017-06-14T23:03:51.843Z', 'bounty_awarded_at': None, 'swag_awarded_at': None, 'disclosed_at': None, 'last_public_activity_at': '2017-06-14T23:03:51.843Z', 'last_activity_at': '2017-06-14T23:03:51.843Z'}, 'relationships': {'reporter': {'data': {'id': '174347', 'type': 'user', 'attributes': {'username': 'reporter_username', 'name': 'John Doe', 'disabled': False, 'created_at': '2017-06-08T20:58:21.626Z', 'profile_picture': {'62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}}}}, 'program': {'data': {'id': '21806', 'type': 'program', 'attributes': {'handle': 'bot_testing_environment', 'created_at': '2017-06-14T21:22:38.050Z', 'updated_at': '2017-06-14T21:42:03.850Z'}}}, 'swag': {'data': []}, 'attachments': {'data': []}, 'weakness': {'data': {'id': '53', 'type': 'weakness', 'attributes': {'name': 'Open Redirect', 'description': 'A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.', 'created_at': '2017-01-05T01:51:19.000Z'}}}, 'activities': {'data': []}, 'bounties': {'data': []}, 'summaries': {'data': []}}}  # noqa
openRedirectUnreproJson = {'id': '240035', 'type': 'report', 'attributes': {'title': 'malformed open redirect', 'state': 'new', 'created_at': '2017-06-14T23:39:08.069Z', 'vulnerability_information': 'this is detected as an open redirect but there is no markdown link to it\n\nhttps://example.com/redir.php?QUERY_STRING=https://google.com', 'triaged_at': None, 'closed_at': None, 'last_reporter_activity_at': '2017-06-14T23:39:08.132Z', 'first_program_activity_at': '2017-06-14T23:39:08.132Z', 'last_program_activity_at': '2017-06-14T23:39:08.132Z', 'bounty_awarded_at': None, 'swag_awarded_at': None, 'disclosed_at': None, 'last_public_activity_at': '2017-06-14T23:39:08.132Z', 'last_activity_at': '2017-06-14T23:39:09.175Z'}, 'relationships': {'reporter': {'data': {'id': '174347', 'type': 'user', 'attributes': {'username': 'reporter_username', 'name': 'John Doe', 'disabled': False, 'created_at': '2017-06-08T20:58:21.626Z', 'profile_picture': {'62x62': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '82x82': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '110x110': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png', '260x260': '/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png'}}}}, 'program': {'data': {'id': '21806', 'type': 'program', 'attributes': {'handle': 'bot_testing_environment', 'created_at': '2017-06-14T21:22:38.050Z', 'updated_at': '2017-06-14T21:42:03.850Z'}}}, 'swag': {'data': []}, 'attachments': {'data': []}, 'weakness': {'data': {'id': '53', 'type': 'weakness', 'attributes': {'name': 'Open Redirect', 'description': 'A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.', 'created_at': '2017-01-05T01:51:19.000Z'}}}, 'activities': {'data': [{'type': 'activity-comment', 'id': '1756745', 'attributes': {'message': 'Hey there! [I am Hackbot](https://support.hackerone.com/hc/en-us/articles/204952469-What-is-Hackbot-), I help find possible duplicates and related reports. Here are my top suggestions:\n\n* (52%) Report [#239981](/reports/239981) by [reporter_username](/reporter_username) (new): open redirect (Jun 2017 - 35 minutes)\n\n', 'created_at': '2017-06-14T23:39:09.175Z', 'updated_at': '2017-06-14T23:39:09.175Z', 'internal': True}, 'relationships': {'actor': {'data': {'type': 'user', 'id': '20889', 'attributes': {'username': 'hackbot', 'name': '', 'disabled': False, 'created_at': '2015-04-21T14:15:00.516Z', 'profile_picture': {'62x62': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/d4e1fd3399b43d7555eba2cc7b21c48fa4ffb4ae_small.png?1429625702', '82x82': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/dd4834fa15b3684705d2af84f8f3acd23a52cd29_medium.png?1429625702', '110x110': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/8afcf976d18ed73dc799259ac5f80ab0f81f1f22_large.png?1429625702', '260x260': 'https://profile-photos.hackerone-user-content.com/production/000/020/889/7df97703a6b5797e4e64373b9ee6b31a04f2e273_xtralarge.png?1429625702'}}}}}}]}, 'bounties': {'data': []}, 'summaries': {'data': []}}}  # noqa


@pytest.mark.fast
def test_ReportWrapperGetters():
    r = ReportWrapper(openRedirectReproJson)
    assert r.getReportID() == '239981'
    assert r.getLatestActivity() == ("blah open_redirect\n\n[some](http://example.com/redir.php?QUERY_STRING="
                                     "https://google.com)")
    assert r.getReportBody() == ("blah open_redirect\n\n[some](http://example.com/redir.php?QUERY_STRING="
                                 "https://google.com)")
    assert r.getReportWeakness() == "Open Redirect"
    assert r.getReportTitle() == "open redirect"
    assert r.getVulnDomains() == ['example.com']
    r = ReportWrapper(openRedirectUnreproJson)
    assert r.getReportID() == '240035'
    assert r.getLatestActivity() == ("this is detected as an open redirect but there is no markdown link to it\n\n"
                                     "https://example.com/redir.php?QUERY_STRING=https://google.com")
    assert r.getReportBody() == ("this is detected as an open redirect but there is no markdown link to it\n\n"
                                 "https://example.com/redir.php?QUERY_STRING=https://google.com")
    assert r.getReportWeakness() == "Open Redirect"
    assert r.getReportTitle() == "malformed open redirect"
    assert r.getVulnDomains() == ['example.com']


@pytest.mark.fast
def test_serialization():
    r = ReportWrapper(openRedirectReproJson)
    results = callAllMethods(r)
    rNew = ReportWrapper()
    rNew.deserialize(r.serialize())
    newResults = callAllMethods(rNew)
    assert results == newResults

    r = ReportWrapper(openRedirectUnreproJson)
    results = callAllMethods(r)
    rNew = ReportWrapper()
    rNew.deserialize(r.serialize())
    newResults = callAllMethods(rNew)
    assert results == newResults


def callAllMethods(obj: object) -> List[Tuple[str, Any]]:
    results = []  # type: List[Tuple[str, Any]]
    for method in dir(obj):
        if method == '__hash__':
            continue
        if callable(getattr(obj, method)):
            try:
                res = getattr(obj, method)()
                if isinstance(res, bool) or isinstance(res, int):
                    results.append((method, res))
                if isinstance(res, str):
                    # Ignore anything with 0x in it since memory addresses change
                    if '0x' not in res:
                        results.append((method, res))
            except:
                if '0x' not in method:
                    results.append(('except', method))
    return results


@pytest.mark.fast
def test_isVerified(monkeypatch):
    r = ReportWrapper()
    monkeypatch.setattr(r, '_ReportWrapper__getBody', lambda a: a)
    monkeypatch.setattr(r, '_getPublicCommentsByUsername', lambda u: ['Comment 1', 'Comment 2'])
    monkeypatch.setattr(r, 'getState', lambda: "new")
    assert r.isVerified() is False
    monkeypatch.setattr(r, 'getState', lambda: "triaged")
    assert r.isVerified() is True
    monkeypatch.setattr(r, 'getState', lambda: "new")
    monkeypatch.setattr(r, '_getPublicCommentsByUsername',
                        lambda u: ['Comment 1', 'Comment 2', "Message\nMetadata: {\"vulnDomain\": etc..."])
    assert r.isVerified() is True


@pytest.mark.fast
def test_isStructured():
    assert isStructured("{1: 2}")
    assert isStructured("{abcdef}")
    assert isStructured("{a:a}")
    assert not isStructured("{}")
    assert not isStructured("[]")
    assert not isStructured("abc")


@pytest.mark.fast
def test_extractJson():
    assert extractJson(("In order to expedite triaging, patching, and paying out vulnerabilities, "
                        "please respond with a link that when visited will pop up an alert box "
                        "containing QABATKVS.\n\nIf this is not possible, there is no need to reply "
                        "and a human will verify your report as soon as possible."
                        "\n\nMetadata: `{\"token\": \"QABATKVS\"}`")) == {"token": "QABATKVS"}
    assert extractJson("`{}`") == {}
    assert extractJson('`{"a":true}`') == {"a": True}
    assert extractJson('`{"a":1}`') == {"a": 1}
    assert extractJson('`{"a":1.2}`') == {"a": 1.2}
    assert extractJson('abc`{"a":true}`def') == {"a": True}
    assert extractJson('`abc{"a":true}`def') == {"a": True}
    assert extractJson('abc`{"a":true}def`') == {"a": True}
    assert extractJson('`abc{"a":true}def`') == {"a": True}
    assert extractJson('```abc```\n`{"a":\ntrue}`\n```def\n\tt```') == {"a": True}
    assert extractJson('`{1}`{"a":true}') is None
    assert extractJson('{1}`{"a":true}`') == {'a': True}
    assert extractJson('`{5:3}``{"a":true}``{"A":"B"}`') == {"a": True}
    assert extractJson('abc}`{"a":true}`') == {"a": True}
    assert extractJson('abc`{"a":true}`def{`test`') == {"a": True}
    # The super fuzzy json parser:
    assert (fuzzyJsonParse(("""{"a": 'b', '1': [1,2,3,4,]"""
                            ""","bool1": true, "bool2": false, "none": null,}""")) ==
            {'a': 'b', '1': [1, 2, 3, 4], 'bool1': True, 'bool2': False, 'none': None})
    try:
        fuzzyJsonParse("[1]")
        extractJson("[1]")
        assert False
    except ValueError:
        assert True


@pytest.mark.fast
def test_extractURLs():
    assert extractURLs("[a](link)") == ['link']
    assert extractURLs("[()a](link)") == ['link']
    assert extractURLs("[a](l[i]nk)") == ['l[i]nk']
    assert extractURLs("abc\n[[a](asdf)\n([a](link)") == ['asdf', 'link']
    assert extractURLs("```http://example.com```") == ['http://example.com']
    assert extractURLs("```http://user:pass@example.com```") == ['http://user:pass@example.com']
    # Fuzzier method
    assert (extractURLs("https://example.example/example/example.example.example?example=a'\"<>()") ==
            ["https://example.example/example/example.example.example?example=a'\"<>()"])


@pytest.mark.fast
def test_getLinks():
    assert (getLinks("https://www.google.com.google/test/test/wut.php?q=1&a=1&d=1") ==
            ['https://www.google.com.google/test/test/wut.php?q=1&a=1&d=1'])
    assert (getLinks(("https://www.google.com.google/test/test/wut.php?q=1&a=1&d=1 aaaaaaaaaaaaaaa "
                      "aaaaaaaaaaaaa \naaaaaaaaaaaaaa https://example.com/testaaaaaaaaaaaaa")) ==
            ['https://www.google.com.google/test/test/wut.php?q=1&a=1&d=1', 'https://example.com/testaaaaaaaaaaaaa'])
    assert getLinks("https://ai") == ['https://ai']
    assert getLinks("http://blog.google") == ['http://blog.google']
