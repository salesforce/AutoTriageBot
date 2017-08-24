"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot import slack


def test_postMessage(monkeypatch):
    # All we can do is test that it doesn't throw an error when we don't have a slack api key
    monkeypatch.setattr(slack.secrets, 'slackOauth', '')
    try:
        slack.postMessage("ABC")
    except:
        assert False
