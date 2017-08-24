"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

# This code requires that the swarm is properly configured with read access to an org
# If not, these tests will fail, so simply disable them

import requests
from requests.auth import HTTPBasicAuth
import json
from AutoTriageBot.ReportWrapper import ReportWrapper
import pytest
from AutoTriageBot import secrets


@pytest.mark.api
@pytest.mark.integration
def test_api():
    ids = json.loads(requests.post('http://api:8080/v1/getReportIDs',
                                   json={'time': '1970-01-01T00:00:00Z', 'openOnly': False},
                                   auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text)
    openIDs = json.loads(requests.post('http://api:8080/v1/getReportIDs',
                                       json={'time': '1970-01-01T00:00:00Z', 'openOnly': True},
                                       auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text)
    assert isinstance(ids, list)
    assert isinstance(openIDs, list)
    assert len(openIDs) <= len(ids)  # There should be an equal or lesser number of open bugs than all bugs
    assert all([(id in ids) for id in openIDs])  # All open ids should be in ids
    for id in ids:
        # They should be strings but they should be parseable into integers
        assert isinstance(id, str) and isinstance(int(id), int)
    # There should be no duplicate IDs
    assert len(set(ids)) == len(ids)

    for id in ids[:10]:
        ser = requests.post('http://api:8080/v1/getReport', json={'id': id},
                            auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text
        try:
            r = ReportWrapper().deserialize(ser)
        except:
            assert False

    for serRep in json.loads(requests.post('http://api:8080/v1/getReports',
                                           auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text)[:10]:
        try:
            r = ReportWrapper().deserialize(serRep)
        except:
            assert False
        assert r.getReportID() in ids
