"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from typing import NamedTuple, Callable
import pytest
from AutoTriageBot import payout
from AutoTriageBot import config


@pytest.mark.fast
def test_suggestPayoutGivenType():
    for key in config.payoutDB:
        assert payout.suggestPayoutGivenType(config.payoutDB[key], []) == config.payoutDB[key]['average']
    for vulnType in config.payoutDB:
        for domain in config.payoutDB[vulnType]:
            assert payout.suggestPayoutGivenType(config.payoutDB[vulnType], [domain]) == \
                   config.payoutDB[vulnType][domain]


@pytest.mark.fast
def test_suggestPayout():
    MockedReportWrapper = NamedTuple('MockedReportWrapper', [('getReportBody', Callable),
                                                             ('getReportWeakness', Callable),
                                                             ('getVulnDomains', Callable)])
    MockedReportWrapperXSS = MockedReportWrapper(getReportBody=lambda: 'XSS',
                                                 getReportWeakness=lambda: 'XSS',
                                                 getVulnDomains=lambda: [])
    assert payout.suggestPayout(MockedReportWrapperXSS) == config.payoutDB['xss']['average']
    for vulnType in config.payoutDB:
        for domain in config.payoutDB[vulnType]:
            MockedReportWrapperVuln = MockedReportWrapper(getReportBody=lambda: vulnType,
                                                          getReportWeakness=lambda: vulnType,
                                                          getVulnDomains=lambda: [domain])
            assert payout.suggestPayout(MockedReportWrapperVuln) == config.payoutDB[vulnType][domain]
    MockedReportWrapperNone = MockedReportWrapper(getReportBody=lambda: '',
                                                  getReportWeakness=lambda: '',
                                                  getVulnDomains=lambda: [])
    assert payout.suggestPayout(MockedReportWrapperNone) is None
