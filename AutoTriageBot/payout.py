"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from typing import Mapping, List, Optional

from AutoTriageBot.modules import xss, openRedirect

from AutoTriageBot.AutoTriageUtils import postComment, VulnTestInfo
from AutoTriageBot.DataTypes import BountyInfo
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot.modules import sqli
from AutoTriageBot import config


def suggestPayoutGivenType(db: Mapping[str, BountyInfo], domains: List[str]) -> BountyInfo:
    """ Returns a BountyInfo containing a suggested payout and the std for the given report given the DB
        for that class of vulnerability"""
    if len(domains) == 0:
        return db['average']
    sum = 0.0
    stdSum = 0.0  # Not actually the std, but good enough™
    cnt = 0
    for domain in domains:
        try:
            sum += db[domain].average
            stdSum += db[domain].std
            cnt += 1
        except KeyError:
            pass
    try:
        return BountyInfo(average=sum/cnt, std=stdSum/cnt)
    except ZeroDivisionError:
        return db['average']


def suggestPayout(report: ReportWrapper) -> Optional[BountyInfo]:
    """ Returns a BountyInfo containing a suggested payout and the standard deviation for the given report """
    if xss.match(report.getReportBody(), report.getReportWeakness()):
        return suggestPayoutGivenType(config.payoutDB['xss'], report.getVulnDomains())
    if openRedirect.match(report.getReportBody(), report.getReportWeakness()):
        return suggestPayoutGivenType(config.payoutDB['open redirect'], report.getVulnDomains())
    if sqli.match(report.getReportBody(), report.getReportWeakness()):
        return suggestPayoutGivenType(config.payoutDB['sqli'], report.getVulnDomains())
    return None


def processReport(report: ReportWrapper) -> None:
    """ Process the given report and post a private comment with a suggested bounty """
    if config.payoutDB:
        bountyInfo = suggestPayout(report)
        if bountyInfo:
            postComment(report.getReportID(),
                        VulnTestInfo(reproduced=False,
                                     info={},
                                     message='Suggested bounty: %.2f with a σ of %.2f' % (bountyInfo.average,
                                                                                          bountyInfo.std),
                                     type=''),
                        internal=True)
    else:
        if config.DEBUGVERBOSE:
            print("Not suggesting a payout beause config.payoutDB is falsy")
