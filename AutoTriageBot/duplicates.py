"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from datetime import datetime
from typing import List, Callable, Tuple, Optional, NewType
from urllib.parse import unquote
import json

from AutoTriageBot import AutoTriageUtils
from AutoTriageBot.AutoTriageUtils import VulnTestInfo
from AutoTriageBot.ReportWrapper import ReportWrapper, getLinks

from AutoTriageBot import config
from AutoTriageBot import secrets
from AutoTriageBot.modules import modules
import requests
from requests.auth import HTTPBasicAuth


def getAllOpenReports(time: datetime) -> List[ReportWrapper]:
    """ Get a list of all the open reports """
    reports = [ReportWrapper().deserialize(ser)
               for ser in json.loads(requests.post('http://api:8080/v1/getReports',
                                                   auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).text)]
    return list(filter(lambda r: r.getReportedTime() < time,
                       (filter(lambda r: r.getState() in ['new', 'triaged', 'needs-more-info'], reports))))


ID = NewType('ID', str)
DuplicateResult = NewType('DuplicateResult', Tuple[Optional[int], ID])


def isDuplicate(r1: ReportWrapper, r2: ReportWrapper) -> DuplicateResult:
    """ Returns a confidence rating on whether the two given reports are duplicates of each other """
    for module in modules:
        if (module.match(r1.getReportBody(), r1.getReportWeakness()) and  # type: ignore
                module.match(r2.getReportBody(), r2.getReportWeakness())):  # type: ignore
            return sameCategoryIsDuplicate(r1, r2, module.containsExploit)  # type: ignore
    return DuplicateResult((None, ID('A')))


def sameCategoryIsDuplicate(r1: ReportWrapper, r2: ReportWrapper, containsExploit: Callable[[str], bool]) -> \
        DuplicateResult:
    """ Returns a confidence rating on whether the two given reports are duplicates of each other given that they are
        of the same type of vulnerability and that containsExploit returns whether or not a given URL is exploiting
        that class of vulnerability. """
    # The links are the only things we refer to in our current duplicate detection algorithm
    links1, links2 = getLinks(r1.getReportBody()), getLinks(r2.getReportBody())
    malLinks1 = [link for link in links1 if containsExploit(link) or containsExploit(unquote(link))]
    malLinks2 = [link for link in links2 if containsExploit(link) or containsExploit(unquote(link))]

    if set(malLinks1) & set(malLinks2):
        return DuplicateResult((99, ID('B')))
    if set(links1) & set(links2):
        return DuplicateResult((90, ID('C')))

    parsedMalLinks1 = list(filter(lambda n: n, map(AutoTriageUtils.parseURL, malLinks1)))
    parsedMalLinks2 = list(filter(lambda n: n, map(AutoTriageUtils.parseURL, malLinks2)))
    parsedLinks1 = list(filter(lambda n: n, map(AutoTriageUtils.parseURL, links1)))
    parsedLinks2 = list(filter(lambda n: n, map(AutoTriageUtils.parseURL, links2)))

    malDomainParameterTuples1 = flatten([[(x.domain, x.path, key)
                                          for key, val in x.queries.items()
                                          if containsExploit(val)] for x in parsedMalLinks1])
    malDomainParameterTuples2 = flatten([[(x.domain, x.path, key)
                                          for key, val in x.queries.items()
                                          if containsExploit(val)] for x in parsedMalLinks2])

    parametersInCommon = (set(flatten([parsed.queries.keys() for parsed in parsedLinks1])) &
                          set(flatten([parsed.queries.keys() for parsed in parsedLinks2])))
    malParametersInCommon = (set(flatten([parsed.queries.keys() for parsed in parsedMalLinks1])) &
                             set(flatten([parsed.queries.keys() for parsed in parsedMalLinks2])))

    injectionParametersInCommon = (set([param for domain, path, param in malDomainParameterTuples1]) &
                                   set([param for domain, path, param in malDomainParameterTuples2]))

    malPathsInCommon = (set([path for domain, path, param in malDomainParameterTuples1 if path != '']) &
                        set([path for domain, path, param in malDomainParameterTuples2 if path != '']))
    pathsInCommon = (set([parsed.path for parsed in parsedLinks1 if parsed.path != '']) &
                     set([parsed.path for parsed in parsedLinks2 if parsed.path != '']))

    domains1 = set([x.domain for x in parsedLinks1 if '[server]' not in x.domain])
    domains2 = set([x.domain for x in parsedLinks2 if '[server]' not in x.domain])

    domainsInCommon = domains1 & domains2
    malDomainsInCommon = (set([x.domain for x in parsedMalLinks1 if '[server]' not in x.domain]) &
                          set([x.domain for x in parsedMalLinks2 if '[server]' not in x.domain]))

    return decide(len(malLinks1), len(malLinks2), len(parametersInCommon), len(malParametersInCommon),
                  len(pathsInCommon), len(malPathsInCommon), len(domainsInCommon), len(malDomainsInCommon),
                  len(injectionParametersInCommon), len(domains1 ^ domains2))


def decide(malLinks1: int, malLinks2: int, parametersInCommon: int, malParametersInCommon: int, pathsInCommon: int,
           malPathsInCommon: int, domainsInCommon: int, malDomainsInCommon: int, injectionParametersInCommon: int,
           symDiffDomains: int) -> DuplicateResult:
    """ Based off of the given signals, comes to a conclusion about whether they are duplicates
          - This was generated via backtesting against historical data, see dev/duplicatesScraperAndStats.py """
    allBools = [malLinks1 > 0, malLinks2 > 0, parametersInCommon > 0, malParametersInCommon > 0, pathsInCommon > 0,
                malPathsInCommon > 0, domainsInCommon > 0, malDomainsInCommon > 0, injectionParametersInCommon > 0]
    if countTrue(*allBools) >= 5:
        return DuplicateResult((99, ID('D')))
    malBools = [malParametersInCommon > 0, malPathsInCommon > 0, malDomainsInCommon > 0,
                injectionParametersInCommon > 0]
    if countTrue(*malBools) >= 1:
        return DuplicateResult((90, ID('E')))
    if countTrue(*allBools) >= 3:
        return DuplicateResult((80, ID('F')))
    if symDiffDomains >= 3:
        return DuplicateResult((20, ID('G')))
    return DuplicateResult((None, ID('H')))


def countTrue(*args):
    # type: (*bool) -> int
    """ Count the number of truthy arguments given """
    return len(list(filter(lambda b: b, args)))


def flatten(l: List) -> List:
    """ Flatten the given list """
    return [item for subl in l for item in subl]


def processReport(report: ReportWrapper) -> bool:
    """ Process a report via searching for duplicates and posting comments based off of the confidence levels
          Returns whether or not the report was classified as a duplicate with a high confidence """
    if report.getState() == "new" and not report.hasDuplicateComment() and not report.isVerified():
        earlierReports = getAllOpenReports(report.getReportedTime())  # type: List[ReportWrapper]
        idConfTuples = []  # type: List[Tuple[str, int]]
        matches = []  # type: List[str]
        for earlierReport in earlierReports:
            for module in modules:
                if (module.match(report.getReportBody(), report.getReportWeakness()) and  # type: ignore
                        module.match(earlierReport.getReportBody(), earlierReport.getReportWeakness())):  # type: ignore
                    matches.append(earlierReport.getReportID())
            try:
                confidence = int(isDuplicate(earlierReport, report)[0])
            except TypeError:
                confidence = 0
            if confidence == 99:
                AutoTriageUtils.postComment(report.getReportID(),
                                            VulnTestInfo(message='Found a duplicate with 99%% confidence: #%s' %
                                                                 earlierReport.getReportID(),
                                                         info={},
                                                         reproduced=False,
                                                         type=''),
                                            internal=True)
                if config.DEBUG:
                    print("Detected that %s (%s) is a duplicate of %s (%s)!" % (report.getReportID(),
                                                                                report.getReportTitle(),
                                                                                earlierReport.getReportID(),
                                                                                earlierReport.getReportTitle()))
                return False  # Change to return True to make the bot stop interacting after finding a duplicate
            elif confidence > 50:
                idConfTuples.append((earlierReport.getReportID(), confidence))
        # If you update the phrases here, you must also update them in AutoTriageUtils.ReportWrapper.hasDuplicateComment
        if len(idConfTuples) > 0:
            def idConfToStr(tuple: Tuple) -> str:
                return ('Detected a possible duplicate report with confidence of %s: #%s' % (tuple[1], tuple[0]))
            AutoTriageUtils.postComment(report.getReportID(),
                                        VulnTestInfo(message='\n'.join([idConfToStr(t) for t in idConfTuples]),
                                                     info={},
                                                     reproduced=False,
                                                     type=''),
                                        internal=True)
            if config.DEBUG:
                print('Found partial matches: %s' % str(idConfTuples))
        if len(matches) > 0 and len(matches) <= 5:
            AutoTriageUtils.postComment(report.getReportID(),
                                        VulnTestInfo(message=('There are currently %s open reports about this type of '
                                                              'vulnerability: %s' %
                                                              (str(len(matches)),
                                                               ', '.join(['#'+id for id in matches]))),
                                                     info={},
                                                     reproduced=False,
                                                     type=''),
                                        internal=True)
            if config.DEBUG:
                print('Found %s reports on the same type of vulnerability as %s: %s'
                      % (str(len(matches)), str(report.getReportID()), ', '.join(['#'+id for id in matches])))
    return False
