"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from datetime import datetime
from typing import List, Optional
from AutoTriageBot.AutoTriageUtils import postComment, getReport, VulnTestInfo
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot import config
from AutoTriageBot.modules import modules
from AutoTriageBot import secrets
import json
import requests
from requests.auth import HTTPBasicAuth
from multiprocessing import Pool


def getReportIDs(startTime: datetime) -> List[str]:
    """ Get a list of report IDs created after the given time """
    return requests.post('http://api:8080/v1/getReportIDs',
                         json={'time': startTime.isoformat(), 'openOnly': True},  # We only need the open reports
                         auth=HTTPBasicAuth('AutoTriageBot', secrets.apiBoxToken)).json()


def getReports(startTime: datetime) -> List[ReportWrapper]:
    """ Get a list of reports created after the given time """
    ids = getReportIDs(startTime)
    p = Pool(4)
    return p.map(getReport, ids)


def generateMetadataVTI(report: ReportWrapper, vti: VulnTestInfo) -> VulnTestInfo:
    """ Given the results of a vulnerability test thar reproduced a vulnerability and a report, generate an internal
        VTI used to hold metadata about the vulnerability """
    internalMetadata = {'id': report.getReportID(),
                        'title': report.getReportTitle(),
                        'reportedTime': str(report.getReportedTime()),
                        'verifiedTime': str(datetime.now()),
                        'type': vti.type,
                        'exploitURL': vti.info['src'],
                        'method': vti.info['method']}
    if vti.type == 'XSS':
        internalMetadata['confirmedBrowsers'] = vti.info['confirmedBrowsers']
        internalMetadata['alertBrowsers'] = vti.info['alertBrowsers']
        internalMetadata['httpType'] = vti.info['httpType']
        internalMetadata['cookies'] = vti.info['cookies']
    elif vti.type == 'SQLi':
        internalMetadata['delay'] = vti.info['delay']
        internalMetadata['httpType'] = vti.info['httpType']
        internalMetadata['cookies'] = vti.info['cookies']
    elif vti.type == 'Open Redirect':
        internalMetadata['redirect'] = vti.info['redirect']
        internalMetadata['httpType'] = vti.info['httpType']
        internalMetadata['cookies'] = vti.info['cookies']
    message = '# Internal Metadata: \n\n```\n%s\n```\n' % json.dumps(internalMetadata,
                                                                     sort_keys=True,
                                                                     indent=4,
                                                                     separators=(',', ': '))

    if config.DEBUGVERBOSE:
        print(internalMetadata)

    internalVTI = VulnTestInfo(reproduced=False,
                               message=message,
                               info={},
                               type='')
    return internalVTI


def processReport(report: ReportWrapper, startTime: datetime) -> Optional[VulnTestInfo]:
    """ Attempt to verify a given report """
    if report.needsBotReply():
        if startTime > report.getReportedTime():
            return None
        if config.DEBUG:
            print("Processing %s" % report.getReportTitle())
        for module in modules:
            if module.match(report.getReportBody(), report.getReportWeakness()):  # type: ignore
                if config.DEBUG:
                    print(module.__file__.split('/')[-1] + " matched id=%s!" % report.getReportID())
                vti = module.process(report)  # type: ignore
                if config.DEBUGVERBOSE:
                    print(vti)
                if vti:
                    postComment(report.getReportID(), vti, addStopMessage=True)
                    if vti.reproduced and config.metadataLogging:
                        metadataVTI = generateMetadataVTI(report, vti)
                        postComment(report.getReportID(), metadataVTI, internal=True)
                return vti
        if config.DEBUG:
            print("No matches")
    return None
