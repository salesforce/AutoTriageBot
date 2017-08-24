"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import time
from AutoTriageBot.ReportWrapper import ReportWrapper
from AutoTriageBot.sqlite import initDB, countFailures
from AutoTriageBot import config, duplicates, payout, verify
from AutoTriageBot import slack
from AutoTriageBot.modules import modules
import traceback
import datetime
import socket


def shouldProcessReport(report: ReportWrapper) -> bool:
    """ Whether the bot should process the given ReportWrapper """
    username = report.getReporterUsername()
    return (shouldProcess_blacklist(username) and shouldProcess_whitelist(username) and
            shouldProcess_failures(username) and shouldProcess_match(report))


def shouldProcess_match(report: ReportWrapper) -> bool:
    """ Whether the bot should process the given ReportWrapper according to whether any of the modules match it """
    return any([m.match(report.getReportBody(), report.getReportWeakness()) for m in modules])  # type: ignore


def shouldProcess_blacklist(username: str) -> bool:
    """ Whether the bot should process a report from the given user according to the blacklist """
    if isinstance(config.blacklistedUsernames, list):
        return username.lower() not in [u.lower() for u in config.blacklistedUsernames]
    return True


def shouldProcess_whitelist(username: str) -> bool:
    """ Whether the bot should process a report from the given user according to the whitelist """
    if isinstance(config.whitelistedUsernames, list):
        return username.lower() in [u.lower() for u in config.whitelistedUsernames]
    return True


def shouldProcess_failures(username: str) -> bool:
    """ Whether the bot should process a report from the given user according to the failure DB """
    # isinstance(False, int) == True in python
    if (isinstance(config.allowedFailures, int) and
            config.allowedFailures is not False and
            config.allowedFailures is not True):
        return countFailures(username.lower()) < config.allowedFailures
    return True


def run():
    """ Run the bot """
    initDB()
    if config.genesis:
        startTime = config.genesis
    else:
        startTime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    while True:
        try:
            reports = verify.getReports(startTime)
            if config.DEBUG:
                print("Found %s reports" % str(len(reports)))
            for idx, report in enumerate(reports):
                if config.DEBUGVERBOSE:
                    print('Processing: %s: %s' % (str(idx), report.getReportTitle()))
                if shouldProcessReport(report):
                    if not duplicates.processReport(report):
                        vti = verify.processReport(report, startTime)
                        if vti and vti.reproduced:
                            payout.processReport(report)
                            try:
                                # Only post the interactive message if the slack container is running
                                socket.gethostbyname('slack')
                                slack.postMessage("<https://hackerone.com/reports/%s|Report #%s> (%s) verified!" %
                                                  (report.getReportID(), report.getReportID(), report.getReportTitle()),
                                                  attachments=[{"text": "",
                                                                "fallback": "",
                                                                "callback_id":
                                                                    "reportVerified_%s" % report.getReportID(),
                                                                "color": "#3AA3E3",
                                                                "attachment_type": "default",
                                                                "actions": [{"name": "metadata",
                                                                             "text": "View metadata",
                                                                             "type": "button",
                                                                             "value": "metadata"},
                                                                            {"name": "body",
                                                                             "text": "View body",
                                                                             "type": "button",
                                                                             "value": "body"}]}])
                            except socket.gaierror:
                                slack.postMessage("<https://hackerone.com/reports/%s|Report #%s> (%s) verified!" %
                                                  (report.getReportID(), report.getReportID(), report.getReportTitle()))
            if config.DEBUG:
                print("Sleeping...")
            time.sleep(10)
        except Exception as e:
            if config.DEBUG:
                print("Caught exception: %s" % str(e))
                traceback.print_exc()
                print("+"*80)


if __name__ == '__main__':
    run()
