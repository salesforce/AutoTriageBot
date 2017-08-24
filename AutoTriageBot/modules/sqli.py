"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from random import SystemRandom
from time import time
from typing import Optional, Mapping
from urllib.parse import urlparse
from AutoTriageBot import constants
from AutoTriageBot.AutoTriageUtils import isProgramURL, extractDataFromJson
from AutoTriageBot.sqlite import addFailureToDB
from AutoTriageBot.ReportWrapper import ReportWrapper, extractJson, isStructured, extractURLs
from AutoTriageBot import config
from urllib.error import URLError
import requests
import traceback
from AutoTriageBot.DataTypes import VulnTestInfo

maxTimeDiff = 1.0

wrongDelayMessage = ("Found a delay of `%s` seconds. In order to verify the vulnerability, "
                     "it must have delayed for `%s` seconds. \n\n"
                     "Please resubmit with a link that will delay for `%s` seconds.")

initialMessage = (('We have detected that this report is about a SQLi vulnerability. \n\n'
                   'To triage this bug quicker, '
                   'this bot can automatically verify vulnerabilities.\n\n'
                   'Try either:\n'
                   '* Posting a URL that delays loading for `"%s"` seconds due to a call to the sleep function\n'
                   '* Use the JSON structure below to change the method and/or add cookies\n\n'
                   '# Examples: \n\n'
                   '## Option 1: Unauthenticated GET\n'
                   'If it can be exploited without authentication via simply loading a URL, respond with a link that '
                   'when '
                   'visited will take `%s` seconds to load due to a call to the sleep function. The link should either '
                   'be specified as a markdown link (`[text](https://example.com)` or inside a code block '
                   '(``` `https://example.com` ```). \n\n'
                   '## Option 2: Authenticated GET\n'
                   'If doing so requires authentication, then please copy and paste the below '
                   'into JSON a code block and fill in the blanks: \n\n'
                   '```\n'
                   '{\n'
                   '    "URL": "<Fill in the URL here>",\n'
                   '    "cookies": {"CookieOneName":   "CookieOneValue", \n'
                   '                "CookieTwoName":   "CookieTwoValue", \n'
                   '                "CookieThreeName": "CookieThreeValue"}, \n'
                   '    "type": "get" \n'
                   '}\n'
                   '```\n\n'
                   '## Option 3: Authenticated POST\n'
                   'If the exploit requires authentication and is done via POST, then please copy '
                   'and paste the below into a code block and fill in the blanks: \n\n'
                   '```\n'
                   '{\n'
                   '    "URL": "<Fill in the URL here>",\n'
                   '    "cookies": {"CookieOneName":   "CookieOneValue", \n'
                   '                "CookieTwoName":   "CookieTwoValue", \n'
                   '                "CookieThreeName": "CookieThreeValue"}, \n'
                   '    "type": "post", \n'
                   '    "data": {"ArgumentOneName":   "ArgumentOneValue", \n'
                   '             "ArgumentTwoName":   "ArgumentTwoValue", \n'
                   '             "ArgumentThreeName": "ArgumentThreeValue"} \n'
                   '}\n'
                   '```\n'
                   '\n'
                   'If this is not possible, there is no need to reply and a human will verify '
                   'your report as soon as possible. \n\n'
                   'Metadata: `{"token": "%s"}`\n\n'))


def containsExploit(text: str) -> bool:
    """ Returns whether or not the given str contains evidence that it is a sqli exploit """
    return ('or' in text.lower() or
            'and' in text.lower() or
            'select' in text.lower() or
            'from' in text.lower() or
            'where' in text.lower())


def match(reportBody: str, reportWeakness: str) -> bool:
    """ Returns whether or not the given report body or report weakness are about a sqli vulnerability """
    return ("sqli" in reportBody.lower() or
            "sql injection" in reportBody.lower() or
            "SQL Injection" in reportWeakness)


def getRandInt() -> str:
    return str(SystemRandom().randint(5, 20))


def process(report: ReportWrapper) -> Optional[VulnTestInfo]:
    """ Process the given report into a VulnTestInfo named tuple """
    # If the user has not yet been prompted for automatic triaging
    if not report.botHasCommented():
        token = getRandInt()
        return VulnTestInfo(reproduced=False,
                            message=initialMessage % (token, token, token),
                            type='SQLi',
                            info={})
    elif report.shouldBackoff():
        if not report.hasPostedBackoffComment():
            addFailureToDB(report.getReporterUsername(), report.getReportID())
            return VulnTestInfo(reproduced=False,
                                message=('Automatic verification of vulnerability has failed, Backing off! Falling '
                                         'back to human verification. '),
                                type='SQLi',
                                info={})
        else:
            return None
    elif report.isVerified():
        return None
    try:
        if isStructured(report.getLatestActivity()):
            return processStructured(report, token=report.getToken())
        else:
            return processUnstructured(report, token=report.getToken())
    except Exception as e:
        print("Caught exception: %s" % str(e))
        traceback.print_exc()
        print("+" * 80)
        return VulnTestInfo(reproduced=False,
                            message=('Internal error detected! Backing off...'),
                            type='SQLi',
                            info={})


def processStructured(report: ReportWrapper, token: str='') -> VulnTestInfo:
    """ Process the given report into a VulnTestInfo named tuple given that it contains structured data """
    info = extractJson(report.getLatestActivity())
    if info is None:
        return VulnTestInfo(reproduced=False,
                            message=('Failed to parse JSON! Please try again.'),
                            type='SQLi',
                            info={'report': report.getLatestActivity()})

    # Pass it off to a helper that can try to handle any inconsistencies
    url, cookies, type, data = extractDataFromJson(info)

    if not isProgramURL(url):
        return VulnTestInfo(reproduced=False,
                            message=('The url provided (`%s`) is not a program URL!') % url,
                            type='SQLi',
                            info={'src': url,
                                  'method': 'structured'})

    if type.lower() == 'post':
        delay = testPOSTSQLDelay(url, cookies, data)
    elif type.lower() == 'get':
        delay = testGETSQLDelay(url, cookies)
    else:
        return VulnTestInfo(reproduced=False,
                            message='Found an invalid value "type"=%s in the JSON blob!' % type,
                            type='SQLi',
                            info={'src': url,
                                  'method': 'structured'})

    if delay and abs(delay - int(token)) < maxTimeDiff:
        return VulnTestInfo(reproduced=True,
                            message=('Successfully found and confirmed SQLi at `%s`!\n'
                                     'Metadata: {"vulnDomain": "%s"}') % (url, urlparse(url).hostname),
                            type='SQLi',
                            info={'src': url,
                                  'method': 'structured',
                                  'delay': int(delay),
                                  'httpType': type,
                                  'cookies': cookies})
    elif delay:
        return VulnTestInfo(reproduced=False,
                            message=wrongDelayMessage % (str(int(delay)), token, token),
                            type='SQLi',
                            info={'src': url,
                                  'method': 'structured'})
    else:
        return VulnTestInfo(reproduced=False,
                            message=("Failed to validate SQLi at `%s` via structured data. Either try again or wait "
                                     "for manual review of your bug.") % url,
                            type='SQLi',
                            info={'method': 'structured'})


def processUnstructured(report: ReportWrapper, token: str='') -> VulnTestInfo:
    """ Process the given report into a VulnTestInfo named tuple given that it doesn't contain structured data """
    urls = extractURLs(report.getLatestActivity())
    if config.DEBUG:
        print("URLs=%s" % str(urls))
    if len(urls) > 5:
        if config.DEBUG:
            print("User submitted %s URLs. Skipping...")
        return VulnTestInfo(reproduced=False,
                            message='Found %s URLs. Please resubmit with a single URL to test.',
                            type='SQLi',
                            info={'URLs': str(urls),
                                  'method': 'structured'})
    testedURLs = []
    for url in urls:
        if isProgramURL(url):
            # Unstructured reports are treated as a GET
            delay = testGETSQLDelay(url, {})
            if delay and abs(delay - int(token)) < maxTimeDiff:
                return VulnTestInfo(reproduced=True,
                                    message=('Successfully found and confirmed SQLi at `%s`!\n'
                                             'Metadata: {"vulnDomain": "%s"}') % (url, urlparse(url).hostname),
                                    type='SQLi',
                                    info={'src': url,
                                          'method': 'unstructured',
                                          'delay': int(delay),
                                          'httpType': 'GET',
                                          'cookies': {}})
            elif delay:
                return VulnTestInfo(reproduced=False,
                                    message=wrongDelayMessage % (str(int(delay)), token, token),
                                    type='SQLi',
                                    info={'src': url,
                                          'method': 'unstructured'})
            else:
                testedURLs.append(url)
    if len(testedURLs) > 0:
        return VulnTestInfo(reproduced=False,
                            message=constants.structuredDataMessage % ('SQLi'),
                            type='SQLi',
                            info={'method': 'unstructured'})
    else:
        return VulnTestInfo(reproduced=False,
                            message=constants.failedToFindURLsMessage,
                            type='SQLi',
                            info={'method': 'unstructured'})


def testGETSQLDelay(url: str, cookies: Mapping[str, str]) -> Optional[float]:
    """ If the given URL pauses for more than 5 seconds when accessed with the given cookies via GET, return the load
        time, otherwise return None """
    try:
        startTime = time()
        requests.get(url, cookies=cookies, timeout=60)
        totalTime = time() - startTime
        if totalTime > 5:
            return totalTime
        else:
            return None
    except (requests.exceptions.Timeout, URLError):
        return None


def testPOSTSQLDelay(url: str, cookies: Mapping[str, str], data: Mapping[str, str]) -> Optional[float]:
    """ If the given URL pauses for more than 5 seconds when accessed with the given cookies via POST, return the load
        time, otherwise return None """
    try:
        startTime = time()
        requests.post(url, dict(data), cookies=cookies, timeout=60)
        totalTime = time() - startTime
        if totalTime > 5:
            return totalTime
        else:
            return None
    except (requests.exceptions.Timeout, URLError):
        return None
