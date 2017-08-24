"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import re
import time
from typing import Optional, Mapping
from urllib.parse import urlparse
from AutoTriageBot import AutoTriageUtils
from AutoTriageBot import constants
from AutoTriageBot.AutoTriageUtils import isProgramURL, extractDataFromJson
from AutoTriageBot.sqlite import addFailureToDB
from AutoTriageBot.ReportWrapper import ReportWrapper, extractJson, isStructured, extractURLs
from AutoTriageBot import SeleniumDrivers
from AutoTriageBot import config
from selenium.common.exceptions import TimeoutException
from urllib.error import URLError
import traceback
from AutoTriageBot.DataTypes import VulnTestInfo

tokenNotFoundMessage = ("Found an open redirect from `%s` to `%s`, but the token `%s` was not in the "
                        "redirected url.\n\n"
                        "Please resubmit with a link that will redirect to a URL containing the "
                        "token `%s`")


def containsExploit(text: str) -> bool:
    """ Returns whether or not the given str contains evidence that it is an open redirect exploit """
    return ('https://' in text.lower() or
            'http://' in text.lower() or
            'javascript:' in text.lower() or
            'example.com' in text.lower())


def match(reportBody: str, reportWeakness: str) -> bool:
    """ Returns whether or not the given report body or report weakness are about an open redirect vulnerability """
    return (re.findall("open[\s\S]redirect", reportBody.lower()) != [] or
            reportWeakness == "Open Redirect")


def process(report: ReportWrapper) -> Optional[VulnTestInfo]:
    """ Process the given report into a VulnTestInfo named tuple """
    # If the user has not yet been prompted for automatic triaging
    if not report.botHasCommented():
        token = AutoTriageUtils.generateToken()
        return VulnTestInfo(reproduced=False,
                            message=constants.initialMessage(token, 'redirect to a domain', 'Open Redirect'),
                            type='Open Redirect',
                            info={})
    elif report.shouldBackoff():
        if not report.hasPostedBackoffComment():
            addFailureToDB(report.getReporterUsername(), report.getReportID())
            return VulnTestInfo(reproduced=False,
                                message=('Automatic verification of vulnerability has failed, Backing off! Falling '
                                         'back to human verification. '),
                                type='Open Redirect',
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
                            type='Open Redirect',
                            info={})


def processStructured(report: ReportWrapper, token: str='') -> VulnTestInfo:
    """ Process the given report into a VulnTestInfo named tuple given that it contains structured data """
    info = extractJson(report.getLatestActivity())
    if info is None:
        return VulnTestInfo(reproduced=False,
                            message=('Failed to parse JSON! Please try again.'),
                            type='Open Redirect',
                            info={'report': report.getLatestActivity()})

    # Pass it off to a helper that can try to handle any inconsistencies
    url, cookies, type, data = extractDataFromJson(info)

    if not isProgramURL(url):
        return VulnTestInfo(reproduced=False,
                            message=('The url provided (`%s`) is not a program URL!') % url,
                            type='Open Redirect',
                            info={'src': url,
                                  'method': 'structured'})

    if type.lower() == 'post':
        res = testPOSTOpenRedirect(url, cookies, data)
    elif type.lower() == 'get':
        res = testGETOpenRedirect(url, cookies)
    else:
        return VulnTestInfo(reproduced=False,
                            message='Found an invalid value "type"=%s in the JSON blob!' % type,
                            type='Open Redirect',
                            info={'src': url,
                                  'method': 'structured'})

    if res and token.lower() in urlparse(res).hostname.lower():
        return VulnTestInfo(reproduced=True,
                            message=('Successfully found and confirmed an open redirect from `%s` to `%s`!\n'
                                     'Metadata: {"vulnDomain": "%s"}') % (url, res, urlparse(url).hostname),
                            type='Open Redirect',
                            info={'src': url,
                                  'redirect': res,
                                  'method': 'structured',
                                  'httpType': type,
                                  'cookies': cookies})
    elif res:
        return VulnTestInfo(reproduced=False,
                            message=tokenNotFoundMessage % (url, res, token, token),
                            type='Open Redirect',
                            info={'src': url,
                                  'redirect': res,
                                  'method': 'structured'})
    else:
        return VulnTestInfo(reproduced=False,
                            message=("Failed to validate open redirect at `%s` via structured data. Either try again "
                                     "or wait for manual review of your bug.") % url,
                            type='Open Redirect',
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
                            message=('Found %s URLs. Please resubmit with a single URL to test.'),
                            type='Open Redirect',
                            info={'URLs': str(urls),
                                  'method': 'structured'})
    testedURLs = []
    for url in urls:
        if isProgramURL(url):
            res = testGETOpenRedirect(url, {})
            print("res=%s" % str(urlparse(res).hostname))
            if res and token.lower() in urlparse(res).hostname.lower():
                return VulnTestInfo(reproduced=True,
                                    message=('Successfully found and confirmed an open redirect from `%s` to `%s`!\n'
                                             'Metadata: {"vulnDomain": "%s"}') % (url, res, urlparse(url).hostname),
                                    type='Open Redirect',
                                    info={'src': url,
                                          'redirect': res,
                                          'method': 'unstructured',
                                          'httpType': 'GET',
                                          'cookies': {}})  # nopep8
            elif res:
                return VulnTestInfo(reproduced=False,
                                    message=tokenNotFoundMessage % (url, res, token, token),
                                    type='Open Redirect',
                                    info={'src': url,
                                          'redirect': res,
                                          'method': 'unstructured'})
            else:
                testedURLs.append(url)
    if len(testedURLs) > 0:
        return VulnTestInfo(reproduced=False,
                            message=constants.structuredDataMessage % 'open redirect',
                            type='Open Redirect',
                            info={'method': 'unstructured'})
    else:
        return VulnTestInfo(reproduced=False,
                            message=constants.failedToFindURLsMessage,
                            type='Open Redirect',
                            info={'method': 'unstructured'})


def testGETOpenRedirect(url: str, cookies: Mapping[str, str]) -> Optional[str]:
    """ If the given URL redirects when accessed with the given cookies via GET, return the new URL, otherwise
        return None """
    driver = SeleniumDrivers.getFirefoxDriver()
    driver.setCookies(url, cookies)

    try:
        driver.get(url)

        time.sleep(config.timeout)

        if driver.current_url == url:
            driver.reset()
            return None
        else:
            url = driver.current_url
            driver.reset()
            return url
    except (TimeoutException, URLError):
        driver.reset()
        return None


def testPOSTOpenRedirect(url: str, cookies: Mapping[str, str], data: Mapping[str, str]) -> Optional[str]:
    """ If the given URL redirects when accessed with the given cookies via POST, return the new URL, otherwise
        return None """
    driver = SeleniumDrivers.getFirefoxDriver()
    driver.setCookies(url, cookies)
    try:
        driver.post(url, data)

        time.sleep(config.timeout)

        if driver.current_url == url:
            driver.reset()
            return None
        else:
            url = driver.current_url
            driver.reset()
            return url
    except (TimeoutException, URLError):
        driver.reset()
        return None
