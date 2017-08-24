"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import re
from typing import Optional, Mapping, Tuple, List
from urllib.parse import urlparse
from AutoTriageBot import AutoTriageUtils
from AutoTriageBot import constants
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait
from AutoTriageBot import SeleniumDrivers
from AutoTriageBot import config
from AutoTriageBot.ReportWrapper import ReportWrapper, isStructured, extractJson, extractURLs
from urllib.error import URLError
from selenium import webdriver
import traceback
from AutoTriageBot.AutoTriageUtils import extractDataFromJson
from AutoTriageBot.sqlite import addFailureToDB
from AutoTriageBot.DataTypes import VulnTestInfo

tokenNotFoundMessage = ("Found an XSS at `%s`, but the token `%s` was not in the alert box. \n\n"
                        "Please resubmit with a link that will create an alert box containing "
                        "the token `%s`")


def containsExploit(text: str) -> bool:
    """ Returns whether or not the given str contains evidence that it is an XSS exploit """
    return ('alert' in text.lower() or
            'prompt' in text.lower() or
            'console.log' in text.lower() or
            '<script>' in text.lower() or
            '</script>' in text.lower())


def match(reportBody: str, reportWeakness: str) -> bool:
    """ Returns whether or not the given report body or report weakness are about an XSS vulnerability """
    return (re.findall("xss", reportBody.lower()) != [] or
            "xss" in reportBody.lower() or
            re.findall("cross[\s\S]site[\s\S]scripting", reportBody.lower()) != [] or
            "XSS" in reportWeakness or
            "onload=alert(1)" in reportBody.lower())


def process(report: ReportWrapper) -> Optional[VulnTestInfo]:
    """ Process the given report into a AutoTriageUtils.VulnTestInfo named tuple """
    # If the user has not yet been prompted for automatic triaging
    if not report.botHasCommented():
        token = AutoTriageUtils.generateToken()
        return VulnTestInfo(reproduced=False,
                            message=constants.initialMessage(token, 'pop up an alert box', 'XSS'),
                            type='XSS',
                            info={})
    elif report.shouldBackoff():
        if not report.hasPostedBackoffComment():
            addFailureToDB(report.getReporterUsername(), report.getReportID())
            return VulnTestInfo(reproduced=False,
                                message=('Automatic verification of vulnerability has failed, Backing off! Falling '
                                         'back to human verification. '),
                                type='XSS',
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
                            type='XSS',
                            info={})


def processStructured(report: ReportWrapper, token: str='') -> VulnTestInfo:
    """ Process the given report into a AutoTriageUtils.VulnTestInfo named
        tuple given that it contains structured data """
    info = extractJson(report.getLatestActivity())
    if info is None:
        return VulnTestInfo(reproduced=False,
                            message=('Failed to parse JSON! Please try again.'),
                            type='XSS',
                            info={'report': report.getLatestActivity()})

    # Pass it off to a helper that can try to handle any inconsistencies
    url, cookies, type, data = extractDataFromJson(info)

    if not AutoTriageUtils.isProgramURL(url):
        return VulnTestInfo(reproduced=False,
                            message=('The url provided (`%s`) is not a program URL!') % url,
                            type='XSS',
                            info={'src': url,
                                  'method': 'structured'})

    if type.lower() == 'post':
        results = testPOSTXSS(url, cookies, data)
    elif type.lower() == 'get':
        results = testGETXSS(url, cookies)
    else:
        return VulnTestInfo(reproduced=False,
                            message='Found an invalid value "type"=%s in the JSON blob!' % type,
                            type='XSS',
                            info={'src': url,
                                  'method': 'structured'})

    reproduced, alertBox, message, confirmedBrowsers, alertBrowsers = makeMarkdownTable(results, token)
    if reproduced:
        return VulnTestInfo(reproduced=True,
                            message='Successfully found and confirmed an XSS at `%s`!\n'
                                    '\n\n%s\n\n'
                                    'Metadata: {"vulnDomain": "%s"}' %
                                    (url, message, urlparse(url).hostname),
                            type='XSS',
                            info={'src': url,
                                  'method': 'unstructured',
                                  'confirmedBrowsers': confirmedBrowsers,
                                  'alertBrowsers': alertBrowsers,
                                  'httpType': type,
                                  'cookies': cookies})  # noqa
    elif alertBox:
        return VulnTestInfo(reproduced=False,
                            message=('Failed to confirm the vulnerability! Detected an alert box '
                                     'but the token: `"%s"` was not found!'
                                     '\n\n%s\n\n') % (token, message),
                            type='XSS',
                            info={'src': url,
                                  'method': 'unstructured'})
    else:
        return VulnTestInfo(reproduced=False,
                            message=("Failed to validate XSS at `%s` via structured data. Either try "
                                     "again or wait for manual review of your bug.") % url,
                            type='XSS',
                            info={'method': 'structured'})


def processUnstructured(report: ReportWrapper, token: str='') -> AutoTriageUtils.VulnTestInfo:
    """ Process the given report into a AutoTriageUtils.VulnTestInfo named tuple
        given that it doesn't contain structured data """
    urls = extractURLs(report.getLatestActivity())
    if config.DEBUG:
        print("URLs=%s" % str(urls))
    if len(urls) > 5:
        if config.DEBUG:
            print("User submitted %s URLs. Skipping...")
        return VulnTestInfo(reproduced=False,
                            message='Found %s URLs. Please resubmit with a single URL to test.',
                            type='XSS',
                            info={'URLs': str(urls),
                                  'method': 'structured'})
    testedURLs = []
    for url in urls:
        if AutoTriageUtils.isProgramURL(url):
            testedURLs.append(url)
            results = testGETXSS(url, {})
            reproduced, alertBox, message, confirmedBrowsers, alertBrowsers = makeMarkdownTable(results, token)
            if reproduced:
                return VulnTestInfo(reproduced=True,
                                    message=('Successfully found and confirmed an XSS at `%s`!\n'
                                             '\n\n%s\n\n'
                                             'Metadata: {"vulnDomain": "%s"}') %
                                            (url, message, urlparse(url).hostname),
                                    type='XSS',
                                    info={'src': url,
                                          'method': 'unstructured',
                                          'confirmedBrowsers': confirmedBrowsers,
                                          'alertBrowsers': alertBrowsers,
                                          'httpType': 'GET',
                                          'cookies': {}})
            elif alertBox:
                return VulnTestInfo(reproduced=False,
                                    message=('Failed to confirm the vulnerability! Detected an alert '
                                             'box but the token: `"%s"` was not found!'
                                             '\n\n%s\n\n') % (token, message),
                                    type='XSS',
                                    info={'src': url,
                                          'method': 'unstructured'})
    if len(testedURLs) > 0:
        return VulnTestInfo(reproduced=False,
                            message=constants.structuredDataMessage % 'XSS',
                            type='XSS',
                            info={'method': 'unstructured'})
    else:
        return VulnTestInfo(reproduced=False,
                            message=constants.failedToFindURLsMessage,
                            type='XSS',
                            info={'method': 'unstructured'})


def testGETXSS(url: str, cookies: Mapping[str, str]) -> Mapping[str, Optional[str]]:
    """ If the given URL pops an alert box when accessed with the given cookies, return the contents of the alert box,
        otherwise return None """
    return {name: testGETXSSDriver(url, cookies, getDriver()) for name, getDriver in SeleniumDrivers.drivers.items()}


def testGETXSSDriver(url: str, cookies: Mapping[str, str], driver: webdriver) -> Optional[str]:
    """ If the given URL pops an alert box when accessed with the given cookies, return the contents of the alert box,
        otherwise return None """
    driver.setCookies(url, cookies)

    try:
        driver.get(url)

        WebDriverWait(driver, config.timeout).until(expected_conditions.alert_is_present())
        # Note that despite the name switch_to_alert also handles prompt:
        #   - http://selenium-python.readthedocs.io/navigating.html#popup-dialogs
        alert = driver.switch_to_alert()
        text = alert.text
        driver.reset()
        return text
    except (TimeoutException, URLError):
        driver.reset()
        return None


def testPOSTXSS(url: str, cookies: Mapping[str, str], data: Mapping[str, str]) -> Mapping[str, Optional[str]]:
    """ If the given URL pops an alert box when accessed with the given cookies, return the contents of the alert box,
        otherwise return None """
    return {name: testPOSTXSSDriver(url, cookies, data, getDriver())
            for name, getDriver in SeleniumDrivers.drivers.items()}


def testPOSTXSSDriver(url: str, cookies: Mapping[str, str], data: Mapping[str, str], driver: webdriver) -> \
        Optional[str]:
    """ If the given URL pops an alert box when accessed with the given cookies, return the contents of the alert box,
        otherwise return None """
    driver.setCookies(url, cookies)

    try:
        driver.post(url, data)

        WebDriverWait(driver, config.timeout).until(expected_conditions.alert_is_present())
        # Note that despite the name switch_to_alert also handles prompt:
        #   - http://selenium-python.readthedocs.io/navigating.html#popup-dialogs
        alert = driver.switch_to_alert()
        text = alert.text
        driver.reset()
        return text
    except (TimeoutException, URLError):
        driver.reset()
        return None


def makeMarkdownTable(results: Mapping[str, Optional[str]], token: str) -> Tuple[bool, bool, str, List[str], List[str]]:
    """ Make a sorted markdown table from the results and the token
         - Returns (reproduced, alertBox, table, list[confirmed browsers], list[alert browsers]) """
    message = '##Results: \n\nDriver | Results\n--- | ---\n'
    reproduced = False
    alertBox = False
    confirmedBrowsers = []
    alertBrowsers = []
    # Store them in arrays so we only have to do one pass through results but can still get a sorted table
    working = []  # type: List[str]
    alert = []  # type: List[str]
    notWorking = []  # type: List[str]
    for driver, result in results.items():
        if result and token in result:
            reproduced = True
            alertBox = True
            confirmedBrowsers.append(driver)
            alertBrowsers.append(driver)
            working += '%s | %s\n' % (driver, 'XSS confirmed working!')
        elif result:
            alertBox = True
            alertBrowsers.append(driver)
            alert += '%s | %s\n' % (driver, ('Found an alert box, but no token found! Please reply with a URL '
                                             'that will pop an alert box containing `"%s"` (for example: '
                                             '`https://example.com/xss.php?q=<script>alert("%s")</script>`)')
                                    % (token, token))
        else:
            notWorking += '%s | %s\n' % (driver, 'No alert box found!')
    for res in working + alert + notWorking:
        message += res
    return reproduced, alertBox, message, confirmedBrowsers, alertBrowsers
