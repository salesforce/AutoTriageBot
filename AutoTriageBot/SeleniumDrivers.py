"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from selenium.common.exceptions import WebDriverException
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from urllib.parse import urlparse, urlunparse
from typing import Mapping, TypeVar, Callable
import signal
from selenium.common.exceptions import TimeoutException
from urllib.error import URLError
import time
import requests
from AutoTriageBot import secrets
from AutoTriageBot import config


class Driver():
    """ Driver class abstracting over the required selenium operations we need to do """
    def __init__(self):
        self.driver = None  # type: webdriver

    def setCookies(self, url: str, cookies: Mapping[str, str]) -> None:
        """ Set cookies for the given URL """
        if cookies:
            parsed = urlparse(url)
            # In order to set cookies, we have to go to an html page on the same domain
            self.driver.get(parsed.scheme + '://' + parsed.netloc)
            for key, val in cookies.items():
                self.driver.add_cookie({'name': key, 'value': val, 'domain': parsed.netloc})

    def get(self, url, *args, **kwargs) -> None:
        """ GET the given URL while enforcing a 60 second timeout and handling error pages """
        def timeoutHandler(signum, frame):
            raise TimeoutException("Timeout!")
        signal.signal(signal.SIGALRM, timeoutHandler)
        signal.alarm(60)
        try:
            self.driver.get(url, *args, **kwargs)
        except WebDriverException as e:
            if 'Message: Reached error page:' in str(e):
                return None
            raise e
        finally:
            signal.alarm(0)

    def post(self, url: str, data: Mapping[str, str]) -> None:
        """ POST the given URL while enforcing a 60 second timeout and handling error pages """
        def timeoutHandler(signum, frame):
            raise TimeoutException("Timeout!")
        signal.signal(signal.SIGALRM, timeoutHandler)
        signal.alarm(60)
        try:
            parsed = urlparse(url)
            # In order to POST data, we have to go to an HTML page on the same domain and then use
            # JS to kick off the post
            self.driver.get(parsed.scheme + '://' + parsed.netloc)
            js = ("function post(path) {\n"
                  "    var form = document.createElement('form');\n"
                  "    form.setAttribute('action', path);\n"
                  "    form.setAttribute('method', 'post');\n"
                  "%s"
                  "    document.body.appendChild(form);\n"
                  "    form.submit();\n"
                  "}\n")
            fields = ''
            for index, (key, val) in zip(range(len(data.items())), data.items()):
                i = str(index)
                field = ("    var a%s = document.createElement('input');\n"
                         "    a%s.setAttribute('name', '%s');\n"
                         "    a%s.setAttribute('value', '%s');\n"
                         "    form.appendChild(a%s);\n") % (i,
                                                            i,
                                                            key.replace("'", "\\'"),
                                                            i,
                                                            val.replace("'", "\\'"),
                                                            i)
                fields += field
            js = js % fields
            path = urlunparse(['', '', parsed.path, parsed.params, parsed.query, parsed.fragment])
            js += "post('%s');\n" % path
            self.driver.execute_script(js)
        except Exception as e:
            signal.alarm(0)
            raise e

    def reset(self) -> None:
        # If you are adding support for additional browsers that will use this reset method, ensure that their hostname
        # matches the name of the driver
        hostname = self.driver.name
        self.driver.quit()
        if config.DEBUGVERBOSE:
            print('Killing: http://%s:4242/kill?token=%s' % (hostname, secrets.killToken))
        # For security reasons, we kill each browser container after every request to ensure no data is leaked between
        # runs
        r = requests.get('http://%s:4242/kill?token=%s' % (hostname, secrets.killToken))
        assert 'Killed' in r.text
        isDown = True
        while isDown:
            time.sleep(1)

            def timeoutHandler(signum, frame):
                raise TimeoutException("Timeout!")

            signal.signal(signal.SIGALRM, timeoutHandler)
            signal.alarm(5)
            try:
                requests.get('http://%s:4242/isUp' % hostname)
                signal.alarm(0)
                isDown = False
            except:
                signal.alarm(0)
        signal.alarm(0)
        time.sleep(5)

    def __getattr__(self, name):
        """ Everything else we pass through directly to the driver"""
        return getattr(self.driver, name)


class FirefoxDriver(Driver):
    """ FirefoxDriver class """
    def __init__(self):
        try:
            self.driver = webdriver.Remote(command_executor='http://firefox:4444/wd/hub',
                                           desired_capabilities=DesiredCapabilities.FIREFOX)
        except URLError as e:
            print("Failed to connect!")
            raise e


class ChromeDriver(Driver):
    """ ChromeDriver class """
    def __init__(self):
        try:
            self.driver = webdriver.Remote(command_executor='http://chrome:4444/wd/hub',
                                           desired_capabilities=DesiredCapabilities.CHROME)
        except URLError as e:
            print("Failed to connect!")
            raise e


def getChromeDriver() -> webdriver:
    """ Get a chrome driver """
    return retry(ChromeDriver)


def getFirefoxDriver() -> webdriver:
    """ Get a firefox driver """
    return retry(FirefoxDriver)


T = TypeVar('T')
delayTime = 15


def retry(func: Callable[[], T]) -> T:
    """ Retry the function with 30 second timeouts until it works
        - I've observed the getFirefoxDriver() without this freeze once (out of hundreds of runs...) so adding this
          as a safety measure. """
    for i in range(10):
        if config.DEBUG and i > 0:
            print("Retry #%s" % str(i))

        def timeoutHandler(signum, frame):
            raise TimeoutException("Timeout!")
        signal.signal(signal.SIGALRM, timeoutHandler)
        signal.alarm(delayTime)
        try:
            t = func()
            signal.alarm(0)
            return t
        except TimeoutException:
            pass
    signal.alarm(0)
    raise TimeoutException("Retried 10 times... Failed!")


drivers = {'Chrome': getChromeDriver, 'Firefox': getFirefoxDriver}
