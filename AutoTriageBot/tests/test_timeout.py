"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import pytest
import time
from AutoTriageBot import SeleniumDrivers
from selenium.common.exceptions import TimeoutException


# VERY slow!
@pytest.mark.slow
def test_seleniumTimeout():
    driver = SeleniumDrivers.getChromeDriver()
    start = time.time()
    driver.get('http://vulnserver/sqli.php?q=10')
    assert time.time() - start > 10 and time.time() - start < 11
    try:
        driver.get('http://vulnserver/sqli.php?q=70')
        assert False
    except TimeoutException:
        assert True
