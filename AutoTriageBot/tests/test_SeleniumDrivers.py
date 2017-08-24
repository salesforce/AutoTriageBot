"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot import SeleniumDrivers
import time
import pytest


def test_retry(monkeypatch):
    monkeypatch.setattr(SeleniumDrivers, 'delayTime', 2)

    class SometimesDelay():
        cnt = 0

        def __call__(self):
            self.cnt += 1
            if self.cnt < 3:
                time.sleep(20)
            return "Finished after %s tries!" % str(self.cnt)

    sd = SometimesDelay()
    startTime = time.time()
    assert SeleniumDrivers.retry(sd) == "Finished after 3 tries!"
    assert 4 < time.time() - startTime < 5


@pytest.mark.integration
def test_reset():
    # Just test that it restarts properly
    driver = SeleniumDrivers.getFirefoxDriver()
    driver.reset()
    SeleniumDrivers.getFirefoxDriver()
