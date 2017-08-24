"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot import sqlite
import pytest
import sqlite3


@pytest.mark.fast
def test_initDB():
    sqlite.initDB()
    con = sqlite3.connect('/sqlite/AutoTriageBotDB.sqlite3')
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Failures'")
    res = cur.fetchall()
    assert res[0][0] == 'Failures'
    assert len(res) == 1


@pytest.mark.fast
def test_addCount():
    currentCount = sqlite.countFailures("TestFailureUser")
    sqlite.addFailureToDB("TestFailureUser", "ID")
    assert sqlite.countFailures("TestFailureUser") == (currentCount + 1)
    # add and count are case insensitive
    sqlite.addFailureToDB("TESTFAILUREUSER", "IDAGAIN")
    assert sqlite.countFailures("testfailureuser") == (currentCount + 2)
