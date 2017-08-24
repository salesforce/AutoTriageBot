"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from os import rename
from AutoTriageBot import sqlite


def pytest_runtest_call(item):
    if isinstance(item, item.Function):
        backupDB()
        item.runtest()
        restoreDB()


def backupDB():
    rename('/sqlite/AutoTriageBotDB.sqlite3', '/sqlite/AutoTriageBotDB.sqlite3.bak')
    sqlite.initDB()


def restoreDB():
    rename('/sqlite/AutoTriageBotDB.sqlite3.bak', '/sqlite/AutoTriageBotDB.sqlite3')
