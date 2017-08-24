"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import sqlite3
from pathlib import Path


def initDB(filename: str='/sqlite/AutoTriageBotDB.sqlite3') -> None:
    Path(filename).touch()
    con = sqlite3.connect(filename)
    cur = con.cursor()
    cur.execute("create table if not exists Failures (Username TEXT, ID TEXT)")
    con.commit()
    con.close()


def addFailureToDB(username: str, id: str, filename: str='/sqlite/AutoTriageBotDB.sqlite3') -> None:
    """ Log a failure of the bot for the given username on the given ID in the Failures table """
    print("Adding failure for username=%s on id=%s to DB!" % (username, id))
    con = sqlite3.connect(filename)
    cur = con.cursor()
    cur.execute("INSERT INTO Failures VALUES(?, ?)", (username.lower(), id))
    con.commit()
    con.close()


def countFailures(username: str, filename: str='/sqlite/AutoTriageBotDB.sqlite3') -> int:
    """ Count the number of times the bot has failed for the given username """
    con = sqlite3.connect(filename)
    cur = con.cursor()
    cur.execute('SELECT COUNT(*) FROM Failures WHERE Username=?', (username.lower(),))
    ret = cur.fetchone()[0]
    con.commit()
    con.close()
    assert isinstance(ret, int)
    return ret
