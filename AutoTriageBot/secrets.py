"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot import config


def tryRead(filename):
    try:
        return open(filename, 'r').read().strip()
    except FileNotFoundError as e:
        if config.DEBUGVERBOSE:
            # So we can at least start to run the program outside docker
            return ''
        raise e


slackOauth = tryRead('/run/secrets/SlackAPIToken')
killToken = tryRead('/run/secrets/KillToken')
apiBoxToken = tryRead('/run/secrets/APIBoxToken')
