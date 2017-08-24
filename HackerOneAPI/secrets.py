"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import config

try:
    apiToken = open('/run/secrets/HackerOneAPIToken', 'r').read().strip()
    apiBoxToken = open('/run/secrets/APIBoxToken', 'r').read().strip()
except FileNotFoundError as e:
    if config.DEBUGVERBOSE:
        # So we can at least start to run the program outside docker
        apiToken = ''
        apiBoxToken = ''
    else:
        raise e
