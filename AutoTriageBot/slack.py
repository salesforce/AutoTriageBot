"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from typing import Mapping, Optional, List

from AutoTriageBot import secrets
from AutoTriageBot import config

from slacker import Slacker


def postMessage(message: str, channel: str=config.channel, attachments: List=[]) -> Optional[Mapping]:
    """ Post a message to the specified slack channel """
    if secrets.slackOauth:
        slack = Slacker(secrets.slackOauth)
        if channel:
            resp = slack.chat.post_message(channel, message, attachments=attachments)
            return resp.body
    return None


class SlackException(Exception):
    pass
