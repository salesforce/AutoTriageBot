"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot import config


disableMessage = '\n\nTo disable AutoTriageBot, reply with %s' % config.stopPhrase


def initialMessage(token: str, description: str, type: str) -> str:
    """ Generate the initial message containing the given information """
    return (('We have detected that this report is about an ' + type + ' vulnerability. \n\n'
             'To triage this bug quicker, '
             'this bot can automatically verify vulnerabilities.\n\n'
             'Try either:\n'
             '* Posting a URL that will %s containing `"%s"`\n'
             '* Use the JSON structure below to change the method and/or add cookies\n\n'
             '# Examples: \n\n'
             '## Option 1: Unauthenticated GET\n'
             'If it can be exploited without authentication via simply loading a URL, respond with a link that when '
             'visited will %s containing `"%s"`. The link should either be specified as a markdown link '
             '(`[text](https://example.com)` '
             'or inside a code block (``` `https://example.com` ```). \n\n'
             '## Option 2: Authenticated GET\n'
             'If doing so requires authentication, then please copy and paste the below '
             'into JSON a code block and fill in the blanks: \n\n'
             '```\n'
             '{\n'
             '    "URL": "<Fill in the URL here>",\n'
             '    "cookies": {"CookieOneName":   "CookieOneValue", \n'
             '                "CookieTwoName":   "CookieTwoValue", \n'
             '                "CookieThreeName": "CookieThreeValue"}, \n'
             '    "type": "get" \n'
             '}\n'
             '```\n\n'
             '## Option 3: Authenticated POST\n'
             'If the exploit requires authentication and is done via POST, then please copy '
             'and paste the below into a code block and fill in the blanks: \n\n'
             '```\n'
             '{\n'
             '    "URL": "<Fill in the URL here>",\n'
             '    "cookies": {"CookieOneName":   "CookieOneValue", \n'
             '                "CookieTwoName":   "CookieTwoValue", \n'
             '                "CookieThreeName": "CookieThreeValue"}, \n'
             '    "type": "post", \n'
             '    "data": {"ArgumentOneName":   "ArgumentOneValue", \n'
             '             "ArgumentTwoName":   "ArgumentTwoValue", \n'
             '             "ArgumentThreeName": "ArgumentThreeValue"} \n'
             '}\n'
             '```\n'
             '\n'
             'If this is not possible, there is no need to reply and a human will verify '
             'your report as soon as possible. \n\n'
             'Metadata: `{"token": "%s"}`')) % (description, token, description, token, token)


structuredDataMessage = ('We failed to find an %s by following any of the URLs specified. \n\n'
                         'If you would like to try again with AutoTriageBot, please follow the '
                         'above directions.')


failedToFindURLsMessage = ("We failed to find any URLs in your comment. Please include the link in either a markdown "
                           "link (for example: `[link text](https://example.com)`) or in a code block (for example: "
                           "`` `https://example.com` ``).")
