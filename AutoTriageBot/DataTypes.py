"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from typing import NamedTuple, Mapping, Any
from datetime import datetime

# Represents the results of a vulnerability test
VulnTestInfo = NamedTuple("VulnTestInfo", [('reproduced', bool),
                                           ('info', Mapping[str, Any]),
                                           ('message', str),
                                           ('type', str)])

# A simple representation of a report (used for duplicate testing purposes)
ReportData = NamedTuple('ReportData', [('title', str),
                                       ('body', str),
                                       ('time', datetime),
                                       ('state', str),
                                       ('id', str),
                                       ('weakness', str)])

# Used to represent a parsed and normalized URL
URLParts = NamedTuple("URLParts", [('domain', str),
                                   ('path', str),
                                   ('queries', Mapping[str, str])])

# Used to hold information about expected bounties
BountyInfo = NamedTuple('BountyInfo', [('average', float),
                                       ('std',     float)])
