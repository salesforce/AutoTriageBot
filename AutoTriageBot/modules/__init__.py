"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from AutoTriageBot.modules import xss, openRedirect, sqli

modules = [openRedirect, xss, sqli]

__all__ = ['xss', 'openRedirect', 'sqli']
