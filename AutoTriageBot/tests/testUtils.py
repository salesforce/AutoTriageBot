"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""


class Counter():
    def __init__(self, ret=None):
        self.count = 0
        self.lastCall = None
        self.ret = ret

    def __call__(self, *args, **kwargs):
        self.count += 1
        self.lastCall = (args, kwargs)
        return self.ret
