"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

import pytest
from AutoTriageBot import secrets


@pytest.mark.fast
def test_secrets():
    # This will fail if run outside of docker
    assert secrets.slackOauth != ''
    assert secrets.killToken != ''
    assert secrets.apiBoxToken != ''
