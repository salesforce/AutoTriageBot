#!/usr/bin/env python3

"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from os import system
import argparse
import time
from typing import Optional, List  # noqa

parser = argparse.ArgumentParser(description='Run tests')
parser.add_argument('--fast', action='store_true', help='Run the fast tests')
parser.add_argument('--integration', action='store_true', help='Run the integration tests')
parser.add_argument('--all', action='store_true', help='Run all of the tests')
parser.add_argument('--norestart', action='store_true', help='Don\'t restart docker')
parser.add_argument('--slow', action='store_true', help='Run the slow tests')
parser.add_argument('--none', action='store_true', help='Don\'t run any tests (only pep8 and mypy)')

args = parser.parse_args()

if not args.none:
    marks = []  # type: Optional[List[str]]

    if args.all:
        marks = None
    elif args.fast:
        marks.append("fast")
    elif args.integration:
        marks.append("integration")
    elif args.slow:
        marks.append("slow")
    else:
        print("Must supply a flag!")
        exit(1)

    if marks:
        flag = '-m %s' % ','.join(marks)
    else:
        flag = ''

    if not args.norestart:
        system('./rebuild.sh')

    time.sleep(10)

    print("Running: %s" % ("bash -c 'docker exec -it `docker ps -qf name=bot` python3 -m pytest -vv %s /app'" % flag))
    system("bash -c 'docker exec -it `docker ps -qf name=bot` python3 -m pytest -vv %s /app'" % flag)
print("Running pep8 and mypy...")
system("flake8 ./ --max-line-length 120 --exclude=.venv,dev")
system("mypy *py HackerOneAPI/ AutoTriageBot/ --ignore-missing-imports")
