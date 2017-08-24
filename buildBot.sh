#!/bin/bash -ex

# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

touch bot.zip; rm bot.zip
zip -q -r bot.zip . -x *.git* -x *.venv*
docker build -t bot:latest -f Dockerfile-bot .
