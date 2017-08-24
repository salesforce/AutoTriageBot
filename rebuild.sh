#!/bin/bash -ex

# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

./buildBot.sh
cd HackerOneAPI; ./build.sh; cd ..
cd Selenium; ./build.sh; cd ..
cd Slack; ./build.sh; cd ..
cd Vulnserver; ./build.sh; cd ..

./swarmDown.sh
./swarmUp.sh
