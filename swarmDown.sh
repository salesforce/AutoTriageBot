#!/bin/bash -ex

# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

docker service update --replicas 0 bot
docker service update --replicas 0 api
docker service update --replicas 0 chrome
docker service update --replicas 0 firefox
docker service update --replicas 0 vulnserver
docker service update --replicas 0 slack
