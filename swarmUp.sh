#!/bin/bash -ex

# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

docker service update --replicas 1 bot
docker service update --replicas 1 api
docker service update --replicas 1 chrome
docker service update --replicas 1 firefox
docker service update --replicas 1 vulnserver
docker service update --replicas 1 slack
