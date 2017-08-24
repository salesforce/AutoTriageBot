#!/bin/bash -ex

# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

if [ ! -f AutoTriageBot/config.py ]; then
    echo "Config.py not found!"
    exit 1
fi

docker swarm init
docker network create --driver overlay overlayNetwork
docker volume create sqlite  # sqlite DB that persists between restarts

read -s -p "Enter your HackerOne API Key: " hackerone
echo $hackerone | docker secret create HackerOneAPIToken -
read -s -p "Enter your Slack API Key: " slack
echo $slack | docker secret create SlackAPIToken -
read -s -p "Enter your Slack Verification Token: " slack
echo $slack | docker secret create SlackVerificationToken -
python3 -c "from random import SystemRandom; from string import ascii_uppercase; print(''.join([SystemRandom().choice(ascii_uppercase) for _ in range(8)]))" | docker secret create KillToken -
python3 -c "from random import SystemRandom; from string import ascii_uppercase; print(''.join([SystemRandom().choice(ascii_uppercase) for _ in range(8)]))" | docker secret create APIBoxToken -

./buildBot.sh
cd HackerOneAPI; ./build.sh; cd ..
cd Selenium; ./build.sh; cd ..
cd Slack; ./build.sh; cd ..
cd Vulnserver; ./build.sh; cd ..

docker service create --replicas 1 --name bot --hostname bot --network overlayNetwork --mount src=sqlite,dst=/sqlite --limit-memory=1.5G --limit-cpu=0.5 --secret APIBoxToken --secret SlackAPIToken --secret KillToken --env PYTHONUNBUFFERED=1 bot:latest
docker service create --replicas 1 --name api --hostname api --network overlayNetwork --limit-memory=1G --limit-cpu=0.5 --secret HackerOneAPIToken --secret APIBoxToken --env PYTHONUNBUFFERED=1 api:latest
docker service create --replicas 1 --name chrome --hostname chrome --network overlayNetwork --limit-memory=1.5G --limit-cpu=0.75 --secret KillToken chrome:latest
docker service create --replicas 1 --name firefox --hostname firefox --network overlayNetwork --limit-memory=1.5G --limit-cpu=0.75 --secret KillToken firefox:latest
docker service create --replicas 1 --name vulnserver --hostname vulnserver --network overlayNetwork vulnserver:latest
docker service create --replicas 1 --name slack --hostname slack --secret SlackAPIToken --secret SlackVerificationToken --secret APIBoxToken -p 443:443 -p 80:80 --network overlayNetwork --mount type=bind,source=`pwd`,destination=/root/ slack:latest
