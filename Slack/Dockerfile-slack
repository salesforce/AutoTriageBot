# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

FROM bot:latest

USER root
RUN apk --no-cache add caddy python3
COPY Caddyfile /etc/caddy/Caddyfile

CMD cd /app; PYTHONPATH=./ python3 /app/Slack/slackServer.py & caddy -conf /etc/caddy/Caddyfile

