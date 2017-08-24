# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

FROM alpine:3.5

RUN apk add --no-cache python3

RUN adduser -S bot
USER bot
WORKDIR /home/bot/

ADD requirements.txt /home/bot/requirements.txt

COPY bot.zip /
USER root
RUN chown bot /bot.zip
RUN mkdir /app
RUN chown bot /app
USER bot
RUN unzip /bot.zip -d /app
USER root
RUN chown bot /home/bot/requirements.txt
RUN chown -R bot /app/
RUN pip3 install -r requirements.txt
RUN mkdir /sqlite; chown -R bot /sqlite
USER bot
CMD chown -R bot /sqlite; cd /app; python3 runBot.py
