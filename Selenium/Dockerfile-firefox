# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

FROM selenium/standalone-firefox:3.4.0-dysprosium

USER root
RUN apt-get update
RUN apt-get install -y python3 python3-pip
USER seluser
RUN pip3 install flask

ADD SeleniumKiller.py /opt/bin/SeleniumKiller.py
USER root
RUN chown seluser:seluser /opt/bin/SeleniumKiller.py
RUN chmod +x /opt/bin/SeleniumKiller.py
USER seluser

EXPOSE 4242

CMD python3 /opt/bin/SeleniumKiller.py & /opt/bin/entry_point.sh