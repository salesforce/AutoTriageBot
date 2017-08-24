"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

# For security reasons, we want to restart the browser containers after every use. Docker doesn't provide any native
# way of doing this (other than forwarding the docker socket-which would allow an easy container escape) so we rely
# on Docker Swarm's autorestart feature that restarts any containers where the main process exits. This means all
# we need to do to restart a container is kill the java process inside of it. So we host a web server with an
# authenticated /kill endpoint that kills java. We also have a /isUp endpoint that simply returns True that is used to
# check whether the container has been restarted.

from flask import Flask, request
from subprocess import check_output

secret = open('/run/secrets/KillToken', 'r').read().strip()
app = Flask(__name__)


@app.route('/kill')
def kill():
    """ Restart the docker container this process is running in by killing java """
    token = request.args.get('token')
    if token == secret:
        # Restart the docker container by killing java
        pid = check_output(['pidof', 'java']).strip()
        check_output(['kill', pid])
        return 'Killed'
    return 'Authentication Failed'


@app.route('/isUp')
def isUp():
    """ Whether this docker container is up """
    return 'True'


app.run(host='0.0.0.0', port=4242)
