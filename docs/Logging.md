# Logging

AutoTriageBot uses Docker's built in logging to manage all logs. This means that within the containers, in order to output data to the logs simply print it to stdout. 

For general management of AutoTriageBot, you can use `docker service logs <bot|api|firefox|chrome> --follow`.  In order to save the logs for later analysis, you'll need to configure a [logging driver](https://docs.docker.com/engine/admin/logging/overview/). 