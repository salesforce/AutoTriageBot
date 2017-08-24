# Architecture

![Architecture Diagram](/docs/Architecture.png)

AutoTriageBot is built on top of Docker Swarm and Selenium. There are four docker containers: `bot`, `api`, `chrome`, and `firefox`. The `bot` container is the core of the application. Every 10 seconds it requests all new reports from the HackerOne API and processes them as shown in the above diagram. The `api` container handles all communication with the HackerOne API. This minimizes the attack surface against the HackerOne API keys (which have permission to award bounties) by storing them in a separate container from the majority of the codebase. The entire application is completely stateless so the containers can be safely started and stopped by the Docker Swarm daemon. 

Note that `AutoTriageBot/ReportWrapper.py` is symlinked to `HackerOneAPI/ReportWrapper.py`. In order to make this work, ReportWrapper cannot import from anything other than `config.py` which is maintained individually in `AutoTriageBot/` and `HackerOneAPI/`. 

## Security

### (SaaS) SSRF as a Service 

Since a HackerOne bot has to be able to request arbitrary webpages, a lot of effort has gone into preventing AutoTriageBot from being exploited. Before testing a domain, the bot checks that the domain matches a whitelist (defined in `AutoTriageUtils.isProgramURL`) and that the domain does not resolve to localhost. These defenses can be relatively easily bypassed (e.g. via a webpage that matches the whitelist but includes an iframe pointing to another website) so it is also key that AutoTriageBot is deployed in an isolated environment. 

There are three main options on how to configure an outbound firewall: 

1. Network level firewall

    a. A network level firewall is the most secure option for blocking outgoing requests. If available, it is the recommended option. 
    
2. Host level firewall

    a. Deploying a firewall on the host via iptables. This is is secure as long as an attacker cannot escape both the browser's sandbox and Docker. 
    
3. Container level firewall

    a. Deploying a firewall on the container via iptables. This is secure as long as an attacker cannot escape the browser's sandbox. This may be necessary if further integrations are being built out and you want to only blacklist IP ranges for certain containers. 

Note that if deployed to AWS you should also firewall off [AWS's metadata API](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html). 

### HackerOne API Keys

In order to post public comments on a HackerOne report API keys have to be a member of the "Standard" group that also allows them to reward bounties. This means that safely storing these keys is crucial. The API keys are securely stored in Docker secrets and only shared with the `api` container. The `api` container implements a limited wrapper with minimal (flask with basic auth) attack surface around the HackerOne API. All API requests are made through this container with basic auth using a password that is only shared to the `bot` container so as to further limit the attack surface. 

### Slack API Keys

The Slack API keys are securely stored in Docker secrets and only shared with the `bot` container. 

### Selenium

In order to ensure that all vulnerability reports are isolated from each other, each vulnerability test is run in a single use docker container. Since Docker doesn't natively expose any way to reset one docker container from within another docker container (except mounting the docker socket—which is a horrible idea), the `chrome` and `firefox` containers actually host two services. The first service is the selenium standalone server on port 4444. The second server is a simple flask web server on port 4242 that defines two endpoints: `/kill` and `/isUp`. The `/kill` endpoint is authenticated via a secret token and is used to kill the selenium server which triggers Docker Swarm to restart the container. The `/isUp` endpoint always returns `"True"` and is used to track whether the container has finished restarting. 

### DoS

To defend against DoS attacks, all web requests are made with 60 second timeouts. This defends the bot from a DoS attack via submitting a link that loads infinitely. In addition, it ensures that the bot cannot be used as an attack point to launch DoS attacks against other services. In addition, each report is limited to testing 5 URLs at a time. 