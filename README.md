![AutoTriageBotBanner](docs/Logos/AutoTriageBotBanner.png)

Automatically verify, deduplicate, and suggest payouts for vulnerability reports through HackerOne. 

Currently, this bot can automatically verify reports about XSS, SQLi, and Open Redirect vulnerabilities (via both GET and POST). In addition, it is built in a modular manner so that it can be easily expanded to add tests for other classes of vulnerabilities. 

## Security: 

AutoTriageBot is effectively SSRF as a Service. In order to securely run AutoTriageBot, it must be run in an isolated environment. It is **highly** recommended to set up a blacklist blocking AutoTriageBot from reaching any potentially dangerous IP addresses. See [Architecture.md](docs/Architecture.md) for three suggested firewall configurations.  

## Usage:

Follow the directions in [`docs/Config.md`](docs/Config.md) to configure AutoTriageBot. Then run `swarmCreate.sh` to start the swarm and run the bot (it will prompt you for API keys). Note that the HackerOne API key needs to be a member of the "Standard" group. 

```bash
./swarmCreate.sh
```

To rebuild the bot, run `./rebuild.sh`. To start and stop the bot, run `./swarmUp.sh` and `./swarmDown.sh` respectively. 

## Tests: 

To run tests, run `runTests.py` with the appropriate flag: 

```
usage: runTests.py [-h] [--fast] [--integration] [--all] [--norestart]
                   [--slow]

Run tests

optional arguments:
  -h, --help     show this help message and exit
  --fast         Run the fast tests
  --integration  Run the integration tests
  --all          Run all of the tests
  --norestart    Don't restart docker
  --slow         Run the slow tests
```

## Docs & Examples:

See the `docs/` folder for further documentation on usage, development, and architecture. 

See the `docs/ExampleReports/` folder for a number of example interactions between the bot and a reporter. 

## Info: 

Copyright Salesforce.com 2017, developed by [David Dworken](https://github.com/ddworken) as an internship project. Pull requests welcome!
