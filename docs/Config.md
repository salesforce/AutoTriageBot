# AutoTriageBot Configuration

AutoTriageBot has two config files: `AutoTriageBot/config.py` and `HackerOneAPI/config.py`. See [`BotConfig.md`](BotConfig.md) for documentation on `AutoTriageBot/config.py` and [`APIConfig.md`](APIConfig.md) for documentation on `HackerOneAPI/config.py`. 

Both config files are simply a python program. This means you can embed arbitrary python into the config file if you want to dynamically generate any of the config options. 

In addition, if you are using the Slack integration then you must create a Caddyfile in Slack directory with these contents:

```
<Domain Name> {
    tls <Contact Email Address>
    proxy /slack http://127.0.0.1:8080
}
```