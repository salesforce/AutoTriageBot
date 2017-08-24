This config file should be placed in `HackerOneAPI/config.py`. 

### HackerOne: 

First we'll need to set the HackerOne config options: 

```python
apiName = "<HackerOne Bot Name>"
programName = "<HackerOne Program Name>"
```

- `apiName` should be set to the "Identifier" associated with the API key in HackerOne's API Settings page. 
- `programName` should be set to the name of the program. This is the path used to access your HackerOne page (e.g. if your page is at `https://hackerone.com/example` then `programName` shoul be set to `example`). 

### Debugging

To enable debugging information, there are two boolean options: `DEBUG` and `DEBUGVERBOSE`. Note that `DEBUGVERBOSE` does not imply `DEBUG`. 

```python
DEBUG = True
DEBUGVERBOSE = True
```

To disable debugging information, set them both to `False`:

```python
DEBUG = False
DEBUGVERBOSE = False
```

Note that it is generally recommended to keep debugging information enabled. 

### Misc. Options

You can configure the stop phrase: 

```python
stopPhrase = "STOP TRIAGEBOT"
```
