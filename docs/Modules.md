# Modules

Adding support for verifying a new class of vulnerability is done through the modules system. `src/modules/` currently 
three example modules: `xss.py`, `openRedirect.py`, and `sqli.py`. 

## Functions

A module has to implement three different functions:

- ```containsExploit(text: str) -> bool```
- ```match(reportBody: str, reportWeakness: str) -> bool```
- ```process(report: AutoTriageUtils.ReportWrapper) -> AutoTriageUtils.VulnTestInfo```

The ```containsExploit``` function should return whether the given string contains evidence of exploiting the specific 
class of vulnerability. This doesn't need to be super accurate, so for example the ```containsExploit``` function for 
SQL injection simply returns whether `or`, `and`, `select`, `from`, or `where` appear in the text. 

The ```match``` function should return whether the given report body and weakness are about this class of 
vulnerability. The ```match``` function for SQL injection simply returns whether `sqli` or `sql injection` are in the 
report body or weakness. 

The ```process``` function should return a VulnTestInfo (defined in `DataTypes.py`) NamedTuple: 

``` python
VulnTestInfo(reproduced=<True, False>,  # If set to True, then the report will be marked as triaged
             info={}  # Debugging information: Not required to store any information in the dict
             message=""  # Message to be posted on HackerOne
             type="")  # Debugging information: Short string describing the class of vulnerability
```

The ```process``` function needs to handle the conversational aspect of the bot along with the actual verification of 
vulnerabilities. 

In addition, you must add your module to `src/modules/__init__.py`. 