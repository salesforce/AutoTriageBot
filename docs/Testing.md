# Tests

Tests are written using py.test and are in the `AutoTriageBot/tests` directory. There are a mix of integration tests and unit tests. Note that the core vulnerability detection logic is tested in `AutoTriageBot/tests/test_vulnDetection.py`. Code in other containers is tested at an integration level via the APIs they expose. 
