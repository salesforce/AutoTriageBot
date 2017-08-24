# Browsers

Currently AutoTriageBot has support for controlling Chrome and Firefox, but it can be easily expanded to control any type of browser that is supported by Selenium. As an example, here is how we would add support for running tests against Edge. In this example, we'll assume that the edge box is running on a separate server (outside docker) at `198.51.100.1`. 

The first step would be defining our wrapper class `EdgeDriver` that extends `Driver`: 

``` python
class EdgeDriver(Driver):
    """ EdgeDriver class """
    def __init__(self):
        try:
            self.driver = webdriver.Remote(command_executor='http://198.51.100.1:4444/wd/hub', 
                                           desired_capabilities=DesiredCapabilities.EDGE)
        except URLError as e:
            print("Failed to connect!")
            raise e
```

Since our Edge server is not running in docker, we'll also have to override the default `reset` method provided by the Driver superclass. 

``` python
    def reset(self):
        self.driver.quit()
```

For additional security, one could build functionality to delete and recreate the whole windows instance into the reset method (as is done for Firefox and Chrome), but that isn't necessary for this example. 

The next step is to define a function that returns a new EdgeDriver: 

``` python
def getEdgeDriver() -> webdriver:
    """ Get an edge driver """
    return EdgeDriver()
```

And the final step is to add it to the dictionary containing all of the supported browsers. This dictionary is used for modules that choose to run tests against all of the available browsers rather than a single browser. 

``` python
drivers = {'Chrome': getChromeDriver, 'Firefox': getFirefoxDriver, 'Edge': getEdgeDriver}
```