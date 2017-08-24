# Selenium

`SeleniumDrivers.py` holds a wrapper class around Selenium webdrivers that is used to provide additional functionality. The `Driver` class implements 4 additional methods: 

### setCookies(url: str, cookies: Mapping[str, str]) -> None

Selenium natively provides an add_cookie method, but it only works once the webdriver has already navigated to a page on the domain for which you want to set the cookies. This setCookies method does not have that limitation. 

### get(url, *args, **kwargs) -> None

This method is a wrapper around the webdriver.get method with two changes. First, it enforces a 60 second timeout (via the signal library) in order to defend against DoS attacks. Second, it ignores Firefox's error pages. 

### post(url: str, data: Mapping[str, str]) -> None

Selenium does not natively provide any method of sending POST requests so this is a wrapper around the webdriver.get method that uses JS to execute the POST requests. Like the get method, it enforces a 60 second timeout. 

### reset() -> None

This method resets the Docker container holding the selenium webdriver. This should be called after every test to ensure that reporters are properly isolated from each other. 