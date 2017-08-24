# Payout Suggestions

Payout suggestions are done based off of historical averages which have to be manually entered into the config file. The suggestions are done based off of the class of vulnerability and the domain the vulnerability was found on. 

In order to add support for suggesting payouts for a new class of vulnerability, you have to add that information in both the `payoutDB` variable in the config file and in `AutoTriageBot/payout.py`. 