# Duplicate Detection

The currently duplicate detection algorithm is based solely off of the URLs included in reports. From these URLs, we extract 12 different signals: 

1. `malLinksInCommon`: The number of malicious links in common
2. `linksInCommon`: The number of links in common
3. `malLinks1`: The number of malicious links in the first report
4. `malLinks2`: The number of malicious links in the second report
5. `parametersInCommon`: The number of GET parameters in common
6. `malParametersInCommon`: The number of malicious GET parameters in common
7. `pathsInCommon`: The number of paths in common
8. `malPathsInCommon`: The number of malicious paths in common
9. `domainsInCommon`: The number of domains in common
10. `malDomainsInCommon`: The number of malicious domains in common
11. `injectionParametersInCommon`: The number of malicious parameter, argument tuples in common
12. `symDiffDomains`: The symmetric difference of the domains in the report

Based off of this data, reports are classified as duplicates with a certain confidence level. The 12 different signals are generated in the `sameCategoryIsDuplicate` function and the calculations are done in the `decide` function. The confidences for each of the signals were calculated through backtesting on historical data and some bayesian statistics. 

## Failed Duplicate Detection Efforsts

This area of the code could definitely be improved, so here is a rough list of what I've tried so far: 

My first attempt at deduplication was based off of a very simplistic model of looking at the [levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance) between paragraphs (defined by new lines) between two reports. This was not accurate since it failed to take into account any variability in human language. In back testing, it was not significantly better than a random guess. 

From there I attempted to use a pretrained doc2vec model (included in ```gensim```) in order to compare similarity. This was relatively successful at classifying vulnerability reports as being about a certain category of vulnerability, but it was not able to accurately determine whether two reports were duplicates. 

My next idea was to look at the links and classify reports based off of links in common with any payloads (e.g. ```<script>alert(0)</script>``` vs ```<svg src=! onerror=alert(0)></svg>```) sanitized. This ran into the issue that reports include unnecessary links (e.g. help docs). In addition, since Salesforce hosts customer orgs on different domains (e.g. ```na44.salesforce.com``` vs ```na45.salesforce.com```), links could be seemingly very different yet be referencing the same components. 

This led to the current implementation where we extract a number of different signals and through backtesting determine what provides a useful signal for duplicate detection. 