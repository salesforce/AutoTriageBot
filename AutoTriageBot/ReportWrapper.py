"""
Copyright (c) 2017, salesforce.com, inc.
All rights reserved.
Licensed under the BSD 3-Clause license.
For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
"""

from typing import NewType, Mapping, List, Union, cast, Optional
from urllib.parse import urlparse
import json
from copy import deepcopy
from datetime import datetime
import arrow
import re
import ast

# Patching the path so we do a relative import for ReportWrapper
# This means we can symlink ReportWrapper in both AutoTriagebot/ and HackerOneAPI/
# See docs/Architecture.md for more info
# import os
# import sys
# sys.path.append(os.path.dirname(__file__))
from AutoTriageBot import config  # noqa
# sys.path = sys.path[:-1]


CommentJSON = NewType('CommentJSON', Mapping[str, Union[str, bool]])
# A CommentJSON is a mapping from str to str with the following mandatory keys:
#   - 'username' --> '<Commenter Username>'
#   - 'time'     --> '<Comment Time in ISO8601 Format>'
#   - 'body'     --> '<Comment Body>'
#   - 'internal' --> True/False
Serialized = NewType('Serialized', str)


class ReportWrapper():
    def __init__(self, *args) -> None:
        if len(args) == 0:
            return
        if len(args) == 1:
            hackeroneJson = args[0]
            assert isinstance(hackeroneJson, dict)
            self._json = hackeroneJson
            self.reportTitle = self._json['attributes']['title']
            self.reportBody = self._json['attributes']['vulnerability_information']
            try:
                self.reportWeakness = self._json['relationships']['weakness']['data']['attributes']['name']
            except KeyError:
                self.reportWeakness = ''  # Reporters are not required to provide one, so default to an empty string
            self.reportID = self._json['id']
            self.reportedTime = parseTime(self._json['attributes']['created_at'])  # type: datetime
            self.reportState = self._json['attributes']['state']

            self.reporterUsername = self._json['relationships']['reporter']['data']['attributes']['username']
            # comments come from H1 in sorted order (most recent first), so we don't need to sort them by date
            self.comments = []  # type: List[CommentJSON]
            try:
                for h1CommentJSON in self._json['relationships']['activities']['data']:
                    j = {'username':
                         cast(str, h1CommentJSON['relationships']['actor']['data']['attributes']['username']),
                         'time': cast(str, h1CommentJSON['attributes']['created_at']),
                         'body': cast(str, h1CommentJSON['attributes']['message']),
                         'internal': cast(bool, h1CommentJSON['attributes']['internal'])}
                    assert isinstance(j['username'], str)
                    assert isinstance(j['time'], str)
                    assert isinstance(j['body'], str)
                    assert isinstance(j['internal'], bool)
                    self.comments.append(cast(CommentJSON, j))
            except KeyError:
                # The HackerOne APi doesn't return comments when querying for all reports. Since we don't want to have
                # to request comments when doing duplicate testing, we make them optional
                pass
        if len(args) >= 2:
            raise ValueError("Too many arguments!")

    def serialize(self) -> Serialized:
        """ Dumps this object to a serialized version of it """
        data = deepcopy(self.__dict__)
        data['reportedTime'] = self.reportedTime.isoformat()
        return Serialized(json.dumps(data))

    def deserialize(self, data: Serialized):
        """ Loads this object from the serialized version """
        if isinstance(data, str):
            d = dict(json.loads(data))
        else:
            d = data
        d['reportedTime'] = parseTime(d['reportedTime'])
        self.__dict__ = d
        return self

    def getReportBody(self) -> str:
        """ Get the body of this report """
        return self.reportBody

    def getReportTitle(self) -> str:
        """ Get the title of this report """
        return self.reportTitle

    def getReportWeakness(self) -> str:
        """ Get the user provided weakness of this report """
        return self.reportWeakness

    def getReportID(self) -> str:
        """ Get the ID number of this report """
        return self.reportID

    def getReporterUsername(self) -> str:
        """ Get the username of the original reporter """
        return self.reporterUsername

    def getReportedTime(self) -> datetime:
        """ Get the time the report was created at """
        assert isinstance(self.reportedTime, datetime)
        return self.reportedTime

    def getState(self) -> str:
        """ Get the state of this report """
        return self.reportState

    def _getComments(self) -> List[CommentJSON]:
        """ Get a list of comments (represented by json) on this report """
        return self.comments

    def _getPublicComments(self) -> List[CommentJSON]:
        """ Get a list of public comments (represented by json) on this report """
        comments = self._getComments()
        return [comment for comment in comments if not comment['internal']]

    def __getCommentUsername(self, commentJson: CommentJSON) -> str:
        """ Get the username associated with the given comment """
        return cast(str, commentJson['username'])

    def _getAllCommentsByUsername(self, username: str) -> List[CommentJSON]:
        """ Get a list of all the comments posted by the given user """
        comments = self._getComments()
        return [comment for comment in comments if comment['username'] == username]

    def _getPublicCommentsByUsername(self, username: str) -> List[CommentJSON]:
        """ Get a list of all the public comments posted by the given user """
        comments = self._getPublicComments()
        return [comment for comment in comments if comment['username'] == username]

    def __getBody(self, commentJson: CommentJSON) -> str:
        """ Get the text body of a given comment """
        return cast(str, commentJson['body'])

    def _getCommentTime(self, commentJson: CommentJSON) -> datetime:
        """ Get the time the given comment was posted """
        return parseTime(cast(str, commentJson['time']))

    def getLatestActivity(self) -> str:
        """ Get the text body of the most recent activity by the original reporter """
        try:
            return self.__getBody(self._getPublicCommentsByUsername(self.getReporterUsername())[0])
        except IndexError:
            # If there are no comments, then the most recent activity is the report body
            return self.getReportBody()

    def getToken(self) -> str:
        """ Get the token stored in the body of a comment by the bot """
        comments = self._getAllCommentsByUsername(config.apiName)
        for comment in comments:
            body = self.__getBody(comment)
            try:
                metadataSection = body.split('Metadata')[-1]
                return extractJson(metadataSection)['token']
            except (KeyError, TypeError):
                pass
        raise TokenNotFound(str([self.__getBody(c) for c in self._getPublicComments()]))

    def getVulnDomains(self) -> List[str]:
        """  Get a list of the vulnerable domains (used for duplicate detection-not an accurate process) """
        def getDomains(urls: List[str]) -> List[str]:
            return [urlparse(url).hostname for url in urls]

        botComments = self._getAllCommentsByUsername(config.apiName)
        reporterComments = ([self.__getBody(x) for x in self._getAllCommentsByUsername(self.getReporterUsername())] +
                            getLinks(self.getReportBody()))
        # First attempt at getting a list of vulnerable domains, see if it is ever set in the metadata
        for botComment in botComments:
            body = self.__getBody(botComment)
            try:
                metadataSection = body.split('Metadata')[-1]
                return getDomains([extractJson(metadataSection)['vulnDomain']])
            except (KeyError, TypeError):
                pass
        allURLs = [link for comment in reporterComments for link in getLinks(comment)]
        # If not, just return the list of all the urls
        return getDomains(allURLs)

    def _reportReproduced(self) -> bool:
        """ Whether this report has alredy been reproduced or triaged in some manner """
        return self.getState() != 'new'

    def _userHasRepliedToBot(self) -> bool:
        """ Whether the user has replied to the bot """
        botComments = self._getPublicCommentsByUsername(config.apiName)
        OPComments = self._getPublicCommentsByUsername(self.getReporterUsername())
        try:
            latestBotComment = botComments[0]
            latestBotCommentTime = self._getCommentTime(latestBotComment)

            latestOPComment = OPComments[0]
            latestOPCommentTime = self._getCommentTime(latestOPComment)

            return latestOPCommentTime > latestBotCommentTime
        except IndexError:
            # If the bot has commented but the user hasn't, then return False
            if len(botComments) > 0 and len(OPComments) == 0:
                return False
            return True

    def needsBotReply(self) -> bool:
        """ Whether this report needs the bot to reply to it """
        return self._userHasRepliedToBot() and not self._reportReproduced()

    def botHasCommented(self) -> bool:
        """ Whether the bost has commented at all """
        botComments = self._getPublicCommentsByUsername(config.apiName)
        return len(botComments) > 0

    def shouldBackoff(self) -> bool:
        """ Whether the bot should back off """
        userComments = self._getPublicCommentsByUsername(self.getReporterUsername())
        containsStopPhrase = any([config.stopPhrase in self.__getBody(comment) for comment in userComments])
        if config.DEBUG and (len(userComments) > 10 or containsStopPhrase):
            print("Backing off: %s or %s" % (len(userComments), containsStopPhrase))
        return (len(userComments) > 10 or containsStopPhrase)

    def hasDuplicateComment(self) -> bool:
        """ Whether the report already has a comment about the duplicate status of the report """
        botComments = self._getAllCommentsByUsername(config.apiName)
        return any([('Detected a possible duplicate report' in self.__getBody(comment) or
                     'open reports about this type of vulnerability' in self.__getBody(comment) or
                     'Found a duplicate with 99% confidence' in self.__getBody(comment) or
                     'Found no possible duplicate reports' in self.__getBody(comment))
                    for comment in botComments])

    def hasPostedBackoffComment(self) -> bool:
        """ Whether the bot has already post a comment saying that it is backing off """
        botComments = self._getAllCommentsByUsername(config.apiName)
        return any(['Backing off' in self.__getBody(comment) for comment in botComments])

    def isVerified(self) -> bool:
        """ Whether the report has been verified """
        if self.getState() == 'triaged':
            return True
        for comment in self._getPublicCommentsByUsername(config.apiName):
            if "Metadata: {\"vulnDomain\": " in self.__getBody(comment):
                return True
        return False

    def extractMetadata(self) -> str:
        """ Extract the report metadata """
        for comment in self._getAllCommentsByUsername(config.apiName):
            body = self.__getBody(comment)
            if 'Internal Metadata' in body:
                return body
        raise MetadataNotFound()


class TokenNotFound(Exception):
    pass


class MetadataNotFound(Exception):
    pass


def parseTime(timeStr: str) -> datetime:
    """ Parse the given time string into a datetime """
    return arrow.get(timeStr).datetime


def fuzzyJsonParse(data: str) -> Mapping:
    """ *Very* fuzzing parsing of json using literal_eval (which is a safe function) """
    subs = {'false': 'False',
            'true': 'True',
            'null': 'None'}
    for orig, sub in subs.items():
        data = data.replace(orig, sub)
    res = ast.literal_eval(data)
    if isinstance(res, dict):
        return res
    raise ValueError("Not JSON!")


def extractJson(message: str) -> Optional[Mapping]:
    """ Returns the first json blob found in the string if any are found """
    # First pass that relies on it being in a code block
    for match in re.findall('\`\s*?{[\s\S]*?}\s*?\`', message):
        potJson = match[1:-1].strip()
        try:
            return json.loads(potJson)
        except ValueError:
            pass
    # Second pass doesn't require the code block, but it still uses the json parser
    for match in re.findall('{[\s\S]*}', message):
        try:
            return json.loads(match)
        except ValueError:
            pass
    # Third pass uses ast.literal_eval (which IS safe-it only evals literals) and some replacements to handle malformed
    # JSON. This is a horrible JSON parser and will incorrectly parse certain types of JSON, but it is far more
    # accepting so we might as well try doing this
    for match in re.findall('{[\s\S]*}', message):
        try:
            return fuzzyJsonParse(match)
        except (SyntaxError, ValueError):
            pass
    return None


def isStructured(body: str) -> bool:
    """ Whether the given body of a reply is (an attempt at) a structured format """
    parsedJson = extractJson(body)
    if parsedJson and isinstance(parsedJson, dict) and len(parsedJson.keys()) >= 2:
        return True
    # Heuristic: {} is not an attempt at JSON, but {AAAAA} is and so is {A:A}
    if re.search(r'{[\s\S]{5}[\s\S]*}', body) or re.search(r'{[\s\S]*:[\s\S]*}', body):
        return True
    return False


def getLinks(text: str) -> List[str]:
    """ Get a list of all URLs starting with https? in the given text """
    return [x[0] for x in
            re.findall(r"((http|https):\/\/[\S-]+(\.[\S-]+)*(\/[\S]+)*(\.[\S-]*)?(\?[\S-]+=[\S-]+(\&[\S-]+=[\S-]+)*)?)",
                       text,
                       re.IGNORECASE)]


def extractURLs(message: str) -> List[str]:
    """ Extract any URLs that are either in markdown URL blocks or code blocks """
    markdownURLBlocks = re.findall(r'\[.*\]\(.*\)', message)
    markdownLinks = ['])'.join(block.split('](')[1:])[:-1] for block in markdownURLBlocks]
    codeBlockURLs = re.findall(r'`\s*http.*?\s*`', message)
    codeLinks = [link.strip('`').strip() for link in codeBlockURLs]
    # If we haven't found anything yet, then fall back to pulling out all URLs
    if len(markdownLinks + codeLinks) == 0:
        return getLinks(message)
    return markdownLinks + codeLinks
