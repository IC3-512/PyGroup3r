"""Port of LibSnaffle/Classifiers/Rules/FileContentRules.cs

One half of the C# `partial class ClassifierRules`, expressed as a mixin.

PORT NOTE (regex dialect): several patterns in this file contain
`[[:space:]]`, which looks like a POSIX character class but is NOT one in
either .NET or Python. Both engines parse `[[:space:]]` as the character set
`[`, `:`, `s`, `p`, `a`, `c`, `e` followed by a literal `]`, so the (buggy)
semantics are identical between the two and the patterns are ported verbatim.
Likewise `.{0-100}` is not a valid quantifier in either engine and is matched
literally by both. Both engines are given case-insensitive matching;
.NET's `RegexOptions.Compiled` and `RegexOptions.CultureInvariant` have no
Python equivalent (see classifier_rules.py).
"""

from group3rpy.classifiers.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
    Triage,
)
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class FileContentRulesMixin:
    """Port of the BuildFileContentRules() half of ClassifierRules."""

    def _build_file_content_rules(self) -> None:
        # Python
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for python related strings.",
                rule_name="PyContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepPyRegexRed",
                word_list=[
                    # python
                    ".py",
                ],
            )
        )

        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepPyRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # python
                    # "mysql\\.connector\\.connect\\(", //python
                    # "psycopg2\\.connect\\(", // python postgres
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )
        # PHP
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for php related strings.",
                rule_name="phpContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepPhpRegexRed",
                word_list=[
                    # php
                    ".php",
                    ".phtml",
                    ".inc",
                    ".php3",
                    ".php5",
                    ".php7",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepPhpRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # php
                    # "mysql_connect[[:space:]]*\\(.*\\$.*\\)", // php
                    # "mysql_pconnect[[:space:]]*\\(.*\\$.*\\)", // php
                    # "mysql_change_user[[:space:]]*\\(.*\\$.*\\)", // php
                    # "pg_connect[[:space:]]*\\(.*\\$.*\\)", // php
                    # "pg_pconnect[[:space:]]*\\(.*\\$.*\\)", // php
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )
        # CSharp
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for CSharp and ASP.NET related strings.",
                rule_name="csContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepCsRegexRed",
                word_list=[
                    # asp.net
                    ".aspx",
                    ".ashx",
                    ".asmx",
                    ".asp",
                    ".cshtml",
                    ".cs",
                    ".ascx",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepCsRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # csharp
                    r"connectionstring.{1,200}passw",
                    r"validationkey[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"decryptionkey[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )
        # Java
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for Java and ColdFusion related strings.",
                rule_name="javaContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepJavaRegexRed",
                word_list=[
                    # java
                    ".jsp",
                    ".do",
                    ".java",
                    # coldfusion
                    ".cfm",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepJavaRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # java
                    # "\\.getConnection\\(\\\"jdbc\\:",
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )
        # Ruby
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for Rubby related strings.",
                rule_name="rubyContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepRubyRegexRed",
                word_list=[
                    # ruby
                    ".rb",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepRubyRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # ruby
                    # "DBI\\.connect\\(",
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )

        # Perl
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for Perl related strings.",
                rule_name="perlContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepPerlRegexRed",
                word_list=[
                    # perl
                    ".pl",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepPerlRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # perl
                    # "DBI\\-\\>connect\\(",
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )

        # PowerShell
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for PowerShell related strings.",
                rule_name="psContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepPsRegexRed",
                word_list=[
                    # powershell
                    ".psd1",
                    ".psm1",
                    ".ps1",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepPsRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # PS
                    r"net user ",
                    # PORT NOTE: `{0-100}` is not a valid quantifier; both .NET and
                    # Python match it as literal text. Ported verbatim.
                    r"psexec .{0-100} -p ",
                    r"-SecureString",
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,00} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )

        # Batch
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for cmd.exe/batch file related strings.",
                rule_name="cmdContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepCmdRegexRed",
                word_list=[
                    # cmd.exe
                    ".bat",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepCmdRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # cmd
                    r"net user ",
                    r"psexec .{0-100} -p ",
                ],
            )
        )

        # bash/sh/zsh/etc
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for Bash related strings.",
                rule_name="bashContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepBashRegexRed",
                word_list=[
                    # bash, sh, zsh, etc
                    ".sh",
                    ".rc",
                    ".profile",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexen are very interesting.",
                rule_name="KeepBashRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    # bash
                    r"sshpass -p.*['|\"]",  # SSH Password
                    # generic tokens etc, same for most languages.
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                ],
            )
        )
        # Firefox/Thunderbird backups
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be searched for Firefox/Thunderbird backups related strings.",
                rule_name="browerContentByName",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileName,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepFFRegexRed",
                word_list=[
                    # Firefox/Thunderbird
                    "logins.json",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with contents matching these regexes are very interesting.",
                rule_name="KeepFFRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    r'"encryptedPassword":"[A-Za-z0-9+/=]+"',
                ],
            )
        )

        # vbscript etc
        # """
        # this.ClassifierRules.Add(new ClassifierRule()
        # {
        #     Description = "Files with these extensions will be searched for VBScript related strings.",
        #     RuleName = "vbsContentByExt",
        #     EnumerationScope = EnumerationScope.FileEnumeration,
        #     MatchLocation = MatchLoc.FileExtension,
        #     WordListType = MatchListType.Exact,
        #     MatchAction = MatchAction.Relay,
        #     RelayTarget = "KeepVbsRegexRed",
        #     WordList = new List<string>()
        #     {
        #         ".vbs",
        #         ".wsf"
        #     },
        # });
        # this.ClassifierRules.Add(new ClassifierRule()
        # {
        #     Description = "Files with contents matching these regexen are very interesting.",
        #     RuleName = "KeepVbsRegexRed",
        #     EnumerationScope = EnumerationScope.ContentsEnumeration,
        #     MatchLocation = MatchLoc.FileContentAsString,
        #     WordListType = MatchListType.Regex,
        #     MatchAction = MatchAction.Snaffle,
        #     Triage = Triage.Red,
        #     WordList = new List<string>()
        #     {
        #         // TODO LOL
        #     }
        # });
        # """

        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be subjected to a generic search for keys and such.",
                rule_name="ConfigContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepConfigRegexRed",
                word_list=[
                    ".yaml",
                    ".yml",
                    ".toml",
                    ".xml",
                    ".json",
                    ".config",
                    ".ini",
                    ".inf",
                    ".cnf",
                    ".conf",
                    ".properties",
                    ".env",
                    ".dist",
                    ".txt",
                    ".sql",
                    ".log",
                    ".sqlite",
                    ".sqlite3",
                    ".fdb",
                    "",
                ],
            )
        )

        self.all_classifier_rules.append(
            ClassifierRule(
                rule_name="KeepConfigRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    r"sqlconnectionstring[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"connectionstring[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"validationkey[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"decryptionkey[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"passwo?r?d[[:space:]]*=[[:space:]]*[\'\"][^\'\"].....*",
                    r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",  # sql creds
                    # "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", //Slack Token
                    # "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", //Slack Webhook
                    # "aws[_\\-\\.]?key", // aws mnagic
                    # "[_\\-\\.]?api[_\\-\\.]?key", // stuff
                    # "[_\\-\\.]oauth[[:space:]]*=", // oauth stuff
                    # "client_secret", // fun
                    # "secret[_\\-\\.]?(key)?[[:space:]]*=",
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                    r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\s|\'|\"|$)",  # aws access key
                    # network device config
                    r"NVRAM config last updated",
                    r"enable password .",
                    r"simple-bind authenticated encrypt",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be grepped for private keys.",
                rule_name="CertContentByExt",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Relay,
                relay_target="KeepCertRegexRed",
                word_list=[
                    "_rsa",  # test file created
                    "_dsa",  # test file created
                    "_ed25519",  # test file created
                    "_ecdsa",  # test file created
                    ".pem",
                ],
            )
        )

        self.all_classifier_rules.append(
            ClassifierRule(
                rule_name="KeepCertRegexRed",
                enumeration_scope=EnumerationScope.ContentsEnumeration,
                match_location=MatchLoc.FileContentAsString,
                word_list_type=MatchListType.Regex,
                match_action=MatchAction.Snaffle,
                triage=Triage.Red,
                word_list=[
                    r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                ],
            )
        )

        # dsa | ecdsa | ed25519 | rsa]
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Files with these extensions will be parsed as x509 certificates to see if they have private keys.",
                rule_name="KeepCertContainsPrivKeyRed",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.CheckForKeys,
                triage=Triage.Red,
                word_list=[
                    ".der",  # test file created
                    ".pfx",
                    ".pk12",
                    ".p12",
                    ".pkcs12",
                ],
            )
        )
