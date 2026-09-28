"""Port of LibSnaffle/Classifiers/ArchiveClassifier.cs"""

from typing import Any, Optional

from group3rpy.assessment.finding import ClassifierResult
from group3rpy.classifiers.classifier_base import ClassifierBase
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class ArchiveClassifier(ClassifierBase):
    """Port of LibSnaffle.Classifiers.ArchiveClassifier.

    TODO VERY WORK IN PROGRESS
    """

    def __init__(
        self, mq: Any, options: ClassifierOptions, fs: Optional[Any] = None
    ) -> None:
        super().__init__(mq, options, fs)

    def classify(
        self, rule: ClassifierRule, file: str
    ) -> Optional[ClassifierResult]:
        # look inside archives for files we like.
        #
        # PORT NOTE: the entire body below is commented out in the C# and the
        # method just throws NotImplementedException, so per the port rules it
        # stays commented out and the raise stays. Two reasons it could not be
        # dropped in as-is even if it were live: it depends on SharpCompress
        # (ArchiveFactory / IArchive, covering zip+rar+7z+tar) for which the
        # stdlib only offers single-format readers (zipfile / tarfile), and it
        # calls a `FileScanner.ScanFile` that does not exist anywhere in Group3r.
        #
        # FileInfo fileInfo = new FileInfo(file);
        # try
        # {
        #     IArchive archive = ArchiveFactory.Open(fileInfo.FullName);
        #     foreach (IArchiveEntry entry in archive.Entries)
        #     {
        #         if (!entry.IsDirectory)
        #         {
        #             try
        #             {
        #                 FileScanner.ScanFile(entry.Key);
        #             }
        #             catch (Exception e)
        #             {
        #                 Mq.Trace(e.ToString());
        #             }
        #         }
        #     }
        # }
        # catch (CryptographicException)
        # {
        #     FileResult result = new FileResult(fileInfo, CopyFile, MaxSizeToCopy, PathToCopyto)
        #     {
        #         MatchedRule = new ClassifierRule() { Triage = Triage.Black, RuleName = "EncryptedArchive" }
        #     });
        #     return result;
        # }
        # catch (Exception e)
        # {
        #     Mq.Trace(e.ToString());
        # }
        # return null;
        raise NotImplementedError()
