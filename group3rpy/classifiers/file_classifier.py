"""Port of LibSnaffle/Classifiers/FileClassifier.cs

Classifier implementation to classify a file.
"""

from typing import Any, Optional

from group3rpy.assessment.finding import ClassifierResult, FileResult, TextResult
from group3rpy.classifiers.classifier_base import ClassifierBase
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.constants import EnumerationScope, MatchAction, MatchLoc
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule
from group3rpy.classifiers.text_classifier import TextClassifier

# PORT NOTE: the C# leans on System.IO.FileInfo for Name/Extension/FullName.
# Those are Windows-path semantics applied to UNC paths that do not exist on the
# local Linux filesystem, so they are reimplemented here as pure string
# operations rather than going through os.path (which would split on '/' only).

_WIN_SEPARATORS = "\\/"


def win_file_name(path: str) -> str:
    """Equivalent of System.IO.FileInfo.Name / Path.GetFileName."""
    index = max(path.rfind("\\"), path.rfind("/"), path.rfind(":"))
    if index >= 0:
        return path[index + 1 :]
    return path


def win_full_name(path: str) -> str:
    """Equivalent of System.IO.FileInfo.FullName.

    PORT NOTE: .NET would root a relative path against the current directory and
    normalise separators / '.' / '..' segments. Group3r only ever feeds this
    absolute UNC or drive-rooted paths harvested from GPO settings, so the path
    is returned unchanged; normalising it would change the string that
    MatchLoc.FilePath rules are tested against.
    """
    return path


def win_extension(name: str) -> str:
    """Equivalent of System.IO.FileInfo.Extension / Path.GetExtension.

    Includes the leading dot. Returns "" when there is no dot, and - matching
    .NET - also returns "" when the name ends in a dot.
    """
    for i in range(len(name) - 1, -1, -1):
        ch = name[i]
        if ch == ".":
            if i != len(name) - 1:
                return name[i:]
            return ""
        if ch in _WIN_SEPARATORS:
            break
    return ""


class FileClassifier(ClassifierBase):
    """Port of LibSnaffle.Classifiers.FileClassifier."""

    def __init__(
        self, mq: Any, options: ClassifierOptions, fs: Optional[Any] = None
    ) -> None:
        super().__init__(mq, options, fs)

    def classify(
        self, classifier_rule: ClassifierRule, artefact: str
    ) -> Optional[ClassifierResult]:
        file_to_classify_name = win_file_name(artefact)
        file_to_classify_full_name = win_full_name(artefact)
        # figure out what part we gonna look at
        string_to_match: Optional[str] = None

        if classifier_rule.match_location == MatchLoc.FileExtension:
            string_to_match = win_extension(file_to_classify_name)
            # special handling to treat files named like 'thing.kdbx.bak'
            if string_to_match == ".bak":
                # strip off .bak
                sub_name = file_to_classify_name.replace(".bak", "")
                string_to_match = win_extension(sub_name)
                # if this results in no file extension, put it back.
                if string_to_match == "":
                    string_to_match = ".bak"
            # this is insane that i have to do this but apparently files with no extension return
            # this bullshit
            if string_to_match == "":
                return None
        elif classifier_rule.match_location == MatchLoc.FileName:
            string_to_match = file_to_classify_name
        elif classifier_rule.match_location == MatchLoc.FilePath:
            string_to_match = file_to_classify_full_name
        elif classifier_rule.match_location == MatchLoc.FileLength:
            if classifier_rule.match_length != self._file_length(
                file_to_classify_full_name
            ):
                return None
        else:
            self._mq_error(
                "You've got a misconfigured file classifier rule named "
                + classifier_rule.rule_name
                + "."
            )
            return None

        text_result: Optional[TextResult] = None

        if string_to_match:
            text_classifier = TextClassifier(self.mq, self.options, self.fs)
            # check if it matches
            text_result = text_classifier.classify(classifier_rule, string_to_match)
            if text_result is None:
                # if it doesn't we just bail now.
                return None

        # if it matches, see what we're gonna do with it
        if classifier_rule.match_action == MatchAction.Discard:
            # chuck it.
            return None
        elif classifier_rule.match_action == MatchAction.Snaffle:
            # snaffle that bad boy
            file_result = self._new_file_result(file_to_classify_full_name)
            file_result.matched_rule = classifier_rule
            file_result.matched_string = string_to_match
            file_result.text_result = text_result
            return file_result
        elif classifier_rule.match_action == MatchAction.CheckForKeys:
            # do a special x509 dance
            if self.x509_priv_key_match(file_to_classify_full_name):
                file_result = self._new_file_result(file_to_classify_full_name)
                file_result.matched_rule = classifier_rule
                file_result.matched_string = string_to_match
                return file_result
            else:
                return None
        elif classifier_rule.match_action == MatchAction.Relay:
            # bounce it on to the next ClassifierRule
            # TODO concurrency uplift make this a new task on the poolq
            try:
                # TODO this needs to iterate over all relay rules
                next_rule = next(
                    (
                        x
                        for x in self.all_rules.all_classifier_rules
                        if x.rule_name == classifier_rule.relay_target
                    ),
                    None,
                )
                if next_rule.enumeration_scope == EnumerationScope.ContentsEnumeration:
                    # Imported here rather than at module scope because
                    # ContentClassifier imports this module's path helpers.
                    from group3rpy.classifiers.content_classifier import (
                        ContentClassifier,
                    )

                    c = ContentClassifier(self.mq, self.options, self.fs)
                    return c.classify(next_rule, artefact)
                raise ValueError(
                    f"Incorrect Classifier Enumeration Scope on rule '{next_rule.rule_name}'"
                )
            except OSError as e:
                # PORT NOTE: catch (IOException) - OSError is the closest Python
                # equivalent, and covers the SMB provider's IO failures.
                self._mq_trace(str(e))
            except Exception as e:  # noqa: BLE001 - mirrors catch (Exception e)
                self._mq_error(
                    "You've got a misconfigured file ClassifierRule named "
                    + classifier_rule.rule_name
                    + "."
                )
                self._mq_trace(str(e))
            return None
        elif classifier_rule.match_action == MatchAction.EnterArchive:
            # do a special looking inside archive files dance using
            # https://github.com/adamhathcock/sharpcompress
            # TODO FUUUUUCK
            raise NotImplementedError(
                "Haven't implemented walking dir structures inside archives. Prob needs pool queue."
            )
        else:
            self._mq_error(
                "You've got a misconfigured file ClassifierRule named "
                + classifier_rule.rule_name
                + "."
            )
            return None

    def _new_file_result(self, path: str) -> FileResult:
        """Stands in for `new FileResult(fileInfo, CopyFile, MaxSizeToCopy, PathToCopyTo)`.

        PORT NOTE: the C# FileResult constructor takes the copy-related options
        but ignores all three of them (it only stores ResultFileInfo), so
        nothing is copied here either.
        """
        return FileResult(
            file_path=path,
            file_length=self._file_length(path),
        )

    def _file_length(self, path: str) -> int:
        """FileInfo.Length, via the injected FsProvider."""
        if self.fs is None:
            return 0
        try:
            return self.fs.file_length(path)
        except OSError:
            return 0

    def x509_priv_key_match(self, path: str) -> bool:
        """Port of FileClassifier.x509PrivKeyMatch.

        PORT NOTE: the C# does `new X509Certificate2(path).HasPrivateKey`, which
        has no stdlib equivalent on Linux (there is no PKCS#12 reader in the
        Python standard library, and pycryptodomex does not provide one either).
        This checks the DER/PEM bytes for the PKCS#12 keyBag
        (1.2.840.113549.1.12.10.1.1) and pkcs8ShroudedKeyBag
        (1.2.840.113549.1.12.10.1.2) object identifiers, plus PEM private key
        armour. Known divergence: for a PKCS#12 blob protected with a non-blank
        password, .NET throws CryptographicException and returns false, whereas
        this returns true because the shrouded key bag is still visible.
        """
        try:
            if self.fs is None:
                return False
            file_bytes = self.fs.read_file(path)
        except Exception:  # noqa: BLE001 - mirrors catch (CryptographicException)
            return False

        if not file_bytes:
            return False

        # OID 1.2.840.113549.1.12.10.1.1 / .1.2 encoded as DER OBJECT IDENTIFIERs
        key_bag = bytes.fromhex("060b2a864886f70d010c0a0101")
        shrouded_key_bag = bytes.fromhex("060b2a864886f70d010c0a0102")
        if key_bag in file_bytes or shrouded_key_bag in file_bytes:
            return True
        if b"-----BEGIN" in file_bytes and b"PRIVATE KEY" in file_bytes:
            return True
        return False
