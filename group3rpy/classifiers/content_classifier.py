"""Port of LibSnaffle/Classifiers/ContentClassifier.cs"""

import hashlib
from typing import Any, Optional

from group3rpy.assessment.finding import ClassifierResult, FileResult, TextResult
from group3rpy.classifiers.classifier_base import ClassifierBase
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.constants import MatchLoc
from group3rpy.classifiers.file_classifier import win_full_name
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule
from group3rpy.classifiers.text_classifier import TextClassifier


class ContentClassifier(ClassifierBase):
    """Port of LibSnaffle.Classifiers.ContentClassifier.

    PORT NOTE: every File.* call in the C# goes through the injected FsProvider
    here, because the artefacts live on remote SMB shares rather than the local
    filesystem.
    """

    def __init__(
        self, mq: Any, options: ClassifierOptions, fs: Optional[Any] = None
    ) -> None:
        super().__init__(mq, options, fs)

    def classify(
        self, classifier_rule: ClassifierRule, artefact: str
    ) -> Optional[ClassifierResult]:
        file_full_name = win_full_name(artefact)
        try:
            file_length = self._file_length(file_full_name)
            if self.options.max_size_to_grep >= file_length:
                # figure out if we need to look at the content as bytes or as string.
                if classifier_rule.match_location == MatchLoc.FileContentAsBytes:
                    file_bytes = self._read_all_bytes(file_full_name)
                    if self.byte_match(file_bytes):
                        file_result = self._new_file_result(file_full_name, file_length)
                        file_result.matched_rule = classifier_rule
                        return file_result
                    else:
                        return None
                elif classifier_rule.match_location == MatchLoc.FileContentAsString:
                    try:
                        file_string = self._read_all_text(file_full_name)

                        text_classifier = TextClassifier(
                            self.mq, self.options, self.fs
                        )
                        text_result: Optional[TextResult] = text_classifier.classify(
                            classifier_rule, file_string
                        )

                        if text_result is not None:
                            file_result = self._new_file_result(
                                file_full_name, file_length
                            )
                            file_result.matched_rule = classifier_rule
                            file_result.text_result = text_result
                            return file_result
                    except PermissionError:
                        # catch (UnauthorizedAccessException)
                        return None
                    except OSError:
                        # catch (IOException)
                        return None
                    return None
                elif classifier_rule.match_location == MatchLoc.FileLength:
                    try:
                        length_result = self.size_match(file_length, classifier_rule)
                        if length_result:
                            file_result = self._new_file_result(
                                file_full_name, file_length
                            )
                            file_result.matched_rule = classifier_rule
                            return file_result
                    except PermissionError:
                        return None
                    except OSError:
                        return None
                    return None
                elif classifier_rule.match_location == MatchLoc.FileMD5:
                    try:
                        md5_result = self.md5_match(file_full_name, classifier_rule)
                        if md5_result:
                            file_result = self._new_file_result(
                                file_full_name, file_length
                            )
                            file_result.matched_rule = classifier_rule
                            return file_result
                    except PermissionError:
                        return None
                    except OSError:
                        return None
                    return None
                else:
                    self._mq_error(
                        "You've got a misconfigured file ClassifierRule named "
                        + classifier_rule.rule_name
                        + "."
                    )
                    return None
            else:
                self._mq_trace(
                    "The following file was bigger than the MaxSizeToGrep config parameter:"
                    + file_full_name
                )
        except NotImplementedError:
            # PORT NOTE: ByteMatch throws NotImplementedException in the C#, which
            # is caught by the `catch (Exception e)` below. Python's
            # NotImplementedError is a subclass of RuntimeError so it would be
            # swallowed by the bare `except Exception` too; it is re-raised
            # explicitly instead so the unimplemented path is visible, matching
            # the intent of the upstream TODO.
            raise
        except Exception as e:  # noqa: BLE001 - mirrors catch (Exception e)
            self._mq_error(str(e))
            return None
        return None

    def size_match(self, file_length: int, classifier_rule: ClassifierRule) -> bool:
        if classifier_rule.match_length == file_length:
            return True
        return False

    def md5_match(self, path: str, classifier_rule: ClassifierRule) -> bool:
        md5_sum = self.get_md5_hash_from_file(path)
        if md5_sum == classifier_rule.match_md5.upper():
            return True
        return False

    def get_md5_hash_from_file(self, file_name: str) -> str:
        # BitConverter.ToString(hash).Replace("-", "") yields upper-case hex.
        return hashlib.md5(self._read_all_bytes(file_name)).hexdigest().upper()

    def byte_match(self, file_bytes: bytes) -> bool:
        # TODO
        raise NotImplementedError(
            "Haven't implemented byte-based content searching yet lol."
        )

    # --- FsProvider-backed IO --------------------------------------------

    def _new_file_result(self, path: str, file_length: int) -> FileResult:
        return FileResult(file_path=path, file_length=file_length)

    def _file_length(self, path: str) -> int:
        if self.fs is None:
            raise OSError(f"No FsProvider available to stat {path}")
        return self.fs.file_length(path)

    def _read_all_bytes(self, path: str) -> bytes:
        if self.fs is None:
            raise OSError(f"No FsProvider available to read {path}")
        return self.fs.read_file(path)

    def _read_all_text(self, path: str) -> str:
        # PORT NOTE: File.ReadAllText defaults to UTF-8 with BOM detection and
        # replaces undecodable bytes rather than throwing, so decode the same way.
        raw = self._read_all_bytes(path)
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
            return raw.decode("utf-8", errors="replace")
        if raw.startswith(b"\xff\xfe"):
            return raw[2:].decode("utf-16-le", errors="replace")
        if raw.startswith(b"\xfe\xff"):
            return raw[2:].decode("utf-16-be", errors="replace")
        return raw.decode("utf-8", errors="replace")
