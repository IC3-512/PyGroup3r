"""Port of Group3r/Assessment/PathAnalyser.cs

Given a path pulled out of a GPO setting, works out whether it is a file, a
directory, or neither -- and in the last case walks up the path looking for the
nearest existing parent directory, so a writable parent can be reported even when
the target itself does not exist yet. Existing paths are also run through the
Snaffler file/dir classifier rules.

PORT NOTE: all existence checks and ACL reads go through the injected FsProvider
instead of System.IO.
"""

from typing import List, Optional

from ..classifiers.dir_classifier import DirClassifier
from ..classifiers.file_classifier import FileClassifier
from .finding import DirPathResult, FilePathResult, PathResult
from .fs_acl_analyser import FsAclAnalyser
from .sddl_analyser import SddlAnalyser


class PathAnalyser:
    """Port of Group3r.Assessment.PathAnalyser."""

    def __init__(self, assessment_options):
        self.assessment_options = assessment_options
        self.sddl_analyser = SddlAnalyser(assessment_options)
        self.fs_acl_analyser = FsAclAnalyser(assessment_options)

    @property
    def _fs(self):
        return getattr(self.assessment_options, "fs", None)

    def analyse_path(self, original_path: str) -> Optional[PathResult]:
        """Port of PathAnalyser.AnalysePath."""
        fs = self._fs
        if fs is None:
            return None

        path_result: Optional[PathResult] = None

        # first we can check if it's a file (and the file exists) and analyse it
        if fs.file_exists(original_path):
            file_path_result = self.analyse_file_path(original_path)
            file_path_result.file_exists = True
            file_path_result.set_properties(original_path, True)
            if file_path_result.rw_status.can_modify:
                file_path_result.file_writable = True
            path_result = file_path_result
        elif fs.dir_exists(original_path):
            # or if it's a dir
            dir_path_result = self.analyse_dir_path(original_path)
            dir_path_result.directory_exists = True
            dir_path_result.set_properties(original_path, True)
            if dir_path_result.rw_status.can_modify or dir_path_result.rw_status.can_write:
                dir_path_result.directory_writable = True
            path_result = dir_path_result
        else:
            # if it doesn't exist at all, we need to step up the path to see if
            # there's a parent dir that exists that might be writable.
            # so we trim backslashes to get an idea of how many elements there are
            # in the path
            path_elements = original_path.strip("\\").split("\\")

            unc = original_path.startswith("\\\\")
            path = "\\".join(path_elements)
            if unc:
                path = "\\\\" + path

            while len(path_elements) >= 1:
                if fs.dir_exists(path):
                    dir_path_result = self.analyse_dir_path(path)
                    dir_path_result.set_properties(original_path, False)
                    dir_path_result.parent_directory_exists = path
                    dir_path_result.directory_exists = False
                    dir_path_result.directory_writable = False
                    if (
                        dir_path_result.rw_status.can_write
                        or dir_path_result.rw_status.can_modify
                    ):
                        dir_path_result.parent_directory_writable = True
                    path_result = dir_path_result
                    break
                path_elements = path_elements[:-1]
                path = "\\".join(path_elements)
                if unc:
                    path = "\\\\" + path

        return path_result

    def analyse_file_path(self, file_path: str) -> FilePathResult:
        """Port of PathAnalyser.AnalyseFilePath."""
        file_classifier = FileClassifier(None, self.assessment_options.classifier_options)
        file_path_result = FilePathResult()

        # we know the file exists, so it's worth running through the snaffler engine.
        rules = self.assessment_options.classifier_options.all_rules.file_classifier_rules
        for rule in rules:
            snaff_result = file_classifier.classify(rule, file_path)
            if snaff_result is not None and snaff_result.matched_rule is not None:
                file_path_result.snaff_file_results.append(snaff_result)

        file_path_result.rw_status = self.fs_acl_analyser.analyse_fs_acl(
            file_path, is_dir=False
        ).rw_status
        return file_path_result

    def analyse_dir_path(self, dir_path: str) -> DirPathResult:
        """Port of PathAnalyser.AnalyseDirPath."""
        dir_classifier = DirClassifier(None, self.assessment_options.classifier_options)
        dir_path_result = DirPathResult()

        # we know the dir exists, so it's worth running through the snaffler engine.
        rules = self.assessment_options.classifier_options.all_rules.dir_classifier_rules
        for rule in rules:
            snaff_result = dir_classifier.classify(rule, dir_path)
            if snaff_result is not None and snaff_result.matched_rule is not None:
                dir_path_result.snaff_dir_results.append(snaff_result)

        dir_path_result.rw_status = self.fs_acl_analyser.analyse_fs_acl(
            dir_path, is_dir=True
        ).rw_status
        return dir_path_result
