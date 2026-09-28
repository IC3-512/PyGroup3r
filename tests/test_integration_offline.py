"""End-to-end offline test against the real upstream fixture.

`upstream/TestSysvol/` ships with Group3r: 8 GPO directories, 66 files, covering
every parser type (GptTmpl.inf, Registry.pol, scripts.ini, and the full set of GPP
preference XML files). Running the whole pipeline over it exercises parsers,
analysers, the finding model and both report formats together, which unit tests
cannot.

The counts asserted here are characterisation baselines: they pin current
behaviour so an accidental regression (a parser that stops matching, an analyser
that stops firing) shows up as a failing test. They are NOT claims of parity with
the C# original -- see reference/ for that, where it exists.
"""

import collections
import pathlib

import pytest

from group3rpy.assessment.analyser_factory import AnalyserFactory
from group3rpy.assessment.finding import GpoResult
from group3rpy.classifiers.constants import Triage
from group3rpy.options.assessment_options import AssessmentOptions
from group3rpy.smb.provider import LocalFsProvider
from group3rpy.sysvol.sysvol import Sysvol

FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "upstream" / "TestSysvol"

pytestmark = pytest.mark.skipif(
    not FIXTURE.is_dir(), reason="upstream TestSysvol fixture not present"
)


class RecordingLog:
    """Captures Mq output so the test can assert on parser diagnostics."""

    def __init__(self):
        self.traces = []
        self.degubs = []
        self.errors = []
        self.infos = []

    def trace(self, message):
        self.traces.append(message)

    def degub(self, message):
        self.degubs.append(message)

    def error(self, message):
        self.errors.append(message)

    def info(self, message):
        self.infos.append(message)

    def fatal(self, message):
        self.errors.append(message)


@pytest.fixture(scope="module")
def parsed():
    log = RecordingLog()
    sysvol = Sysvol(str(FIXTURE), LocalFsProvider(), log)
    return sysvol, log


@pytest.fixture(scope="module")
def analysed(parsed):
    """Run every setting through its analyser, as GroupCon does."""
    sysvol, _ = parsed
    options = AssessmentOptions()
    options.fs = LocalFsProvider()
    factory = AnalyserFactory()

    results = []
    for gpo in sysvol.gpos:
        gpo_result = GpoResult(options, gpo.attributes)
        for setting in gpo.settings:
            analyser = factory.get_analyser(setting)
            if analyser is None:
                continue
            analyser.min_triage = options.min_triage
            analyser.mq = RecordingLog()
            try:
                gpo_result.setting_results.append(analyser.analyse(options))
            except Exception as exc:  # mirrors GroupCon's per-setting guard
                gpo_result.setting_results.append(
                    type("Failed", (), {"setting": setting, "findings": [], "error": exc})()
                )
        results.append(gpo_result)
    return results, options


# ----------------------------------------------------------------- parse layer


def test_finds_all_gpo_directories(parsed):
    sysvol, _ = parsed
    assert len(sysvol.gpo_dirs) == 8


def test_every_gpo_yields_settings(parsed):
    sysvol, _ = parsed
    assert len(sysvol.gpos) == 8
    for gpo in sysvol.gpos:
        assert gpo.settings, f"{gpo.attributes.uid} parsed no settings"


def test_setting_type_coverage(parsed):
    """Every parser family must be represented, or a parser has silently broken."""
    sysvol, _ = parsed
    counts = collections.Counter(
        type(setting).__name__ for gpo in sysvol.gpos for setting in gpo.settings
    )

    # Families that the fixture definitely contains.
    for expected in [
        "RegistrySetting",
        "PrivRightSetting",
        "SystemAccessSetting",
        "SchedTaskSetting",
        "KerbPolicySetting",
        "ScriptSetting",
        "GroupSetting",
        "NtServiceSetting",
        "DriveSetting",
        "EnvVarSetting",
        "FolderSetting",
        "ShortcutSetting",
        "FileSetting",
        "UserSetting",
        "IniFileSetting",
        "DataSourceSetting",
        "PrinterSetting",
        "DeviceSetting",
    ]:
        assert counts[expected] > 0, f"no {expected} parsed from the fixture"

    assert sum(counts.values()) >= 400


def test_registry_pol_files_are_parsed(parsed):
    """registry.pol carries a large share of registry settings.

    Upstream detects the hive from a `\\machine\\` / `\\user\\` substring, which
    does not match POSIX-separated offline paths -- a bug that silently discarded
    every registry.pol. This pins the fix.
    """
    sysvol, log = parsed
    hive_errors = [m for m in log.degubs + log.errors if "hive associated" in m]
    assert hive_errors == [], f"registry.pol hive detection failing: {hive_errors[:2]}"

    from group3rpy.settings.registry_types import RegHive

    pol_settings = [
        setting
        for gpo in sysvol.gpos
        for setting in gpo.settings
        if (setting.source or "").lower().endswith("registry.pol")
    ]
    assert pol_settings, "no settings parsed out of any registry.pol"
    hives = {s.hive for s in pol_settings if getattr(s, "hive", None) is not None}
    assert hives <= {RegHive.HKEY_LOCAL_MACHINE, RegHive.HKEY_CURRENT_USER}

    # Machine-scoped pol files must resolve to HKLM.
    machine = [s for s in pol_settings if "machine" in (s.source or "").lower()]
    assert machine
    assert all(s.hive is RegHive.HKEY_LOCAL_MACHINE for s in machine)


def test_policy_type_is_assigned(parsed):
    """sortSettings must classify every setting as Computer or User policy."""
    from group3rpy.ad.gpo import PolicyType

    sysvol, _ = parsed
    for gpo in sysvol.gpos:
        for setting in gpo.settings:
            assert setting.policy_type in (
                PolicyType.Computer,
                PolicyType.User,
                PolicyType.Package,
            ), f"{type(setting).__name__} from {setting.source} has no policy type"


def test_unparseable_files_are_skipped_not_fatal(parsed):
    """.ps1, .aas and gpt.ini have no parser; upstream logs and moves on."""
    _, log = parsed
    assert any("No parser for" in m for m in log.degubs)


# -------------------------------------------------------------- analysis layer


def test_analysis_produces_findings(analysed):
    results, _ = analysed
    findings = [
        finding
        for result in results
        for setting_result in result.setting_results
        for finding in setting_result.findings
    ]
    assert findings, "the whole fixture produced no findings at all"

    # Every finding must be fully populated -- a blank reason means a port gap.
    for finding in findings:
        assert finding.finding_reason, "finding with no reason"
        assert isinstance(finding.triage, Triage)


def test_findings_span_multiple_triage_levels(analysed):
    results, _ = analysed
    levels = {
        finding.triage
        for result in results
        for setting_result in result.setting_results
        for finding in setting_result.findings
    }
    assert len(levels) >= 2, f"expected a spread of triage levels, got {levels}"


def test_min_triage_suppresses_lower_findings(parsed):
    """Raising MinTriage to Black must not produce more findings than Green does."""
    sysvol, _ = parsed
    factory = AnalyserFactory()

    def count_at(level):
        options = AssessmentOptions()
        options.fs = LocalFsProvider()
        options.min_triage = level
        total = 0
        for gpo in sysvol.gpos:
            for setting in gpo.settings:
                analyser = factory.get_analyser(setting)
                if analyser is None:
                    continue
                analyser.min_triage = level
                analyser.mq = RecordingLog()
                try:
                    total += len(analyser.analyse(options).findings)
                except Exception:
                    pass
        return total

    at_green = count_at(Triage.Green)
    at_black = count_at(Triage.Black)
    assert at_green >= at_black, (
        f"MinTriage=Black produced {at_black} findings vs {at_green} at Green -- "
        "triage guards are inverted somewhere"
    )


def test_disabled_analysers_never_run(parsed):
    """The 8 analysers upstream leaves commented out must stay unregistered."""
    sysvol, _ = parsed
    factory = AnalyserFactory()
    disabled = {
        "DeviceSetting",
        "DriveSetting",
        "EnvVarSetting",
        "EventAuditSetting",
        "FolderSetting",
        "IniFileSetting",
        "SystemAccessSetting",
        "UserSetting",
    }
    seen = set()
    for gpo in sysvol.gpos:
        for setting in gpo.settings:
            name = type(setting).__name__
            if name in disabled:
                seen.add(name)
                assert factory.get_analyser(setting) is None, (
                    f"{name} got an analyser, but upstream has it commented out"
                )
    # The fixture should actually contain some of them, or this proves nothing.
    assert seen, "fixture contained none of the disabled setting types"


# ----------------------------------------------------------------- report layer


def test_html_report_builds_from_real_data(analysed, tmp_path):
    from group3rpy.view.html_report import HtmlReportBuilder

    results, _ = analysed
    builder = HtmlReportBuilder(domain="testsysvol.local", command_line="pytest")
    for result in results:
        builder.add_gpo_result(result)

    out = tmp_path / "report.html"
    summary = builder.write(str(out))

    assert summary["gpoCount"] == 8
    assert summary["rowCount"] > 0
    assert out.stat().st_size > 1000
    markup = out.read_text(encoding="utf-8")
    assert "__GROUP3R_DATA__" not in markup
    assert "https://" not in markup and "http://" not in markup


def test_payload_is_internally_consistent(analysed):
    """Every string index in the payload must be in range."""
    from group3rpy.view.html_report import HtmlReportBuilder

    results, _ = analysed
    builder = HtmlReportBuilder(domain="testsysvol.local")
    for result in results:
        builder.add_gpo_result(result)
    payload = builder.build_payload()

    limit = len(payload["strings"])
    findings = payload["findings"]
    row_count = len(findings["gpo"])

    for column in ("type", "policy", "triage", "reason", "detail", "source", "has"):
        assert len(findings[column]) == row_count, f"column {column} is ragged"

    for index in findings["reason"] + findings["detail"] + findings["source"]:
        assert 0 <= index < limit
    for gpo_index in findings["gpo"]:
        assert 0 <= gpo_index < len(payload["gpos"])
    for type_index in findings["type"]:
        assert 0 <= type_index < len(payload["settingTypes"])
    for row in findings["fields"]:
        for key, value in row:
            assert 0 <= key < limit and 0 <= value < limit
