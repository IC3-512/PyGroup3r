"""Browser-driven tests for the filterable HTML report.

These run the real page in headless Chromium, because the report's value is in its
client-side filtering -- asserting on the generated markup alone would not prove
that search, faceting or virtualisation actually work.
"""

import datetime
import json
import random
import re

import pytest

from group3rpy.ad.gpo import GPOAttributes, GPOLink, PolicyType
from group3rpy.ad.trustee import Trustee
from group3rpy.assessment.finding import (
    ACEType,
    DirPathResult,
    FilePathResult,
    GpoFinding,
    GpoResult,
    RwStatus,
    SettingResult,
    SimpleAce,
)
from group3rpy.classifiers.constants import Triage
from group3rpy.options.assessment_options import AssessmentOptions
from group3rpy.settings import RegistrySetting, ScriptSetting
from group3rpy.view.html_report import HtmlReportBuilder

playwright_api = pytest.importorskip("playwright.sync_api")

GPO_COUNT = 60
FINDINGS_PER_GPO = 10
# One extra no-finding setting row per GPO.
EXPECTED_ROWS = GPO_COUNT * (FINDINGS_PER_GPO + 1)
EXPECTED_FINDINGS = GPO_COUNT * FINDINGS_PER_GPO
EXPECTED_NO_FINDING = GPO_COUNT

# The fixture assigns triage by `slot % 4` over FINDINGS_PER_GPO slots, which is
# not an even split unless FINDINGS_PER_GPO is a multiple of 4. Derive the real
# per-triage totals rather than assuming.
_ORDER = ["Green", "Yellow", "Red", "Black"]
TRIAGE_TOTALS = {name: 0 for name in _ORDER}
for _slot in range(FINDINGS_PER_GPO):
    TRIAGE_TOTALS[_ORDER[_slot % 4]] += GPO_COUNT


@pytest.fixture(scope="module")
def report_path(tmp_path_factory):
    options = AssessmentOptions()
    builder = HtmlReportBuilder(domain="corp.local", command_line="group3rpy -d corp.local")
    random.seed(7)

    for index in range(GPO_COUNT):
        attributes = GPOAttributes(
            display_name=f"Workstation Policy {index}",
            uid="{%036d}" % index,
            path_in_sysvol=f"\\\\dc01\\sysvol\\corp.local\\Policies\\{{{index:036d}}}",
            distinguished_name=f"CN={{{index:036d}}},CN=Policies,CN=System,DC=corp,DC=local",
            version_number="65539",
            computer_policy_enabled=True,
            user_policy_enabled=(index % 3 == 0),
            created_date=datetime.datetime(2023, 1, 1),
            modified_date=datetime.datetime(2024, 6, 2),
            gpo_links=[
                GPOLink(
                    link_path="OU=Workstations,DC=corp,DC=local",
                    link_enforced="Enabled, Unenforced",
                )
            ],
        )
        gpo_result = GpoResult(options, attributes)

        for slot in range(FINDINGS_PER_GPO):
            setting = ScriptSetting(
                source=f"\\\\dc01\\sysvol\\corp.local\\Policies\\{{{index:036d}}}"
                "\\Machine\\Scripts\\scripts.ini"
            )
            setting.policy_type = PolicyType.Computer
            setting.command_line = f"\\\\fileserver\\netlogon\\map{slot}.bat"

            triage = [Triage.Green, Triage.Yellow, Triage.Red, Triage.Black][slot % 4]
            finding = GpoFinding(
                finding_reason="Found a startup script that is writable by a low-privileged user.",
                finding_detail=f"cpassword recovered: Sup3rSecret{slot}",
                triage=triage,
                acl_result=[
                    SimpleAce(
                        trustee=Trustee(
                            display_name="Domain Users", sid="S-1-5-21-1-2-3-513"
                        ),
                        ace_type=ACEType.Allow,
                        rights=["GENERIC_WRITE", "WRITE_DAC"],
                    )
                ],
            )
            path_result = FilePathResult()
            path_result.assessed_path = setting.command_line
            path_result.file_exists = True
            path_result.file_writable = True
            path_result.rw_status = RwStatus(
                exists=True, can_read=True, can_write=True, can_modify=True
            )
            finding.path_findings = [path_result]
            gpo_result.setting_results.append(
                SettingResult(setting=setting, findings=[finding])
            )

        # A setting with no findings, which the report keeps behind the None filter.
        registry = RegistrySetting(source="registry.pol")
        registry.policy_type = PolicyType.User
        gpo_result.setting_results.append(SettingResult(setting=registry, findings=[]))

        builder.add_gpo_result(gpo_result)

    out = tmp_path_factory.mktemp("report") / "group3r.html"
    builder.write(str(out))
    return out


@pytest.fixture(scope="module")
def browser():
    """One browser for the module -- sync_playwright() cannot be nested."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        instance = p.chromium.launch()
        yield instance
        instance.close()


@pytest.fixture(scope="module")
def page(report_path, browser):
    errors = []
    pg = browser.new_page()
    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(report_path.as_uri())
    pg.wait_for_selector("#loading", state="detached", timeout=30_000)
    pg.errors = errors
    yield pg
    pg.close()


@pytest.fixture(autouse=True)
def reset_state(page):
    """The page is module-scoped for speed, so each test starts from a clean slate."""
    page.click("#btnReset")
    page.wait_for_timeout(150)
    yield


def count_text(page):
    return page.inner_text("#countline")


def visible_count(page):
    match = re.search(r"([\d,]+)\s+of\s+([\d,]+)", count_text(page))
    return int(match.group(1).replace(",", "")), int(match.group(2).replace(",", ""))


def search(page, query):
    page.fill("#q", query)
    page.wait_for_timeout(320)  # debounce is 160ms
    return visible_count(page)[0]


def test_loads_without_console_errors(page):
    assert page.errors == [], f"console errors: {page.errors}"


def test_all_rows_present_on_load(page):
    shown, total = visible_count(page)
    assert total == EXPECTED_ROWS
    assert shown == EXPECTED_ROWS


def test_virtualisation_keeps_dom_small(page):
    """The whole point of virtualising: DOM row count must not track row count."""
    rendered = page.eval_on_selector_all("#sizer .row", "els => els.length")
    assert rendered > 0
    assert rendered < 60, f"{rendered} rows in DOM — virtualisation is not working"


def test_free_text_search_narrows(page):
    hits = search(page, "Sup3rSecret3")
    # One finding per GPO carries slot 3.
    assert hits == GPO_COUNT
    search(page, "")


def test_search_matches_nothing_for_absent_term(page):
    assert search(page, "definitely-not-in-this-report-xyzzy") == 0
    search(page, "")


def test_quoted_phrase_and_field_scoped_search(page):
    assert search(page, 'trustee:"Domain Users"') == EXPECTED_FINDINGS
    assert search(page, "right:WRITE_DAC") == EXPECTED_FINDINGS
    assert search(page, "type:Script") == EXPECTED_FINDINGS
    assert search(page, "type:Registry") == GPO_COUNT
    search(page, "")


def test_negation_excludes(page):
    total_script = search(page, "type:Script")
    both = search(page, "type:Script -Sup3rSecret3")
    assert both == total_script - GPO_COUNT
    search(page, "")


def test_terms_are_anded(page):
    assert search(page, "Sup3rSecret3 Sup3rSecret4") == 0
    search(page, "")


def test_triage_pill_filters(page):
    page.click('.pill[data-t="Green"]')
    page.wait_for_timeout(120)
    without_green = visible_count(page)[0]
    assert without_green == EXPECTED_ROWS - TRIAGE_TOTALS["Green"]
    page.click('.pill[data-t="Green"]')  # restore
    page.wait_for_timeout(120)
    assert visible_count(page)[0] == EXPECTED_ROWS


def test_none_triage_pill_controls_no_finding_rows(page):
    page.click('.pill[data-t="None"]')
    page.wait_for_timeout(120)
    assert visible_count(page)[0] == EXPECTED_FINDINGS
    page.click('.pill[data-t="None"]')
    page.wait_for_timeout(120)
    assert visible_count(page)[0] == EXPECTED_ROWS


def test_finding_type_facet_filters(page):
    page.click('a[data-none="types"]')
    page.wait_for_timeout(150)
    assert visible_count(page)[0] == 0
    page.click('a[data-all="types"]')
    page.wait_for_timeout(150)
    assert visible_count(page)[0] == EXPECTED_ROWS


def test_detail_pane_shows_finding_and_acl(page):
    page.click("#sizer .row")
    page.wait_for_selector("#detail:not(.hide)")
    detail = page.inner_text("#detail")
    assert "Found a startup script that is writable by a low-privileged user." in detail
    assert "Domain Users" in detail
    assert "GENERIC_WRITE" in detail
    assert "Workstation Policy" in detail
    # Assessed path flags come from the PathResult.
    assert "FILE WRITABLE" in detail
    page.keyboard.press("Escape")


def test_sorting_by_column_reorders(page):
    first_before = page.inner_text("#sizer .row:first-child .c-gpo")
    page.click('.thead [data-sort="gpo"]')
    page.wait_for_timeout(120)
    first_asc = page.inner_text("#sizer .row:first-child .c-gpo")
    page.click('.thead [data-sort="gpo"]')
    page.wait_for_timeout(120)
    first_desc = page.inner_text("#sizer .row:first-child .c-gpo")
    assert first_asc != first_desc


def test_reset_restores_everything(page):
    search(page, "Sup3rSecret1")
    page.click("#btnReset")
    page.wait_for_timeout(150)
    assert visible_count(page)[0] == EXPECTED_ROWS
    assert page.input_value("#q") == ""


def test_csv_export_contains_filtered_rows_only(page, tmp_path):
    search(page, "Sup3rSecret2")
    with page.expect_download() as info:
        page.click("#btnCsv")
    path = tmp_path / "out.csv"
    info.value.save_as(str(path))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == GPO_COUNT + 1  # header + rows
    assert "Triage,GPO,GPO UID" in lines[0]
    assert "Sup3rSecret2" in lines[1]
    page.click("#btnReset")
    page.wait_for_timeout(150)


def test_json_export_is_valid_and_complete(page, tmp_path):
    search(page, "Sup3rSecret5")
    with page.expect_download() as info:
        page.click("#btnJson")
    path = tmp_path / "out.json"
    info.value.save_as(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["rows"]) == GPO_COUNT
    row = data["rows"][0]
    assert row["settingType"] == "ScriptSetting"
    assert row["acl"][0]["trustee"] == "Domain Users"
    assert row["paths"][0]["fileWritable"] is True
    assert row["gpo"]["pathInSysvol"].startswith("\\\\dc01\\sysvol")
    page.click("#btnReset")
    page.wait_for_timeout(150)


def test_report_is_self_contained(report_path):
    """No external resources: the file must be safe to hand to a client offline."""
    markup = report_path.read_text(encoding="utf-8")
    assert "<script src=" not in markup
    assert "<link " not in markup
    assert "http://" not in markup
    assert "https://" not in markup


# ---------------------------------------------------------------- scale guard

SCALE_GPOS = 500
SCALE_PER_GPO = 80
SCALE_ROWS = SCALE_GPOS * SCALE_PER_GPO  # 40,000


@pytest.fixture(scope="module")
def big_report_path(tmp_path_factory):
    """A deliberately large report, to pin the scale characteristics.

    The design claim is that search cost scales with the size of the interned
    string dictionary rather than with the number of findings, and that rendering
    is virtualised. Both are load-bearing for the real-world case this report
    exists for -- domains whose flat-text report runs to hundreds of MB.
    """
    import datetime

    options = AssessmentOptions()
    builder = HtmlReportBuilder(domain="bigcorp.local", command_line="scale test")
    reasons = [
        "Found a startup script that is writable by a low-privileged user.",
        "Found a scheduled task that runs a binary from a writable path.",
        "This GPP setting contains a cpassword value, which is trivially decryptable.",
    ]
    random.seed(11)

    for index in range(SCALE_GPOS):
        attributes = GPOAttributes(
            display_name=f"Corp Policy {index}",
            uid="{%036d}" % index,
            path_in_sysvol=f"\\\\dc01\\sysvol\\bigcorp.local\\Policies\\{{{index:036d}}}",
            computer_policy_enabled=True,
            created_date=datetime.datetime(2023, 1, 1),
        )
        gpo_result = GpoResult(options, attributes)
        for slot in range(SCALE_PER_GPO):
            setting = ScriptSetting(source="registry.pol")
            setting.policy_type = PolicyType.Computer
            finding = GpoFinding(
                finding_reason=reasons[slot % len(reasons)],
                finding_detail=f"item {index}-{slot} at \\\\fs{slot % 30}\\share\\t{slot}.exe",
                triage=random.choice(list(Triage)),
                acl_result=[
                    SimpleAce(
                        trustee=Trustee(display_name="Domain Users", sid="S-1-5-21-1-2-3-513"),
                        ace_type=ACEType.Allow,
                        rights=["GENERIC_WRITE"],
                    )
                ],
            )
            gpo_result.setting_results.append(
                SettingResult(setting=setting, findings=[finding])
            )
        builder.add_gpo_result(gpo_result)

    out = tmp_path_factory.mktemp("big") / "big.html"
    summary = builder.write(str(out))
    assert summary["rowCount"] == SCALE_ROWS
    return out


def test_scale_file_size_stays_small(big_report_path):
    """Interning + gzip must keep the file far smaller than the raw text."""
    size = big_report_path.stat().st_size
    bytes_per_row = size / SCALE_ROWS
    assert bytes_per_row < 60, (
        f"{bytes_per_row:.1f} bytes/row -- compression or interning has regressed"
    )


def test_scale_load_search_and_sort_stay_fast(big_report_path, browser):
    import time

    errors = []
    pg = browser.new_page()
    pg.on("pageerror", lambda e: errors.append(str(e)))
    started = time.time()
    pg.goto(big_report_path.as_uri())
    pg.wait_for_selector("#loading", state="detached", timeout=120_000)
    load_seconds = time.time() - started

    shown, total = visible_count(pg)
    assert total == SCALE_ROWS and shown == SCALE_ROWS

        # Virtualisation: DOM size must not track row count.
    assert pg.eval_on_selector_all("#sizer .row", "e => e.length") < 60

        # Filter latency, measured in-page to exclude the input debounce.
    worst = 0.0
    for query in ["cpassword", 'trustee:"Domain Users"', "type:Script", "-Green t7"]:
        elapsed = pg.evaluate(
            "(q) => { const t = performance.now(); state.query = q; apply();"
            " return performance.now() - t; }",
            query,
        )
        worst = max(worst, elapsed)

    sort_ms = pg.evaluate(
        "() => { const t = performance.now(); sortKey='gpo'; sortDir=1;"
        " sortView(); render(true); return performance.now() - t; }"
    )
    pg.close()

    assert errors == [], f"page errors: {errors}"
    # Generous bounds: these exist to catch an algorithmic regression (e.g. search
    # starting to scan rows instead of the string dictionary), not to benchmark.
    assert load_seconds < 20, f"load took {load_seconds:.1f}s"
    assert worst < 1500, f"worst filter took {worst:.0f}ms"
    assert sort_ms < 1500, f"sort took {sort_ms:.0f}ms"


# ----------------------------------------------------------- scope ("blast radius")

SCOPE_GPOS = 12


@pytest.fixture(scope="module")
def scoped_report_path(tmp_path_factory):
    """A report carrying resolved scope, covering every reach bucket and flag."""
    from group3rpy.ad.scope import GpoLinkRef, GpoScope

    options = AssessmentOptions()
    builder = HtmlReportBuilder(domain="corp.local", command_line="scope test")

    for index in range(SCOPE_GPOS):
        guid = "{%036d}" % index
        attributes = GPOAttributes(
            display_name=f"Policy {index}",
            uid=guid,
            path_in_sysvol=f"\\\\dc\\sysvol\\corp.local\\Policies\\{guid}",
            computer_policy_enabled=True,
        )
        gpo_result = GpoResult(options, attributes)
        setting = ScriptSetting(source="scripts.ini")
        setting.policy_type = PolicyType.Computer
        gpo_result.setting_results.append(
            SettingResult(
                setting=setting,
                findings=[
                    GpoFinding(
                        finding_reason="Writable startup script.",
                        finding_detail=f"detail {index}",
                        triage=Triage.Red,
                    )
                ],
            )
        )

        scope = GpoScope(guid=guid, display_name=attributes.display_name)
        if index > 0:
            scope.links = [
                GpoLinkRef(
                    gpo_guid=guid,
                    container_dn=f"OU=Site{index},DC=corp,DC=local",
                    container_kind="ou",
                    link_index=0,
                    disabled=(index == 1),
                    enforced=(index == 2),
                )
            ]
            if index > 1:
                count = {2: 5, 3: 50, 4: 500, 5: 2000}.get(index, index * 3)
                scope.affected_computers = [
                    f"CN=SRV{i:04d},OU=Site{index},DC=corp,DC=local" for i in range(count)
                ]
            if index == 6:
                scope.security_filter_principals = [
                    Trustee(sid="S-1-5-21-1-2-3-1105", display_name="CORP\\tier1")
                ]
                # ScopeResolver.resolve() adds these; set one explicitly so the
                # detail pane's note rendering is covered too.
                scope.notes = [
                    "Security filtering restricts this GPO to: CORP\\tier1. The "
                    "affected list above is the link scope and may be wider than "
                    "what actually applies."
                ]
            if index == 7:
                scope.wmi_filter = "SELECT * FROM Win32_OperatingSystem"
        builder.add_gpo_result(gpo_result, scope=scope)

    out = tmp_path_factory.mktemp("scoped") / "scoped.html"
    summary = builder.write(str(out))
    assert summary["scopeResolved"] is True
    return out


@pytest.fixture(scope="module")
def scoped_page(scoped_report_path, browser):
    errors = []
    pg = browser.new_page()
    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(scoped_report_path.as_uri())
    pg.wait_for_selector("#loading", state="detached", timeout=30_000)
    pg.errors = errors
    yield pg
    pg.close()


def test_scope_report_loads_cleanly(scoped_page):
    assert scoped_page.errors == [], f"console errors: {scoped_page.errors}"
    assert visible_count(scoped_page)[1] == SCOPE_GPOS


def test_reach_column_renders_counts_and_states(scoped_page):
    cells = scoped_page.eval_on_selector_all("#sizer .c-reach", "e => e.map(x => x.textContent)")
    # GPO 0 is unlinked, GPO 1 has its only link disabled.
    assert "none" in cells, f"expected an unlinked row, got {cells}"
    assert "off" in cells, f"expected a links-disabled row, got {cells}"
    assert "2,000" in cells, f"expected a large reach row, got {cells}"


def test_reach_facet_filters_by_bucket(scoped_page):
    scoped_page.evaluate("() => { state.reach = new Set(['1000+']); apply(); }")
    assert visible_count(scoped_page)[0] == 1
    scoped_page.evaluate("() => { state.reach = new Set(['orphaned']); apply(); }")
    assert visible_count(scoped_page)[0] == 1
    scoped_page.evaluate("() => { state.reach = null; apply(); }")
    assert visible_count(scoped_page)[0] == SCOPE_GPOS


def test_only_show_flags_narrow_results(scoped_page):
    for flag, expected in (("enforced", 1), ("filtered", 1), ("wmi", 1)):
        scoped_page.evaluate(
            "(f) => { state.requireFlags = new Set([f]); apply(); }", flag
        )
        assert visible_count(scoped_page)[0] == expected, f"flag {flag}"
    scoped_page.evaluate("() => { state.requireFlags = new Set(); apply(); }")
    assert visible_count(scoped_page)[0] == SCOPE_GPOS


def test_computer_and_container_search_fields(scoped_page):
    def count_for(query):
        scoped_page.evaluate("(q) => { state.query = q; apply(); }", query)
        return visible_count(scoped_page)[0]

    # Site3's GPO has 50 machines, so SRV0049 is in it but SRV0499 is not.
    assert count_for("container:Site3") == 1
    assert count_for("computer:SRV0499") >= 1
    assert count_for("computer:CN=SRV9999") == 0
    scoped_page.evaluate("() => { state.query = ''; apply(); }")


def test_sorting_by_reach(scoped_page):
    scoped_page.evaluate(
        "() => { sortKey = 'reach'; sortDir = -1; sortView(); render(true); }"
    )
    first = scoped_page.inner_text("#sizer .row:first-child .c-reach")
    assert first == "2,000", f"descending reach sort should lead with the largest, got {first}"


def test_scope_detail_section(scoped_page):
    scoped_page.click("#btnReset")
    scoped_page.wait_for_timeout(150)
    # Pick the security-filtered GPO by searching for it.
    scoped_page.evaluate("() => { state.query = 'gpo:\"Policy 6\"'; apply(); }")
    scoped_page.wait_for_timeout(120)
    scoped_page.click("#sizer .row")
    scoped_page.wait_for_selector("#detail:not(.hide)")
    detail = scoped_page.inner_text("#detail")
    assert "blast radius" in detail.lower()
    assert "affected computers" in detail.lower()
    assert "SECURITY-FILTERED" in detail
    assert "tier1" in detail
    assert "security filtering" in detail.lower()
    scoped_page.keyboard.press("Escape")


def test_csv_export_carries_scope_columns(scoped_page, tmp_path):
    scoped_page.click("#btnReset")
    scoped_page.wait_for_timeout(150)
    with scoped_page.expect_download() as info:
        scoped_page.click("#btnCsv")
    path = tmp_path / "scope.csv"
    info.value.save_as(str(path))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert "Affected computers" in lines[0]
    assert "Scope flags" in lines[0]
    assert any("not linked" in line for line in lines[1:])
    assert any("enforced" in line for line in lines[1:])


def test_json_export_carries_scope_object(scoped_page, tmp_path):
    scoped_page.click("#btnReset")
    scoped_page.wait_for_timeout(150)
    with scoped_page.expect_download() as info:
        scoped_page.click("#btnJson")
    path = tmp_path / "scope.json"
    info.value.save_as(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    scopes = [row["scope"] for row in data["rows"]]
    assert all(s is not None for s in scopes)
    assert any(s["notLinked"] for s in scopes)
    assert any(s["enforced"] for s in scopes)
    assert any(s["securityFilteringNarrowed"] for s in scopes)
    assert any(s["wmiFilter"] for s in scopes)
    biggest = max(scopes, key=lambda s: s["affectedComputerCount"])
    assert biggest["affectedComputerCount"] == 2000
    # The per-GPO computer list is capped, and that must be declared.
    assert biggest["computersTruncated"] is True
    assert len(biggest["computers"]) == 500


def test_report_without_scope_has_no_reach_facet(page):
    """The scope UI must not appear when --scope was not used."""
    assert page.eval_on_selector_all("[data-reach]", "e => e.length") == 0
    cells = page.eval_on_selector_all("#sizer .c-reach", "e => e.map(x => x.textContent)")
    assert cells and all(c.strip() in ("—", "—") for c in cells), cells
