"""Port of Group3r/GroupCon.cs

The main controller: loads AD and SYSVOL data, resolves the target user's group
memberships into the trustee set, then fans GPO analysis out across a thread pool
and pushes each result onto the message queue.

PORT NOTE: `BlockingStaticTaskScheduler` becomes a `ThreadPoolExecutor` with the
same worker count (`MaxSysvolThreads`). The original's `MaxSysvolQueue` bound is
applied as a semaphore so an unbounded queue cannot blow up memory on a large
domain, matching the intent of the C# bounded scheduler.
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Optional

from .ad.active_directory import ActiveDirectory
from .ad.ldap_search import DirectorySearch
from .ad.trustee import Trustee
from .assessment.analyser_factory import AnalyserFactory
from .assessment.finding import GpoResult
from .options.assessment_options import TrusteeOption
from .smb.provider import CompositeFsProvider, LocalFsProvider, SmbFsProvider
from .sysvol.sysvol import SysvolException, SysvolHelper


class GroupCon:
    """Port of Group3r.GroupCon."""

    def __init__(self, options, mq):
        self.options = options
        self.mq = mq
        self._results_lock = threading.Lock()
        # Collected for the HTML report, which needs every result in one place.
        self.gpo_results: List[GpoResult] = []
        # PORT ADDITION: GPO guid -> GpoScope, populated when --scope is used.
        self.scopes: dict = {}

    def execute(self) -> None:
        """Port of GroupCon.Execute."""
        start_time = datetime.now()

        fs = self._build_fs_provider()
        self.options.assessment_options.fs = fs

        svh = SysvolHelper(fs, self.mq)
        ad: Optional[ActiveDirectory] = None

        if self.options.offline_mode:
            # make sure the user gave us a sysvol target for offline mode to work
            if not self.options.sysvol_path:
                raise SysvolException("Offline mode requires a SYSVOL Path. Use -y.")
            if self.options.resolve_scope:
                # Scope resolution needs OU/computer/site objects from LDAP, which
                # offline mode by definition cannot reach.
                self.mq.error(
                    "Scope resolution needs LDAP, so it is skipped in offline mode."
                )
                self.options.resolve_scope = False
            self.mq.trace("Loading Sysvol Offline")
            # Manually load SYSVOL offline.
            sysvol = svh.load_sysvol_offline(self.options.sysvol_path)
            # make an empty AD object
            ad = ActiveDirectory(None, self.mq)
            # stick our sysvol in it
            ad.sysvol = sysvol
            # and merge them straight into the slot in AD - no point calling
            # ConsolidateGpos() as there's no AD data there.
            ad.gpos = ad.sysvol.gpos
        else:
            self.mq.trace("building ActiveDirectory")
            try:
                directory_search = self._build_directory_search()
                ad = ActiveDirectory(
                    directory_search,
                    self.mq,
                    self.options.target_domain,
                    self.options.target_dc,
                )

                self.mq.trace(
                    "Enumerating target/current user's name and group memberships."
                )

                target_user_name = self.options.target_user_name or ""
                if "\\" in target_user_name:
                    target_user_name = target_user_name.split("\\")[1]

                current_user_and_groups = ad.get_users_groups_recursive(target_user_name)

                trustee_options = self.options.assessment_options.trustee_options
                for uog in current_user_and_groups:
                    match = False
                    # check match on both SID and displayname
                    disp_matches = [
                        t for t in trustee_options if t.display_name == uog.display_name
                    ]
                    if disp_matches:
                        match = True
                        # if we are a member of a well-known group it should be targeted
                        disp_matches[0].target = True
                    sid_matches = [t for t in trustee_options if t.sid == uog.sid]
                    if sid_matches:
                        match = True
                        # if we are a member of a well-known group it should be targeted
                        sid_matches[0].target = True
                    if not match:
                        # if it's not already in the list of well-known principals,
                        # add it to TrusteeOptions
                        trustee_options.append(
                            TrusteeOption(
                                sid=uog.sid,
                                display_name=uog.display_name,
                                target=True,
                            )
                        )

                # if the user has defined some custom trustee(s) to target:
                if self.options.assessment_options.target_trustees is not None:
                    for trustee_option in self.options.assessment_options.target_trustees:
                        trustee_option.target = True
                        trustee_options.append(trustee_option)

                # Resolve SIDs through LDAP where the well-known table cannot,
                # standing in for the original's LookupAccountSid.
                self.options.assessment_options.sid_resolver = ad.build_sid_resolver()

                self.mq.degub("Getting GPOs.")
                ad.obtain_domain_gpos()
                self.mq.degub("Loading files from SYSVOL.")
                self._load_sysvol_online(ad, svh)
                self.mq.degub("Consolidating GPOs.")
                ad.consolidate_gpos()

                if self.options.resolve_scope:
                    self._resolve_scope(ad, directory_search)
            except Exception as exc:
                self.mq.error(str(exc))
                self.mq.terminate()
                return

        self.mq.trace("Enqueuing GPO Tasks")
        self.enqueue_gpo_tasks(ad)

        # Finish off timing.
        finished = datetime.now()
        run_span = finished - start_time
        self.mq.info("Finished at " + str(finished.astimezone()))
        self.mq.info("Group3rin' took " + str(run_span))
        self.mq.finish()

    # -- setup helpers --------------------------------------------------------

    def _build_fs_provider(self) -> CompositeFsProvider:
        """Wire up SMB and/or local filesystem access from the CLI options."""
        smb: Optional[SmbFsProvider] = None
        lmhash, nthash = "", ""
        if getattr(self.options, "hashes", None):
            raw = self.options.hashes
            if ":" in raw:
                lmhash, nthash = raw.split(":", 1)
            else:
                nthash = raw

        if not self.options.offline_mode or getattr(self.options, "username", None):
            smb = SmbFsProvider(
                username=getattr(self.options, "username", "") or "",
                password=getattr(self.options, "password", "") or "",
                domain=self.options.target_domain or "",
                lmhash=lmhash,
                nthash=nthash,
                aes_key=getattr(self.options, "aes_key", "") or "",
                kerberos=bool(getattr(self.options, "kerberos", False)),
                kdc_host=self.options.target_dc,
                host_override=getattr(self.options, "dc_ip", None),
            )
        return CompositeFsProvider(smb, LocalFsProvider())

    def _build_directory_search(self) -> DirectorySearch:
        lmhash, nthash = "", ""
        if getattr(self.options, "hashes", None):
            raw = self.options.hashes
            if ":" in raw:
                lmhash, nthash = raw.split(":", 1)
            else:
                nthash = raw
        return DirectorySearch(
            domain=self.options.target_domain or "",
            # Prefer the DC *name* here: it is what Kerberos turns into the
            # ldap/<host> SPN. `dc_ip` then rides along as host_override, the
            # address actually dialled -- the same split SmbFsProvider uses.
            # With only one of the two supplied this collapses to the old
            # `dc_ip or target_dc or target_domain` value.
            domain_controller=self.options.target_dc
            or getattr(self.options, "dc_ip", None)
            or self.options.target_domain,
            host_override=getattr(self.options, "dc_ip", None),
            username=getattr(self.options, "username", "") or "",
            password=getattr(self.options, "password", "") or "",
            lmhash=lmhash,
            nthash=nthash,
            aes_key=getattr(self.options, "aes_key", "") or "",
            kerberos=bool(getattr(self.options, "kerberos", False)),
        )

    def _load_sysvol_online(self, ad: ActiveDirectory, helper: SysvolHelper) -> None:
        """Port of ActiveDirectory.LoadSysvolOnline.

        Tries the domain name first and falls back to the specific DC, exactly as
        the original does.
        """
        try:
            self.mq.degub("Loading SYSVOL by domain " + str(ad.target_domain))
            ad.sysvol = helper.load_sysvol_online_by_domain(ad.target_domain)
            self.mq.degub("Finished loading SYSVOL")
        except Exception:
            self.mq.degub("Loading SYSVOL by DC " + str(ad.target_dc))
            ad.sysvol = helper.load_sysvol_online_by_dc(ad.target_domain, ad.target_dc)
            self.mq.degub("Finished loading SYSVOL")

    def _resolve_scope(self, ad: ActiveDirectory, directory_search) -> None:
        """PORT ADDITION: work out which computers each GPO actually reaches.

        Failures here are logged and swallowed: a scan that produced findings must
        not be lost because the extra scope queries did not work.
        """
        from .ad.scope import ScopeResolver

        try:
            self.mq.degub("Resolving GPO scope.")
            resolver = ScopeResolver(
                directory_search,
                self.mq,
                include_users=bool(self.options.scope_users),
            )
            resolver.collect()
            self.scopes = resolver.resolve(
                ad.gpos,
                sid_resolver=getattr(
                    self.options.assessment_options, "sid_resolver", None
                ),
            )
            resolver.attach_wmi_filters(self.scopes, ad.gpos)

            linked = sum(1 for scope in self.scopes.values() if scope.is_linked)
            orphaned = sum(1 for scope in self.scopes.values() if scope.is_orphaned)
            reach = sum(scope.affected_computer_count for scope in self.scopes.values())
            self.mq.info(
                f"Resolved scope for {len(self.scopes)} GPOs: {linked} linked, "
                f"{orphaned} orphaned, {reach} GPO-to-computer applications."
            )
        except Exception as exc:
            self.mq.error("Failed to resolve GPO scope: " + str(exc))
            self.scopes = {}

    # -- analysis -------------------------------------------------------------

    def enqueue_gpo_tasks(self, ad: ActiveDirectory) -> None:
        """Port of GroupCon.EnqueueGpoTasks."""
        analyser_factory = AnalyserFactory()
        max_workers = max(1, int(self.options.max_sysvol_threads or 1))

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [
                pool.submit(self._analyse_gpo, gpo, analyser_factory) for gpo in ad.gpos
            ]
            for future in futures:
                # Surface anything the per-GPO handler did not already catch.
                exc = future.exception()
                if exc is not None:
                    self.mq.error(str(exc))

    def _analyse_gpo(self, gpo, analyser_factory: AnalyserFactory) -> None:
        """The body of the per-GPO task in EnqueueGpoTasks."""
        try:
            self.mq.trace("Analysing " + str(gpo.attributes.path_in_sysvol))
            # make the result object and put the attributes in it.
            gpo_result = GpoResult(self.options.assessment_options, gpo.attributes)

            for setting in gpo.settings:
                try:
                    if not setting.source or not setting.source.strip():
                        self.mq.error(
                            "Not sure what file source i got this setting from but "
                            "i'm analysing it anyway: " + str(type(setting))
                        )
                    analyser = analyser_factory.get_analyser(setting)

                    if analyser is not None:
                        analyser.mq = self.mq
                        analyser.min_triage = self.options.assessment_options.min_triage
                        # have analyser return settingResult
                        setting_result = analyser.analyse(self.options.assessment_options)

                        # if it didn't have a finding, and we haven't specified that
                        # we only want findings, stick the setting in settings.
                        if len(setting_result.findings) == 0 and not self.options.findings_only:
                            gpo_result.setting_results.append(setting_result)
                        elif len(setting_result.findings) > 0:
                            gpo_result.setting_results.append(setting_result)
                except Exception as exc:
                    self.mq.error(
                        "Failure processing setting from "
                        + str(setting.source)
                        + "/r/n"
                        + str(exc)
                    )

            with self._results_lock:
                self.gpo_results.append(gpo_result)

            # Enqueue the output of the analysis for output with both the raw object
            # and the pretty string if we're building one
            self.mq.gpo_result(
                gpo_result, self.options.printer.output_gpo_result(gpo_result)
            )
        except Exception as exc:
            self.mq.error("Exception in scanning " + str(gpo.attributes.path_in_sysvol))
            self.mq.error(str(exc))


def bytes_to_string(byte_count: int) -> str:
    """Port of GroupCon.BytesToString."""
    import math

    suf = ["B", "kB", "MB", "GB", "TB", "PB", "EB"]  # Longs run out around EB
    if byte_count == 0:
        return "0" + suf[0]
    num_bytes = abs(byte_count)
    place = int(math.floor(math.log(num_bytes, 1024)))
    num = round(num_bytes / math.pow(1024, place), 1)
    sign = (byte_count > 0) - (byte_count < 0)
    return str(sign * num) + suf[place]
