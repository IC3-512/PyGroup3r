"""Port of LibSnaffle/ActiveDirectory/ActiveDirectory.cs

Covers GPO enumeration from a DC, GPO link enumeration, GPO package
enumeration, GPO consolidation against SYSVOL, and recursive group membership
lookup for the target user.

PORT NOTE: the original discovers the forest/domain/DC set through
System.DirectoryServices.ActiveDirectory, which needs a domain-joined Windows
host. Here the domain and DC are supplied explicitly (or derived from the
credentials) and all queries go through impacket. LDAP filters, requested
attributes and all parsing logic are preserved verbatim.
"""

from typing import Callable, Dict, List, Optional

from ..settings.package_setting import PackageSetting
from .gpo import GPO, GPOLink, PolicyType
from .ldap_search import DirectorySearch, parse_ad_timestamp, sid_to_string
from .trustee import Trustee


def _guid_from_bytes(raw: Optional[bytes]) -> Optional[str]:
    """Port of `new Guid(byte[])` -- .NET mixed-endian GUID layout."""
    if not raw or len(raw) < 16:
        return None
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    rest = raw[8:16]
    return (
        f"{d1:08x}-{d2:04x}-{d3:04x}-"
        f"{rest[0]:02x}{rest[1]:02x}-"
        f"{rest[2]:02x}{rest[3]:02x}{rest[4]:02x}{rest[5]:02x}{rest[6]:02x}{rest[7]:02x}"
    )


class ActiveDirectoryException(Exception):
    """Port of LibSnaffle.Errors.ActiveDirectoryException."""


class ActiveDirectory:
    """Port of LibSnaffle.ActiveDirectory.ActiveDirectory."""

    def __init__(
        self,
        directory_search: DirectorySearch,
        logger=None,
        target_domain: Optional[str] = None,
        target_dc: Optional[str] = None,
    ):
        self._directory_search = directory_search
        self.mq = logger
        self.target_domain = target_domain
        self.target_dc = target_dc
        self.gpos: List[GPO] = []
        self.sysvol = None

    # -- logging shims --------------------------------------------------------

    def _trace(self, message: str) -> None:
        if self.mq is not None:
            self.mq.trace(message)

    def _degub(self, message: str) -> None:
        if self.mq is not None:
            self.mq.degub(message)

    def _error(self, message: str) -> None:
        if self.mq is not None:
            self.mq.error(message)

    # -- top-level ------------------------------------------------------------

    def obtain_domain_gpos(self) -> None:
        """Port of the GPO-acquisition block in ActiveDirectory.

        Order matters and is preserved: GPOs, then packages, then links, and the
        empty-result check with the original's error string.
        """
        all_domain_gpos: List[GPO] = []
        try:
            gpos = self.enumerate_domain_gpos_from_dc()
            try:
                self.enumerate_gpo_packages(gpos)
            except Exception as exc:
                self._error(
                    "Error Obtaining Packages from DC " + str(self.target_dc) + " " + str(exc)
                )

            all_domain_gpos.extend(gpos)
            self.gpos = all_domain_gpos
            try:
                self.enumerate_domain_gpo_links()
            except Exception as exc:
                self._error("Failed to enumerate domain GPO links.")
                self._trace(str(exc))
        except Exception as exc:
            self._error(
                "Error Obtaining GPOs from DC " + str(self.target_dc) + " " + str(exc)
            )

        # Ensure we actually got some data.
        if len(self.gpos) == 0:
            raise ActiveDirectoryException(
                "Something fucked out finding stuff in the domain. "
                "You must be holding it wrong."
            )

        self._trace("Successfully got GPO data.")

    # -- GPOs -----------------------------------------------------------------

    def enumerate_domain_gpos_from_dc(self) -> List[GPO]:
        """Port of ActiveDirectory.EnumerateDomainGposFromDC."""
        from ..sddl.sddl import SecurableObjectType, sddl_from_binary

        domain_gpos: List[GPO] = []

        ldap_properties = [
            "adspath",
            "displayname",
            "whencreated",
            "ntsecuritydescriptor",
            "whenchanged",
            "cn",
            "distinguishedname",
            "name",
            "versionnumber",
            "flags",
            # ADDITION: not requested by the C# original; needed so a WMI-filtered
            # GPO can be flagged as possibly narrower in scope than its links imply.
            "gPCWQLFilter",
        ]

        ldap_filter = "(objectClass=groupPolicyContainer)"

        search_result_entries = self._directory_search.query_ldap(
            ldap_filter, ldap_properties, want_security_descriptor=True
        )

        self._trace(f"{len(search_result_entries)} GPOs found.")

        for index, res_ent in enumerate(search_result_entries, start=1):
            self._trace(f"Ingesting attributes for GPO #{index}")
            # Note: Properties can contain multiple values.
            thisuid = res_ent.get_property("name")
            gpo = GPO.create(thisuid)

            gpo.attributes.ads_path = res_ent.get_property("adspath")
            gpo.attributes.display_name = res_ent.get_property("displayname")

            created_date = res_ent.get_property("whenCreated")
            modified_date = res_ent.get_property("whenChanged")
            gpo.attributes.created_date = parse_ad_timestamp(created_date)
            gpo.attributes.modified_date = parse_ad_timestamp(modified_date)

            nt_security_descriptor = res_ent.get_property_as_bytes("ntsecuritydescriptor")
            if nt_security_descriptor:
                # PORT NOTE: the original builds a RawSecurityDescriptor and calls
                # GetSddlForm(AccessControlSections.All) to get an SDDL string,
                # then parses it. Here the binary blob is converted directly, via
                # the same right-name tables, so the resulting ACEs are identical.
                parsed_sddl = sddl_from_binary(
                    nt_security_descriptor, SecurableObjectType.DirectoryServiceObject
                )
                # `Sddl.raw` is the SDDL string the descriptor was parsed from,
                # which is what the C# assigns here (the GetSddlForm result).
                gpo.attributes.nt_security_descriptor = (
                    parsed_sddl.raw if parsed_sddl is not None else None
                )
                gpo.attributes.nt_security_descriptor_sddl = parsed_sddl

            gpo.attributes.uid = res_ent.get_property("name")
            gpo.attributes.version_number = res_ent.get_property("versionnumber")
            gpo.attributes.distinguished_name = res_ent.get_property("distinguishedname")

            gpo.attributes.wmi_filter = res_ent.get_property("gPCWQLFilter")

            gpo_flags = res_ent.get_property("flags")
            if gpo_flags == "0":
                gpo.attributes.user_policy_enabled = True
                gpo.attributes.computer_policy_enabled = True
            elif gpo_flags == "1":
                gpo.attributes.computer_policy_enabled = True
                gpo.attributes.user_policy_enabled = False
            elif gpo_flags == "2":
                gpo.attributes.computer_policy_enabled = False
                gpo.attributes.user_policy_enabled = True
            elif gpo_flags == "3":
                gpo.attributes.computer_policy_enabled = False
                gpo.attributes.user_policy_enabled = False
            else:
                self._degub("Couldn't process GPO Enabled Status. Weird.")

            domain_gpos.append(gpo)

        self._trace("Finished grabbing GPO attributes.")
        return domain_gpos

    # -- links ----------------------------------------------------------------

    def enumerate_domain_gpo_links(self) -> None:
        """Port of ActiveDirectory.EnumerateDomainGpoLinks."""
        ldap_properties = ["gplink", "gpoptions", "name", "displayname"]
        ldap_filter = (
            "(|(objectClass=organizationalUnit)(objectClass=site)(objectClass=domain))"
        )

        search_result_entries = self._directory_search.query_ldap(
            ldap_filter, ldap_properties
        )
        count = len(search_result_entries)
        self._trace(f"{count} sites and OUs found.")

        if count < 1:
            return

        for search_result_entry in search_result_entries:
            try:
                linked_gpos = search_result_entry.get_property("gplink")
                if not linked_gpos or not linked_gpos.strip():
                    continue

                # Split on both ']' and '[' as the original does.
                split_gpos = linked_gpos.replace("[", "]").split("]")

                for gpolink in split_gpos:
                    if gpolink.startswith("LDAP"):
                        gpo_link_result = GPOLink()
                        # The distinguishedname is in the first part, the status
                        # of the gplink in the second.
                        split_link = gpolink.split(";")
                        distinguished_name = split_link[0]
                        cn_index = distinguished_name.upper().find("CN=")
                        distinguished_name = distinguished_name[cn_index:]
                        gpo_link_result.link_path = search_result_entry.distinguished_name

                        # DELIBERATE DIVERGENCE from upstream -- see DIVERGENCES.md.
                        # LibSnaffle/ActiveDirectory/ActiveDirectory.cs:289-292 swaps
                        # the enabled/disabled half of statuses 2 and 3. The gPLink
                        # status is a bitmask: bit 0 (1) = link disabled, bit 1 (2) =
                        # enforced, so 2 is Enabled+Enforced and 3 is Disabled+Enforced.
                        # The label is not cosmetic: nice_gpo_printer tests it with
                        # `"Enabled" in link_enforced` to drive -e/--enabled, so the
                        # upstream mapping hides a GPO that really is enabled and
                        # enforced. `ad/scope.py::parse_gplink` already reads the bits
                        # correctly, so upstream's two paths disagree with each other.
                        status = split_link[1] if len(split_link) > 1 else None
                        if status == "0":
                            gpo_link_result.link_enforced = "Enabled, Unenforced"
                        elif status == "1":
                            gpo_link_result.link_enforced = "Disabled, Unenforced"
                        elif status == "2":
                            gpo_link_result.link_enforced = "Enabled, Enforced"
                        elif status == "3":
                            gpo_link_result.link_enforced = "Disabled, Enforced"

                        try:
                            gpo = next(
                                g
                                for g in self.gpos
                                if (g.attributes.distinguished_name or "").lower()
                                == distinguished_name.lower()
                            )
                            gpo.attributes.gpo_links.append(gpo_link_result)
                        except StopIteration as exc:
                            self._error(
                                "Error looking up GPO "
                                + distinguished_name
                                + " to insert links in it."
                            )
                            self._error(
                                "This seems to happen a LOT in some environments and "
                                "I'm still not sure why. Here's some extra debugging "
                                "info and maybe we can figure it out! Come tell me "
                                "about what you see on the BloodHound Slack in "
                                "#grouper!"
                            )
                            self._error(str(exc))
                    else:
                        if gpolink and gpolink.strip():
                            self._error("Unparsed GPO Link:" + gpolink)
            except Exception as exc:
                self._error(
                    "Something went wrong inserting GPO links into the GPO objects."
                    + str(exc)
                )

    # -- packages -------------------------------------------------------------

    def enumerate_gpo_packages(self, gpos: List[GPO]) -> None:
        """Port of ActiveDirectory.EnumerateGpoPackages."""
        ldap_properties = [
            "displayName",
            "adsPath",
            "distinguishedName",
            "msiFileList",
            "msiScriptName",
            "productCode",
            "whenCreated",
            "whenChanged",
            "upgradeProductCode",
            "cn",
        ]

        ldap_filter = "(objectClass=packageRegistration)"
        search_result_entries = self._directory_search.query_ldap(
            ldap_filter, ldap_properties
        )

        # iterate through the apps found
        for package in search_result_entries:
            try:
                gpo_package = PackageSetting()
                gpo_package.source = "LDAP"
                gpo_package.display_name = package.get_property("displayName")

                # check to see if there are transforms
                msi_file_list = package.get_property_as_array("msiFileList")
                msi_file_count = len(msi_file_list)
                if msi_file_count > 1:
                    for entry in msi_file_list:
                        split_path = entry.split(":")
                        for path in split_path:
                            if path == "0":
                                continue
                            gpo_package.msi_file_list.append(path)
                else:
                    gpo_package.msi_file_list.append(
                        msi_file_list[0].lstrip("0:") if msi_file_list else ""
                    )

                gpo_package.product_code = _guid_from_bytes(
                    package.get_property_as_bytes("productCode")
                )
                gpo_package.upgrade_product_code = _guid_from_bytes(
                    package.get_property_as_bytes("upgradeProductCode")
                )

                gpo_package.created_date = parse_ad_timestamp(
                    package.get_property("whenCreated")
                )
                gpo_package.modified_date = parse_ad_timestamp(
                    package.get_property("whenChanged")
                )

                # Next we need to find the GPO this app is in
                dn = package.distinguished_name
                arr_fqdn = dn.split(",")
                element_pos = len(arr_fqdn) - 5
                parent_gpo_element = arr_fqdn[element_pos].split("=")[1]
                gpo_package.parent_gpo = parent_gpo_element

                # now resolve whether the app is published or assigned
                if len(arr_fqdn) > 3 and arr_fqdn[3] == "CN=User":
                    if package.get_property("msiScriptName") == "A":
                        gpo_package.package_action = "User Assigned"
                    if package.get_property("msiScriptName") == "P":
                        gpo_package.package_action = "User Published"
                    if package.get_property("msiScriptName") == "R":
                        gpo_package.package_action = "Package Removed"
                else:
                    gpo_package.package_action = "Computer Assigned"

                gpo_package.cn = package.get_property("cn")
                # add the package directly into its parent GPO
                gpo_package.policy_type = PolicyType.Package

                parent = next(
                    (p for p in gpos if p.attributes.uid == gpo_package.parent_gpo),
                    None,
                )
                if parent is None:
                    # Mirrors SingleOrDefault(...).Settings throwing when no GPO
                    # matches, which the original wraps as ActiveDirectoryException.
                    raise ActiveDirectoryException(
                        "Error setting GPO packages: no GPO matching "
                        + str(gpo_package.parent_gpo)
                    )
                parent.settings.append(gpo_package)
            except Exception as exc:
                raise ActiveDirectoryException("Error setting GPO packages") from exc

    # -- consolidation --------------------------------------------------------

    def consolidate_gpos(self) -> None:
        """Port of ActiveDirectory.ConsolidateGpos.

        For each GPO found in SYSVOL: if it already exists in the LDAP-derived
        list, attach the sysvol path, append its settings and take its file list;
        otherwise add it as a new GPO.
        """
        import ntpath

        if self.sysvol is None:
            return

        for gpo in self.sysvol.gpos:
            dir_uid = ntpath.basename((gpo.attributes.path_in_sysvol or "").rstrip("\\/"))
            index = next(
                (i for i, g in enumerate(self.gpos) if g.attributes.uid == dir_uid),
                -1,
            )
            if index < 0:
                self.gpos.append(gpo)
            else:
                self.gpos[index].attributes.path_in_sysvol = gpo.attributes.path_in_sysvol
                for setting in gpo.settings:
                    self.gpos[index].settings.append(setting)
                self.gpos[index].gpo_files = gpo.gpo_files

    # -- group membership -----------------------------------------------------

    def get_users_groups_recursive(self, domain_user: str) -> List[Trustee]:
        """Port of ActiveDirectory.GetUsersGroupsRecursive.

        Populates the target trustee set: the user plus every group they are a
        member of, transitively. This drives the `Target` flag on TrusteeOptions,
        which in turn gates a large share of the ACL findings, so the traversal
        semantics (including the de-duplication by distinguishedName) matter.
        """
        results: List[Trustee] = []
        user_filter = "(samaccountname=" + domain_user + ")"
        ldap_properties = ["distinguishedName", "objectsid", "cn"]

        user_search_result_entries = self._directory_search.query_ldap(
            user_filter, ldap_properties
        )

        if len(user_search_result_entries) == 0:
            self._error(
                "Failed to find target user in domain, ACL checks are likely to be "
                "inaccurate."
            )
            return [Trustee(display_name=domain_user, sid="")]

        user_dn = user_search_result_entries[0]
        group_filter = (
            "(&(objectClass=group)(member=" + (user_dn.get_property("distinguishedName") or "") + "))"
        )
        # stick user in result list
        results.append(
            Trustee(
                distinguished_name=user_dn.distinguished_name,
                sid=user_dn.get_sid(),
                display_name=user_dn.get_property("cn"),
            )
        )

        group_search_result_entries = self._directory_search.query_ldap(
            group_filter, ldap_properties
        )

        working_groups: List[Trustee] = []
        # add first round results into bag and list
        for src_group in group_search_result_entries:
            group_dn = Trustee(
                distinguished_name=src_group.distinguished_name,
                display_name=src_group.get_property("cn"),
                sid=src_group.get_sid(),
            )
            self._degub("Added " + str(group_dn.display_name) + " to Target Trustees")
            working_groups.append(group_dn)
            results.append(group_dn)

        # iterate while bag is not empty
        while working_groups:
            sub_group_dn = working_groups.pop()
            sub_group_filter = (
                "(&(objectClass=group)(member=" + (sub_group_dn.distinguished_name or "") + "))"
            )
            sub_group_search_result_entries = self._directory_search.query_ldap(
                sub_group_filter, ldap_properties
            )

            for src_group in sub_group_search_result_entries:
                next_group_dn = src_group.distinguished_name
                # if we don't already have them, add them to working and result vars.
                if not any(g.distinguished_name == next_group_dn for g in results):
                    self._degub("Added " + str(next_group_dn) + " to Target Trustees")
                    working_groups.append(
                        Trustee(
                            distinguished_name=src_group.distinguished_name,
                            display_name=src_group.get_property("cn"),
                            sid=src_group.get_sid(),
                        )
                    )
                    results.append(
                        Trustee(
                            distinguished_name=src_group.distinguished_name,
                            display_name=src_group.get_property("cn"),
                            sid=src_group.get_sid(),
                        )
                    )

        return results

    def build_sid_resolver(self) -> Callable[[str], Optional[str]]:
        """LDAP-backed stand-in for the Win32 LookupAccountSid the original uses.

        Resolves a SID to `DOMAIN\\samaccountname` (falling back to `cn`) and
        caches results, since the same handful of SIDs recur across every GPO.
        """
        cache: Dict[str, Optional[str]] = {}
        netbios = (self.target_domain or "").split(".")[0].upper()

        def resolve(sid: str) -> Optional[str]:
            if sid in cache:
                return cache[sid]
            result: Optional[str] = None
            try:
                entries = self._directory_search.query_ldap(
                    f"(objectSid={sid})", ["samaccountname", "cn"]
                )
                if entries:
                    name = entries[0].get_property("samaccountname") or entries[
                        0
                    ].get_property("cn")
                    if name:
                        result = f"{netbios}\\{name}" if netbios else name
            except Exception:
                result = None
            cache[sid] = result
            return result

        return resolve
