"""Port of LibSnaffle/ActiveDirectory/Users/Trustee.cs

The C# original resolves SIDs with the Win32 LookupAccountSid API and falls back
to a hard-coded well-known SID table. Since this port targets Linux and
authenticates with impacket, SID resolution is done in two stages:

  1. an optional LSAT/LDAP lookup against the target domain, injected by the
     caller as a `resolver` callable (this stands in for LookupAccountSid), and
  2. the well-known SID table below, a literal port of GetWellKnownSid.

The table, its insertion order, the `<DOMAIN>` placeholder rows and the
`splitSid[7] == splitTrustee[5]` RID comparison are reproduced exactly, because
the display names it returns are compared against TrusteeOption.DisplayName all
over the analysers -- changing a single string would change findings.
"""

from dataclasses import dataclass
from typing import Callable, Optional

# Literal port of the sidDict in Trustee.GetWellKnownSid, in original order.
# Insertion order is preserved by dict, matching the C# foreach iteration.
_SID_DICT = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
    "S-1-5-21-<DOMAIN>-498": "Enterprise Read-only Domain Controllers",
    "S-1-5-21-<DOMAIN>-500": "Administrator",
    "S-1-5-21-<DOMAIN>-501": "Guest",
    "S-1-5-21-<DOMAIN>-502": "KRBTGT",
    "S-1-5-21-<DOMAIN>-512": "Domain Admins",
    "S-1-5-21-<DOMAIN>-513": "Domain Users",
    "S-1-5-21-<DOMAIN>-514": "Domain Guests",
    "S-1-5-21-<DOMAIN>-515": "Domain Computers",
    "S-1-5-21-<DOMAIN>-516": "Domain Controllers",
    "S-1-5-21-<DOMAIN>-517": "Cert Publishers",
    "S-1-5-21-<DOMAIN>-518": "Schema Admins",
    "S-1-5-21-<DOMAIN>-519": "Enterprise Admins",
    "S-1-5-21-<DOMAIN>-520": "Group Policy Creator Owners",
    "S-1-5-21-<DOMAIN>-522": "Cloneable Domain Controllers",
    "S-1-5-21-<DOMAIN>-526": "Key Admins",
    "S-1-5-21-<DOMAIN>-527": "Enterprise Key Admins",
    "S-1-5-21-<DOMAIN>-553": "RAS and IAS Servers",
    "S-1-5-21-<DOMAIN>-521": "Read-only Domain Controllers",
    "S-1-5-21-<DOMAIN>-571": "Allowed RODC Password Replication Group",
    "S-1-5-21-<DOMAIN>-572": "Denied RODC Password Replication Group",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
    "S-1-5-80-0": "All Services",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

SID_RESOLUTION_FAILED = "Failed to resolve SID."
SID_RESOLUTION_EXCEPTION = "Failed SID resolution"


def get_well_known_sid(sid: str) -> str:
    """Literal port of Trustee.GetWellKnownSid.

    Note the original's quirks, preserved here:
      * domain SIDs are detected by a `S-1-5-21` prefix check (no trailing dash),
      * for a domain SID only the `<DOMAIN>` rows are consulted, since every
        other row splits into fewer than 5 parts and hits `continue`, which also
        skips that row's exact-match check,
      * the RID comparison is `splitSid[7] == splitTrustee[5]`, so it only
        matches canonical 4-subauthority domain SIDs. A shorter domain SID
        raises IndexError here, which the caller converts the same way the
        original's UserException path does.
    """
    is_domain_sid = sid.startswith("S-1-5-21")

    for key, value in _SID_DICT.items():
        if is_domain_sid:
            split_sid = sid.split("-")
            split_trustee = key.split("-")
            # if there's not at least 5 elements in the sid it's not a domain sid
            if len(split_trustee) < 5:
                continue
            # IndexError here mirrors the original's IndexOutOfRangeException.
            if split_sid[7] == split_trustee[5]:
                return value

        if key == sid:
            return value

    return SID_RESOLUTION_FAILED


@dataclass
class Trustee:
    """Port of LibSnaffle.ActiveDirectory.Trustee."""

    sid: Optional[str] = None
    display_name: Optional[str] = None
    distinguished_name: Optional[str] = None

    @classmethod
    def from_input(
        cls,
        value: str,
        is_sid: bool = True,
        resolver: Optional[Callable[[str], Optional[str]]] = None,
    ) -> "Trustee":
        """Port of the `Trustee(string input, bool isSid = true)` constructor.

        `input.Trim('*')` strips the leading asterisk that GptTmpl.inf writes in
        front of SIDs. `resolver` stands in for LookupAccountSid; as in the
        original, a resolver failure falls through to the well-known table.
        """
        value = (value or "").strip("*")
        if not is_sid:
            return cls(display_name=value)

        display = None
        if resolver is not None:
            try:
                display = resolver(value) or None
            except Exception:
                display = None

        if display is None:
            try:
                display = get_well_known_sid(value)
            except Exception:
                # Mirrors the constructor's catch around the lookup.
                display = SID_RESOLUTION_EXCEPTION

        return cls(sid=value, display_name=display)
