"""Port of LibSnaffle/Sddl.Parser/Sid.cs."""

from .acm import Acm
from .errors import Error
from .format import Format
from .match import Match


class Sid(Acm):
    """Port of the Sddl.Parser.Sid class."""

    def __init__(self, sid: str):
        super().__init__()

        self._raw = sid

        alias = Match.one_by_regex_or_prefix(sid, KNOWN_ALIASES_LIST)

        if alias is None:
            self.report(Error.SDP001.format(sid))

            alias = Format.unknown(sid)

        self._alias = alias

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def alias(self) -> str:
        return self._alias

    def __str__(self) -> str:
        return str(self._alias)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Sid) and self._alias == other._alias

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self._alias)


# A list of tuples of bigram in format XX as define in https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings and
# well known SIDs in format S-* as defined in https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems.
#
# (bigram, sid, alias)
KNOWN_ALIASES_LIST: list[tuple[str | None, str, str]] = [
    (None, "^S-1-0$", r"Null Authority"),
    (None, "^S-1-0-0$", r"Nobody"),
    (None, "^S-1-1$", r"World Authority"),
    ("WD", "^S-1-1-0$", r"Everyone"),
    (None, "^S-1-2$", r"Local Authority"),
    (None, "^S-1-2-0$", r"Local"),
    (None, "^S-1-2-1$", r"Console Logon"),
    (None, "^S-1-3$", r"Creator Authority"),
    ("CO", "^S-1-3-0$", r"Creator Owner"),
    ("CG", "^S-1-3-1$", r"Creator Group"),
    (None, "^S-1-3-2$", r"Creator Owner Server"),
    (None, "^S-1-3-3$", r"Creator Group Server"),
    ("OW", "^S-1-3-4$", r"Owner Rights"),
    (None, "^S-1-4$", r"Non-unique Authority"),
    (None, "^S-1-5$", r"NT Authority"),
    (None, "^S-1-5-1$", r"Dialup"),
    ("NU", "^S-1-5-2$", r"Network"),
    (None, "^S-1-5-3$", r"Batch"),
    ("IU", "^S-1-5-4$", r"Interactive"),
    (None, "^S-1-5-5-(.+)-(.+)$", r"Logon Session"),
    ("SU", "^S-1-5-6$", r"Service"),
    ("AN", "^S-1-5-7$", r"Anonymous"),
    (None, "^S-1-5-8$", r"Proxy"),
    ("ED", "^S-1-5-9$", r"Enterprise Domain Controllers"),
    ("PS", "^S-1-5-10$", r"Principal Self"),
    ("AU", "^S-1-5-11$", r"Authenticated Users"),
    ("RC", "^S-1-5-12$", r"Restricted Code"),
    (None, "^S-1-5-13$", r"Terminal Server Users"),
    (None, "^S-1-5-14$", r"Remote Interactive Logon"),
    (None, "^S-1-5-15$", r"This Organization"),
    (None, "^S-1-5-17$", r"IUSR"),
    ("SY", "^S-1-5-18$", r"Local System"),
    ("LS", "^S-1-5-19$", r"Local Service"),
    ("NS", "^S-1-5-20$", r"Network Service"),
    ("LA", "^S-1-5-21(.*)-500$", r"Administrator"),
    ("LG", "^S-1-5-21(.*)-501$", r"Guest"),
    (None, "^S-1-5-21(.*)-502$", r"KRBTGT"),
    ("DA", "^S-1-5-21(.*)-512$", r"Domain Admins"),
    ("DU", "^S-1-5-21(.*)-513$", r"Domain Users"),
    ("DG", "^S-1-5-21(.*)-514$", r"Domain Guests"),
    ("DC", "^S-1-5-21(.*)-515$", r"Domain Computers"),
    ("DD", "^S-1-5-21(.*)-516$", r"Domain Controllers"),
    ("CA", "^S-1-5-21(.*)-517$", r"Cert Publishers"),
    ("SA", "^S-1-5-21(.*)-518$", r"Schema Admins"),
    ("EA", "^S-1-5-21(.*)-519$", r"Enterprise Admins"),
    ("PA", "^S-1-5-21(.*)-520$", r"Group Policy Creator Owners"),
    ("AP", "^S-1-5-21(.*)-525$", r"Protected Users"),
    ("KA", "^S-1-5-21(.*)-526$", r"Key Admins"),
    ("EK", "^S-1-5-21(.*)-527$", r"Enterprise Key Admins"),
    ("RS", "^S-1-5-21(.*)-553$", r"RAS and IAS Servers"),
    ("BA", "^S-1-5-32-544$", r"Administrators"),
    ("BU", "^S-1-5-32-545$", r"Users"),
    ("BG", "^S-1-5-32-546$", r"Guests"),
    ("PU", "^S-1-5-32-547$", r"Power Users"),
    ("AO", "^S-1-5-32-548$", r"Account Operators"),
    ("SO", "^S-1-5-32-549$", r"Server Operators"),
    ("PO", "^S-1-5-32-550$", r"Print Operators"),
    ("BO", "^S-1-5-32-551$", r"Backup Operators"),
    ("RE", "^S-1-5-32-552$", r"Replicators"),
    ("WR", "^S-1-5-33$", r"Write Restricted Code"),
    (None, "^S-1-5-64-10$", r"NTLM Authentication"),
    (None, "^S-1-5-64-14$", r"SChannel Authentication"),
    (None, "^S-1-5-64-21$", r"Digest Authentication"),
    (None, "^S-1-5-80$", r"NT Service"),
    (None, "^S-1-5-80-0$", r"All Services"),
    (None, "^S-1-5-83-0$", "NT VIRTUAL MACHINE\\Virtual Machines"),
    (None, "^S-1-16-0$", r"Untrusted Mandatory Level"),
    (None, "^S-1-16-4096$", r"Low Mandatory Level"),
    (None, "^S-1-16-8192$", r"Medium Mandatory Level"),
    (None, "^S-1-16-8448$", r"Medium Plus Mandatory Level"),
    (None, "^S-1-16-12288$", r"High Mandatory Level"),
    (None, "^S-1-16-16384$", r"System Mandatory Level"),
    (None, "^S-1-16-20480$", r"Protected Process Mandatory Level"),
    (None, "^S-1-16-28672$", r"Secure Process Mandatory Level"),
    ("RU", "^S-1-5-32-554$", "BUILTIN\\Pre-Windows 2000 Compatible Access"),
    ("RD", "^S-1-5-32-555$", "BUILTIN\\Remote Desktop Users"),
    ("NO", "^S-1-5-32-556$", "BUILTIN\\Network Configuration Operators"),
    (None, "^S-1-5-32-557$", "BUILTIN\\Incoming Forest Trust Builders"),
    ("MU", "^S-1-5-32-558$", "BUILTIN\\Performance Monitor Users"),
    ("LU", "^S-1-5-32-559$", "BUILTIN\\Performance Log Users"),
    (None, "^S-1-5-32-560$", "BUILTIN\\Windows Authorization Access Group"),
    (None, "^S-1-5-32-561$", "BUILTIN\\Terminal Server License Servers"),
    (None, "^S-1-5-32-562$", "BUILTIN\\Distributed COM Users"),
    ("RO", "^S-1-5-21(.*)-498$", r"Enterprise Read-only Domain Controllers"),
    (None, "^S-1-5-21(.*)-521$", r"Read-only Domain Controllers"),
    ("IS", "^S-1-5-32-568$", r"IIS_IUSRS"),
    ("CY", "^S-1-5-32-569$", "BUILTIN\\Cryptographic Operators"),
    (None, "^S-1-5-21(.*)-571$", r"Allowed RODC Password Replication Group"),
    (None, "^S-1-5-21(.*)-572$", r"Denied RODC Password Replication Group"),
    ("ER", "^S-1-5-32-573$", "BUILTIN\\Event Log Readers"),
    ("CD", "^S-1-5-32-574$", "BUILTIN\\Certificate Service DCOM Access"),
    ("CN", "^S-1-5-21(.*)-522$", r"Cloneable Domain Controllers"),
    ("RA", "^S-1-5-32-575$", "BUILTIN\\RDS Remote Access Servers"),
    ("ES", "^S-1-5-32-576$", "BUILTIN\\RDS Endpoint Servers"),
    ("MS", "^S-1-5-32-577$", "BUILTIN\\RDS Management Servers"),
    ("HA", "^S-1-5-32-578$", "BUILTIN\\Hyper-V Administrators"),
    ("AA", "^S-1-5-32-579$", "BUILTIN\\Access Control Assistance Operators"),
    ("RM", "^S-1-5-32-580$", "BUILTIN\\Remote Management Users"),
    ("UD", "^S-1-5-84-0-0-0-0-0$", r"User-Mode Driver Process"),
    ("AC", "^S-1-15-2-1$", r"All App Package"),
    ("AS", "^S-1-18-1$", r"Authentication Authority Asserted Identity"),
    ("SS", "^S-1-18-2$", r"Service Asserted Identity"),
]
