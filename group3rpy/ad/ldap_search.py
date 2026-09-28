"""Port of LibSnaffle/ActiveDirectory/LDAP/DirectorySearch.cs (and the bits of
Extensions.cs / Helpers.cs that read attributes off a search result).

PORT NOTE: the original uses System.DirectoryServices.Protocols, which implicitly
authenticates as the logged-on Windows user. Here the transport is impacket's
LDAP client, so credentials are explicit (password, NTLM hash, or Kerberos) and a
target DC must be resolvable. Query semantics -- filters, requested attributes,
subtree scope, paging -- are preserved.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from impacket.ldap import ldap as impacket_ldap
from impacket.ldap import ldapasn1

# LDAP_SERVER_SD_FLAGS_OID. Asking for OWNER|GROUP|DACL keeps the query readable
# by an unprivileged user; SACL would need SeSecurityPrivilege and AD silently
# returns nothing for the whole attribute if you ask for it without the right.
LDAP_SERVER_SD_FLAGS_OID = "1.2.840.113556.1.4.801"
SD_FLAGS_OWNER_GROUP_DACL = 0x07


class SearchResultEntry:
    """Wraps one LDAP entry, mirroring the C# extension methods.

    `GetProperty`, `GetPropertyAsBytes`, `GetPropertyAsArray` and `GetSid` from
    Extensions.cs become `get_property`, `get_property_as_bytes`,
    `get_property_as_array` and `get_sid`. Attribute lookup is
    case-insensitive, matching the .NET behaviour the original relies on (it
    requests `"ntsecuritydescriptor"` but reads `"whenCreated"`).
    """

    def __init__(self, distinguished_name: str, attributes: Dict[str, List[bytes]]):
        self.distinguished_name = distinguished_name
        # Store lowercased keys; keep raw byte values so callers can choose.
        self._attributes = {k.lower(): v for k, v in attributes.items()}

    @property
    def attributes(self) -> Dict[str, List[bytes]]:
        return self._attributes

    def get_property(self, name: str) -> Optional[str]:
        values = self._attributes.get(name.lower())
        if not values:
            return None
        value = values[0]
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def get_property_as_bytes(self, name: str) -> Optional[bytes]:
        values = self._attributes.get(name.lower())
        if not values:
            return None
        value = values[0]
        return value if isinstance(value, bytes) else str(value).encode()

    def get_property_as_array(self, name: str) -> List[str]:
        values = self._attributes.get(name.lower()) or []
        out = []
        for value in values:
            out.append(
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes)
                else str(value)
            )
        return out

    def get_sid(self) -> Optional[str]:
        """Port of Extensions.GetSid -- objectSid bytes to S-1-5-21-... form."""
        raw = self.get_property_as_bytes("objectsid")
        if not raw:
            return None
        return sid_to_string(raw)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SearchResultEntry {self.distinguished_name}>"


def sid_to_string(raw: bytes) -> Optional[str]:
    """Convert a binary SID to its S-1-... string form."""
    if not raw or len(raw) < 8:
        return None
    revision = raw[0]
    sub_authority_count = raw[1]
    identifier_authority = int.from_bytes(raw[2:8], "big")
    parts = [f"S-{revision}-{identifier_authority}"]
    offset = 8
    for _ in range(sub_authority_count):
        if offset + 4 > len(raw):
            break
        parts.append(str(int.from_bytes(raw[offset : offset + 4], "little")))
        offset += 4
    return "-".join(parts)


def parse_ad_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Port of `DateTime.ParseExact(x, "yyyyMMddHHmmss.0K", InvariantCulture)`.

    AD generalised time is `20240131120000.0Z`; the `K` specifier also accepts a
    `+hhmm`/`-hhmm` offset, so both are handled. Returns None rather than raising,
    because a GPO with an unparseable timestamp should still be reported.
    """
    if not value:
        return None
    value = value.strip()
    try:
        head, _, tail = value.partition(".")
        base = datetime.strptime(head, "%Y%m%d%H%M%S")
        tail = tail.lstrip("0")
        if tail in ("Z", ""):
            return base.replace(tzinfo=timezone.utc)
        sign = 1 if tail.startswith("+") else -1
        digits = tail[1:].replace(":", "")
        hours = int(digits[0:2] or 0)
        minutes = int(digits[2:4] or 0)
        return base.replace(
            tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes))
        )
    except Exception:
        return None


class DirectorySearch:
    """Port of LibSnaffle.ActiveDirectory.LDAP.DirectorySearch."""

    def __init__(
        self,
        domain: str,
        domain_controller: Optional[str] = None,
        username: str = "",
        password: str = "",
        lmhash: str = "",
        nthash: str = "",
        aes_key: str = "",
        kerberos: bool = False,
        use_ldaps: bool = False,
        base_dn: Optional[str] = None,
        host_override: Optional[str] = None,
    ):
        self.domain = domain
        self.domain_controller = domain_controller or domain
        # PORT NOTE: mirrors SmbFsProvider.host_override. `domain_controller` is
        # the *name* the DC is known by, which is what Kerberos needs to build the
        # ldap/<host> SPN; `host_override` is the address actually connected to.
        # Passing both lets `--dc <fqdn> --dc-ip <ip>` work under Kerberos on a
        # host that cannot resolve the domain's DNS. When only one is supplied
        # they are the same value, which is the pre-existing behaviour.
        self.host_override = host_override
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes_key = aes_key
        self.kerberos = kerberos
        self.use_ldaps = use_ldaps
        self.base_dn = base_dn or domain_to_base_dn(domain)
        self._connection: Optional[impacket_ldap.LDAPConnection] = None

    def connect(self) -> impacket_ldap.LDAPConnection:
        if self._connection is not None:
            return self._connection
        scheme = "ldaps" if self.use_ldaps else "ldap"
        url = f"{scheme}://{self.domain_controller}"
        # impacket's third LDAPConnection argument is the address it dials; the
        # host in the URL is what it derives the Kerberos SPN from.
        dst_ip = self.host_override or self.domain_controller
        try:
            conn = impacket_ldap.LDAPConnection(url, self.base_dn, dst_ip)
            if self.kerberos:
                conn.kerberosLogin(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                    self.aes_key,
                    kdcHost=dst_ip,
                )
            else:
                conn.login(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                )
        except impacket_ldap.LDAPSessionError:
            # Fall back to LDAPS, since many hardened DCs refuse simple/NTLM
            # binds over cleartext 389.
            if self.use_ldaps:
                raise
            self.use_ldaps = True
            conn = impacket_ldap.LDAPConnection(
                f"ldaps://{self.domain_controller}", self.base_dn, dst_ip
            )
            if self.kerberos:
                conn.kerberosLogin(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                    self.aes_key,
                    kdcHost=dst_ip,
                )
            else:
                conn.login(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                )
        self._connection = conn
        return conn

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None

    def query_ldap(
        self,
        ldap_filter: str,
        attributes: Iterable[str],
        search_base: Optional[str] = None,
        want_security_descriptor: bool = False,
    ) -> List[SearchResultEntry]:
        """Port of DirectorySearch.QueryLdap with subtree scope.

        impacket handles paging internally, which replaces the original's
        PageResultRequestControl loop.
        """
        conn = self.connect()
        attribute_list = list(attributes)

        controls = []
        if want_security_descriptor:
            from impacket.ldap.ldap import SimplePagedResultsControl  # noqa: F401

            controls.append(_sd_flags_control(SD_FLAGS_OWNER_GROUP_DACL))

        results: List[SearchResultEntry] = []

        def record_handler(item) -> None:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                return
            dn = str(item["objectName"])
            attrs: Dict[str, List[bytes]] = {}
            for attribute in item["attributes"]:
                key = str(attribute["type"])
                values: List[bytes] = []
                for value in attribute["vals"]:
                    raw = value.asOctets() if hasattr(value, "asOctets") else bytes(value)
                    values.append(raw)
                attrs[key] = values
            results.append(SearchResultEntry(dn, attrs))

        try:
            conn.search(
                searchBase=search_base or self.base_dn,
                searchFilter=ldap_filter,
                attributes=attribute_list,
                sizeLimit=0,
                searchControls=controls or None,
                perRecordCallback=record_handler,
            )
        except impacket_ldap.LDAPSearchError as exc:
            # A sizeLimit-exceeded style error still yields the records already
            # collected, which matches the original's best-effort behaviour.
            if "sizeLimitExceeded" not in str(exc):
                raise
        return results


def _sd_flags_control(flags: int):
    """Build an LDAP_SERVER_SD_FLAGS_OID control requesting the given SD parts."""
    from pyasn1.codec.der import encoder
    from pyasn1.type import namedtype, univ

    class SDFlagsRequestValue(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("Flags", univ.Integer())
        )

    request_value = SDFlagsRequestValue()
    request_value.setComponentByName("Flags", flags)

    control = ldapasn1.Control()
    control["controlType"] = LDAP_SERVER_SD_FLAGS_OID
    control["criticality"] = True
    control["controlValue"] = encoder.encode(request_value)
    return control


def domain_to_base_dn(domain: str) -> str:
    """`corp.local` -> `DC=corp,DC=local`."""
    if not domain:
        return ""
    if domain.upper().startswith("DC="):
        return domain
    return ",".join(f"DC={part}" for part in domain.split(".") if part)
