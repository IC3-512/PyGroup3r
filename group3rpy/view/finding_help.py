"""Operator-facing explanations for findings. PORT ADDITION -- not in upstream.

Upstream Group3r tells you *what* it found and leaves the rest to you; the
GPO-ACL finding's detail text is literally "IDK just look at it jeez." That is
fine when the person reading the report wrote the tool, and unhelpful otherwise.

Each entry answers three questions, in the spirit of BloodHound's edge help:

    what    -- what the setting actually does, in plain terms
    abuse   -- what an attacker does with it, concretely
    fix     -- what the defender changes

This is rendered **only in the HTML report**, which is itself a port addition.
Nothing here touches `NiceGpoPrinter` or the JSON printer, so the text output
stays byte-identical to the original -- see DIVERGENCES.md.

Matching is by finding-reason prefix, because several analysers append a value
to the reason ("Group Policy Preferences password found:" + the password). The
longest matching prefix wins; `types` is a fallback keyed on the setting class
name for findings whose reason is too generic to key on.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Each entry: slug -> (title, what, abuse, fix, reason-prefixes, setting-types)
_ENTRIES: List[Dict[str, object]] = [
    {
        "slug": "gpp-cpassword",
        "title": "Group Policy Preferences password",
        "what": (
            "A Group Policy Preferences item stores a credential in SYSVOL, "
            "encrypted with AES-256. Microsoft published the key in MSDN in 2012 "
            "(MS14-025), so the encryption is decorative -- the password above was "
            "recovered from the policy file, not guessed."
        ),
        "abuse": (
            "Any domain user can read SYSVOL, so any domain user can read this "
            "password. These accounts are usually local administrators on every "
            "machine the GPO applies to, or service accounts with rights across the "
            "estate, so the result is typically immediate lateral movement. Check "
            "the blast radius above for exactly which machines, and try the "
            "credential against them and against any account with the same name."
        ),
        "fix": (
            "Delete the preference item -- clearing the password field is not enough, "
            "the cpassword stays in the XML until the item is removed. Rotate the "
            "account's password, and check SYSVOL for older copies in "
            "Policies_NTFRS_* replication-failure directories. For local admin "
            "passwords use LAPS instead."
        ),
        "reasons": ["Group Policy Preferences password found:"],
    },
    {
        "slug": "gpo-acl",
        "title": "Interesting ACLs on the GPO object",
        "what": (
            "The access control list on the GPO object itself in Active Directory "
            "grants rights beyond the usual Domain Admins / Enterprise Admins / "
            "SYSTEM set. The Access Control table below lists every ACE; the ones "
            "that matter grant write access to a principal that is not already "
            "domain-privileged."
        ),
        "abuse": (
            "Write access to a GPO means control of every machine and user the GPO "
            "applies to. An attacker holding WRITE_DAC, WRITE_OWNER, GENERIC_ALL or "
            "WRITE_PROPERTY on the object can add an immediate scheduled task, a "
            "startup script or a local-group membership, wait for the refresh "
            "interval, and execute as SYSTEM on everything in scope. The blast "
            "radius above is the list of machines that would be affected. This is "
            "BloodHound's GenericWrite/GenericAll-on-GPO path."
        ),
        "fix": (
            "Remove the delegation, or narrow it to the specific attribute the "
            "delegated team actually needs. Treat write access to any GPO linked at "
            "the domain or Domain Controllers OU as equivalent to Domain Admin, and "
            "audit it on the same cycle."
        ),
        "reasons": ["Found some interesting ACLs on this GPO"],
    },
    {
        "slug": "priv-right",
        "title": "Privileged user right assignment",
        "what": (
            "A Windows privilege or logon right is granted to this trustee by policy "
            "on every machine in scope. Several of these are equivalent to local "
            "administrator even when the account is not in the Administrators group."
        ),
        "abuse": (
            "SeDebugPrivilege allows opening any process, including LSASS, so it "
            "yields credential dumping. SeImpersonate/SeAssignPrimaryToken enable the "
            "Potato family of local privilege escalations. SeBackup/SeRestore read "
            "and write any file regardless of its ACL, including the registry hives "
            "needed to extract local secrets. SeLoadDriver loads a signed vulnerable "
            "driver for kernel execution. SeTakeOwnership takes ownership of any "
            "object, then rewrites its ACL. If the trustee is a broad group such as "
            "Everyone, Authenticated Users or Domain Users, every domain user gets it."
        ),
        "fix": (
            "Remove the assignment, or replace the broad group with the specific "
            "accounts that need it. SeBackup/SeRestore belong to Backup Operators "
            "with the group tightly held; SeDebugPrivilege should be Administrators "
            "only."
        ),
        "reasons": [
            "Well-known low-priv user/group assigned an interesting OS privilege.",
            "User/group assigned an interesting OS privilege.",
        ],
    },
    {
        "slug": "group-membership",
        "title": "Privileged local group membership",
        "what": (
            "Policy adds a member to a privileged local group -- usually the local "
            "Administrators group -- on every machine in scope."
        ),
        "abuse": (
            "If the added principal is a broad group such as Domain Users, "
            "Authenticated Users or a large helpdesk group, then every one of those "
            "users is a local administrator on every machine the GPO reaches. That is "
            "a direct path to credential dumping on those hosts and to any session "
            "present on them -- BloodHound's AdminTo edge, which this report also "
            "emits in its Cypher export."
        ),
        "fix": (
            "Replace the broad group with a per-tier administrative group scoped to "
            "the machines that genuinely need it, and keep tier-0 accounts out of "
            "workstation admin groups entirely."
        ),
        "reasons": [
            "A privileged local group is having a low-priv member added to it.",
            "A privileged local group is having a member added to it.",
            "A privileged local group is being renamed.",
        ],
    },
    {
        "slug": "service-acl",
        "title": "Abusable service permissions",
        "what": (
            "Policy sets the security descriptor of a Windows service so that a "
            "non-administrative principal can reconfigure it."
        ),
        "abuse": (
            "SERVICE_CHANGE_CONFIG lets the trustee repoint the service binary and "
            "restart it, executing as whatever account the service runs under -- "
            "usually LocalSystem. WRITE_DAC and WRITE_OWNER let them grant themselves "
            "that right first. This is local privilege escalation on every machine in "
            "scope, and it is applied by policy, so it is uniform and persistent."
        ),
        "fix": (
            "Restore the default service descriptor, or grant only the specific right "
            "required (usually just start/stop, not change-config) to a narrow group."
        ),
        "reasons": ["A Windows service's ACL is being configured to grant abusable"],
    },
    {
        "slug": "registry-bad-value",
        "title": "Weakening registry value",
        "what": (
            "A registry value is being set by policy to something weaker than the "
            "recommended configuration, on every machine in scope."
        ),
        "abuse": (
            "The impact depends on the key. Common ones: "
            "WDigest UseLogonCredential=1 puts cleartext passwords back in LSASS; "
            "LmCompatibilityLevel below 3 allows LM/NTLMv1, which is crackable and "
            "relayable; disabling SMB signing enables NTLM relay; "
            "AlwaysInstallElevated lets any user install an MSI as SYSTEM; "
            "EnableLUA=0 disables UAC; LocalAccountTokenFilterPolicy=1 re-enables "
            "remote local-admin logons; RestrictAnonymous=0 permits anonymous "
            "enumeration. Autologon keys store the password in cleartext in the "
            "registry, readable by any local user."
        ),
        "fix": (
            "Set the value back to the recommended setting, or remove it from policy "
            "and let the secure default apply. Check the Detail field for the value "
            "found and what was expected."
        ),
        "reasons": [
            "This registry key was set to a 'less-than-good' value",
            "This registry key was found to match a known-vulnerable value.",
            "This registry key being present at all is considered interesting.",
            "This registry key was set to a non-default value",
        ],
    },
    {
        "slug": "registry-acl",
        "title": "Interesting registry key ACL",
        "what": (
            "Policy applies a security descriptor to a registry key that grants "
            "rights to a non-administrative principal."
        ),
        "abuse": (
            "Write access to a key under HKLM that feeds service configuration, "
            "start-up execution (Run keys, AppInit_DLLs, Image File Execution "
            "Options) or COM registration gives code execution, often as SYSTEM and "
            "often persistently."
        ),
        "fix": (
            "Remove the grant or narrow it. Registry keys delegated to broad groups "
            "should be treated with the same care as filesystem ACLs on program "
            "directories."
        ),
        "reasons": ["Found some interesting ACEs on a registry key"],
    },
    {
        "slug": "writable-path",
        "title": "Writable file or directory in a policy-driven execution path",
        "what": (
            "Policy points at a file that you can modify, or at a path that does not "
            "exist inside a directory that you can write to."
        ),
        "abuse": (
            "Every machine in scope executes or consumes this path. Replacing the "
            "file -- or creating it, if policy references something that is missing -- "
            "runs attacker code on all of them, in the context the policy uses "
            "(SYSTEM for computer policy, the user for user policy). A missing file "
            "in a writable directory is the better primitive: nothing is overwritten, "
            "so nothing breaks and the change is unlikely to be noticed."
        ),
        "fix": (
            "Restrict write access on the share and directory to administrators, "
            "recreate the missing file, and prefer SYSVOL over an ordinary file "
            "server for policy-referenced content -- SYSVOL is read-only to users by "
            "default."
        ),
        "reasons": [
            "Writable file identified at ",
            "Writable ",
            "Scheduled Task execute action points at a file that you can modify.",
            "Scheduled Task execute action points to a file that doesn't exist",
            "Scheduled task exec action is configured to use a working directory",
            "Shortcut points at a file that you can modify.",
            "Shortcut points to a file that doesn't exist",
            "Shortcut is configured to use a working directory",
            "A GPP File GPO setting is missing its source file",
        ],
    },
    {
        "slug": "password-in-args",
        "title": "Credential in a command line",
        "what": (
            "The arguments of a scheduled task, shortcut or logon script look like "
            "they contain a password."
        ),
        "abuse": (
            "The value is readable from SYSVOL by any domain user, and it is also "
            "visible in process command lines on every machine that runs it, so it is "
            "recoverable from memory, from EDR telemetry and from event logs with "
            "command-line auditing enabled. Treat it as disclosed."
        ),
        "fix": (
            "Move the credential to a managed service account or a secret store, "
            "rotate what is there now, and check logging pipelines that may have "
            "retained the command line."
        ),
        "reasons": [
            "Scheduled Task exec action has an arguments setting that looks like",
            "Shortcut has an arguments setting that looks like",
            "Logon script has an arguments setting that looks like",
            "Script has an arguments setting that looks like",
        ],
    },
    {
        "slug": "datasource",
        "title": "Database connection details",
        "what": (
            "A GPP data source distributes ODBC connection details, often including a "
            "username and a stored password."
        ),
        "abuse": (
            "Gives a server name, a database and frequently a working credential. "
            "Database service accounts are commonly over-privileged both in SQL and "
            "in the domain, and SQL Server offers onward paths -- xp_cmdshell, linked "
            "servers, and impersonation -- to the host and beyond."
        ),
        "fix": (
            "Use integrated authentication rather than a stored credential, rotate "
            "anything already published this way, and review the account's rights on "
            "the database."
        ),
        "reasons": ["Potentially useful database connection info identified."],
    },
    {
        "slug": "kerberos-policy",
        "title": "Non-default Kerberos policy",
        "what": (
            "A Kerberos policy value differs from the Windows default. On its own "
            "this is informational -- it tells you how tickets behave in this domain."
        ),
        "abuse": (
            "Long ticket lifetimes widen the window in which a stolen or forged "
            "ticket stays valid, which matters for golden/silver ticket persistence "
            "and for pass-the-ticket. A large clock skew tolerance makes forged "
            "timestamps easier. 'Enforce user logon restrictions' disabled means the "
            "KDC stops validating that the user still has the right to log on to the "
            "target, so revocation is slower to take effect."
        ),
        "fix": (
            "Return to the defaults unless there is a documented reason: 10 hours "
            "ticket age, 7 days renewal, 600 minutes service ticket, 5 minutes skew, "
            "and logon restrictions enforced."
        ),
        "reasons": [
            "Non-default maximum Kerberos",
            "Non-default minimum Kerberos",
            "Kerberos 'Enforce user logon restrictions' setting is disabled.",
        ],
    },
    {
        "slug": "password-policy",
        "title": "Account and password policy",
        "what": (
            "A password or lockout policy value differs from the default, or a "
            "protective setting has been turned off."
        ),
        "abuse": (
            "Weak length or disabled complexity makes offline cracking of captured "
            "hashes and online password spraying far more productive. A missing or "
            "generous lockout threshold makes spraying essentially unlimited; a very "
            "aggressive one is its own problem, since it can be used for denial of "
            "service against accounts. Reversible encryption stores passwords "
            "recoverably in the directory."
        ),
        "fix": (
            "Align with current guidance: length over complexity, screen against "
            "breached-password lists, and never enable reversible encryption."
        ),
        "reasons": [
            "Non-default lockout",
            "Non-default maximum password age.",
            "Non-default minimum password age.",
            "Non-default minimum password length.",
            "Non-default password history size.",
            "Password complexity disabled.",
            "Passwords are stored using reversible encryption",
            "Force logoff outside hours is enforced.",
        ],
    },
    {
        "slug": "lsa-anon",
        "title": "Anonymous access to LSA policy",
        "what": (
            "Policy permits unauthenticated callers to query the local security "
            "authority."
        ),
        "abuse": (
            "Allows enumeration of users, groups, the machine's domain membership and "
            "the password policy without credentials -- the classic RID-cycling and "
            "null-session reconnaissance that feeds a password spray."
        ),
        "fix": (
            "Set RestrictAnonymous and RestrictAnonymousSAM back to the restrictive "
            "values, and remove 'Everyone' from the pre-Windows 2000 compatible "
            "access group if it is still present."
        ),
        "reasons": ["Anonymous users can query the local LSA policy."],
    },
    {
        "slug": "local-accounts",
        "title": "Built-in local account state",
        "what": (
            "Policy changes the state or name of the built-in Administrator or Guest "
            "account."
        ),
        "abuse": (
            "An enabled Guest account allows unauthenticated share access on machines "
            "in scope. Renaming the Administrator account is cosmetic -- it keeps RID "
            "500, so it is trivially found again -- and is worth noting mainly because "
            "the new name tells you what to spray. A uniformly configured built-in "
            "administrator across the estate implies a shared password unless LAPS is "
            "in use."
        ),
        "fix": (
            "Keep Guest disabled. Deploy LAPS so the built-in administrator password "
            "differs per machine, and prefer per-admin named accounts."
        ),
        "reasons": [
            "Local Administrator account disabled.",
            "Local Administrator account name changed.",
            "Local Guest account enabled.",
            "Local Guest account name changed.",
        ],
    },
    {
        "slug": "snaffler-path",
        "title": "Interesting path",
        "what": (
            "The Snaffler classifier matched this path by name -- it looks like it "
            "holds credentials, keys, configuration or backups."
        ),
        "abuse": (
            "Policy-referenced shares are readable by every user the policy applies "
            "to. Files matching these patterns routinely contain connection strings, "
            "private keys, unattend.xml answer files with embedded passwords, or "
            "database dumps."
        ),
        "fix": (
            "Review the contents, move secrets into a managed store, and restrict the "
            "share to the principals that need it."
        ),
        "reasons": [
            "The Snaffler engine deemed this directory path interesting on its own.",
            "The Snaffler engine deemed this file path interesting on its own.",
        ],
    },
    {
        "slug": "sched-task-email",
        "title": "Scheduled task email action",
        "what": "A scheduled task sends mail, possibly with attachments.",
        "abuse": (
            "The task definition carries the SMTP server, sender and recipients, and "
            "sometimes credentials. Attachment paths reveal where interesting files "
            "live, and the mail flow itself can be a data egress channel."
        ),
        "fix": "Review the recipients and attachment paths; remove stored credentials.",
        "reasons": ["Scheduled Task is emailing attachments."],
    },
]

# Reason prefix -> slug, longest prefix first so specific beats general.
_BY_REASON: List[tuple] = sorted(
    ((reason, entry["slug"])
     for entry in _ENTRIES
     for reason in entry.get("reasons", [])),
    key=lambda pair: len(pair[0]),
    reverse=True,
)

_BY_SLUG: Dict[str, Dict[str, object]] = {e["slug"]: e for e in _ENTRIES}


def lookup_slug(reason: Optional[str]) -> Optional[str]:
    """Best matching help entry for a finding reason, or None."""
    if not reason:
        return None
    for prefix, slug in _BY_REASON:
        if reason.startswith(prefix):
            return slug
    return None


def entries_for_payload() -> List[Dict[str, str]]:
    """The KB in the order the HTML payload indexes it."""
    return [
        {
            "slug": str(e["slug"]),
            "title": str(e["title"]),
            "what": str(e["what"]),
            "abuse": str(e["abuse"]),
            "fix": str(e["fix"]),
        }
        for e in _ENTRIES
    ]


def slug_order() -> Dict[str, int]:
    """slug -> index into `entries_for_payload()`."""
    return {str(e["slug"]): i for i, e in enumerate(_ENTRIES)}
