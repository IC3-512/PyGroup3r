# Group3r reference output — how it was produced, and what it does NOT cover

Reference output from the **original, unmodified C# Group3r**, run in OFFLINE mode
against the upstream test fixture, for use as ground truth when diffing a port.

| | |
|---|---|
| Upstream source | `/opt/group3r/upstream` (**never modified** — read-only reference) |
| Upstream commit | `3c4911ed65e09f0935ca4e684b72bf650233602f` (2025-04-08, "Merge pull request #22 from Scrogga/clock-skew") |
| Fixture | `/opt/group3r/upstream/TestSysvol` (8 GPO dirs under `TestSysvol/Policies/`) |
| Primary runtime | `mono` 6.8.0.105 (Debian/Ubuntu `6.8.0.105+dfsg-3.6ubuntu2`) |
| Build toolchain | `dotnet` SDK 8.0.131 / MSBuild 17.8, targeting **net48** |
| Cross-check runtime | .NET 8 (see "Cross-runtime validation") |

**No C# source file in `upstream/` was edited.** Not one. The primary build compiles
the upstream `.cs` files exactly as they are on disk.

---

## 1. Did it build? Yes.

`mono` 6.8 on this box has **no** `msbuild`/`xbuild` (`mono-devel` is not installed;
only `mcs` and the runtime are), so the original `Group3r.sln` /
`packages.config` route is not available. The route that worked:

* SDK-style `.csproj` files that **reference the upstream `.cs` files in place**
  (`<Compile Include="/opt/group3r/upstream/…/**/*.cs" />`), so the reference
  source tree is never copied or touched;
* `TargetFramework` = `net48` instead of the upstream `v4.5.1`, via the
  `Microsoft.NETFramework.ReferenceAssemblies` 1.0.3 NuGet package (real .NET
  Framework reference assemblies — so `System.DirectoryServices*`,
  `System.Security.AccessControl`, `WindowsIdentity` etc. **all compile with zero
  stubs and zero `#if`**);
* `PackageReference` for the two real dependencies, `NLog` 4.7.12 and
  `CommandLineArgumentsParser` 3.0.22. `dnMerge` (an ILMerge-style post-build step)
  and `System.ValueTuple` / `Portable.System.ValueTuple` were dropped: the former is
  irrelevant to behaviour, the latter are built into `net48`;
* the resulting net48 `Group3r.exe` is executed by `mono`.

Build files live in `build/` (see §5). The built, ready-to-run output is in `bin/`.

### Rebuild from scratch

```sh
# 1. primary (mono / net48) build — needs network for the NuGet restore
cd /opt/group3r/reference/build/Group3r
dotnet build -c Release          # also builds ../LibSnaffle

# 2. drop the three runtime stub assemblies next to the exe (see §2)
cd /opt/group3r/reference/build/stubs
mcs -target:library -out:System.DirectoryServices.dll                   sds.cs
mcs -target:library -out:System.DirectoryServices.AccountManagement.dll sdsam.cs
mcs -target:library -out:System.DirectoryServices.Protocols.dll         sdsp.cs
cp *.dll /opt/group3r/reference/build/Group3r/bin/Release/

# 3. that directory is now equivalent to reference/bin/
```

Verified: a from-scratch rebuild of `build/` reproduces `original_nice.txt` exactly
(`normalise.py --drop-stacks` diff = 0). Without `--drop-stacks` you see ~52 lines
of difference: mono prints the assembly MVID inside managed stack-trace lines
(`… in <04c6fc29e918…>:0`) and that GUID changes on every compile. It is build
metadata, not behaviour.

### Re-run (exact commands used for every file in this directory)

All runs use `-f <file>` (NLog file target), **not** `-s` (stdout) — see §4.1.
`stdin` is redirected from `/dev/null` because the unhandled-exception path calls
`Console.ReadLine()`.

```sh
cd /opt/group3r/reference/bin
S=/opt/group3r/upstream/TestSysvol
R=/opt/group3r/reference

mono Group3r.exe -o -y $S -f $R/original_nice.txt                 </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_mintriage1.txt  -a 1 </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_mintriage2.txt  -a 2 </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_mintriage3.txt  -a 3 </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_mintriage4.txt  -a 4 </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_findingsonly.txt -w  </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_enabledonly.txt  -e  </dev/null
mono Group3r.exe -o -y $S -f $R/original_nice_currentonly.txt  -r  </dev/null
mono Group3r.exe -o -y $S -f $R/original_trace.txt      -v trace   </dev/null
mono Group3r.exe -h > $R/original_help.txt                         </dev/null

# the (unreliable) stdout variant, kept only for comparison
mono Group3r.exe -o -y $S -s > $R/original_stdout_nondeterministic.txt 2>&1 </dev/null

# SID-fallback variant (§3.3) — run from the other bin dir
cd /opt/group3r/reference/bin-sidfallback
LD_LIBRARY_PATH=$PWD mono Group3r.exe -o -y $S -f $R/original_nice_sidfallback.txt        </dev/null
LD_LIBRARY_PATH=$PWD mono Group3r.exe -o -y $S -f $R/original_trace_sidfallback.txt -v trace </dev/null

# canonical (sorted) form of each, for diffing
for f in $R/original_*.txt; do
  case "$f" in *canonical*|*help*|*stdout*) continue;; esac
  python3 $R/normalise.py "$f" > "${f%.txt}.canonical.txt"
done
```

Offline-mode flags, from `Group3r/Options/OptionsParser.cs`:
`-o/--offline`, `-y/--sysvol <path>`, `-s/--stdout`, `-f/--outfile <path>`,
`-a/--mintriage 1..4`, `-w/--findingsonly`, `-e/--enabled`, `-r/--currentonly`,
`-v/--verobsity info|debug|degub|trace`, `-t/--threads`, `-u/--testuser`,
`-c/--dc`, `-d/--domain`, `-h/--help`.

---

## 2. What is stubbed — READ THIS BEFORE TRUSTING ANY DIFF

### 2.1 Three stub framework assemblies (compile-time: none; runtime: type loading only)

mono 6.8 ships `System.DirectoryServices.dll` but **without** the
`System.DirectoryServices.ActiveDirectory` namespace, and ships **no**
`System.DirectoryServices.AccountManagement.dll` and no
`System.DirectoryServices.Protocols.dll` at all. `LibSnaffle.ActiveDirectory`
has *properties* of those types (`Forest`, `Domain`, `DomainCollection`,
`DirectoryContext`, `DomainControllerCollection`, `PrincipalContext`), so merely
**loading** the class fails — which, because `GroupCon.Execute()` runs inside a
`Task` whose exception nobody observes, made the program hang forever with no
output. (Microsoft's real `net48` *reference* assemblies cannot be used at
runtime: mono rejects them with `BadImageFormatException`.)

Fix: three minimal assemblies (`build/stubs/*.cs`, ~45 lines total) declaring
**only the type names**, all members empty/throwing:

| Stub assembly | Types declared |
|---|---|
| `System.DirectoryServices.dll` | `System.DirectoryServices.ActiveDirectory`: `ActiveDirectoryOperationException`, `ActiveDirectoryPartition`, `DirectoryContext`, `DirectoryContextType`, `Domain`, `DomainCollection`, `DomainControllerCollection`, `Forest` |
| `System.DirectoryServices.AccountManagement.dll` | `PrincipalContext` |
| `System.DirectoryServices.Protocols.dll` | `DirectoryAttribute`, `DirectoryConnection`, `DirectoryControl`, `DirectoryControlCollection`, `DirectoryRequest`, `DirectoryResponse`, `LdapConnection`, `LdapDirectoryIdentifier`, `LdapSessionOptions`, `PageResultRequestControl`, `PageResultResponseControl`, `PartialResultProcessing`, `ReferralChasingOptions`, `SearchOption`, `SearchOptionsControl`, `SearchRequest`, `SearchResponse`, `SearchResultAttributeCollection`, `SearchResultEntry`, `SearchResultEntryCollection`, `SearchScope`, `SecurityDescriptorFlagControl`, `SecurityMasks` |

**Consequence:** ONLINE mode (`ActiveDirectory.ObtainDomainGpos`, `LoadSysvolOnline`,
`ConsolidateGpos`, `GetUsersGroupsRecursive`, all of
`LibSnaffle/ActiveDirectory/LDAP/*`) would throw the instant it is touched. It is
**not exercised and not covered** by this reference output. That is fine — offline
mode never enters those code paths — but a port's LDAP/AD code has **no** ground
truth here.

### 2.2 Nothing else is stubbed in the primary build

`System.Security.AccessControl`, `WindowsIdentity`, `Sddl.Parser`, the SDDL/ACE
analysers, `System.IO.Compression`, `AesCryptoServiceProvider`, NLog, the argument
parser, every `GpoFile` parser, every analyser and the `NiceGpoPrinter` all run as
the real upstream code.

---

## 3. Known platform divergences — features MISSING from this reference

These are things a **Windows** run of the same unmodified binary against the same
fixture would print but this Linux reference does not. Three of the four are
upstream Windows-only assumptions, not artefacts of the build.

### 3.1 ALL `Registry.pol` settings are silently dropped — biggest gap

`LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/PolGpoFile.cs:48,52`:

```csharp
if (FilePath.ToLower().Contains("\\machine\\"))      { setting.Hive = RegHive.HKEY_LOCAL_MACHINE; }
else if (FilePath.ToLower().Contains("\\user\\"))    { setting.Hive = RegHive.HKEY_CURRENT_USER;  }
else throw new NotImplementedException("Something went wrong trying to figure out the hive …");
```

Hard-coded `\` separators. On Linux the path is `/Machine/`, so **every**
`Registry.pol` throws and **all Administrative-Template registry settings are
lost**. All 4 `Registry.pol` files in the fixture are affected, including a 60 KB one:

```
{5CFC9C70-A964-4FA0-A1EB-91C36271CA98}/Machine/Registry.pol   60766 bytes
{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol    2736 bytes
{36FA6290-EFEE-4909-845A-4A33A04D3088}/Machine/Registry.pol    2586 bytes
{2CE5ACF5-D072-4267-8E45-5C8F8843DEC6}/Machine/Registry.pol    2586 bytes
```

The failure is logged at **Degub** level only ("Something went wrong trying to
figure out the hive associated with this registry.pol file"), so in
`original_nice.txt` it is completely invisible — see `original_trace.txt` (4 hits).

Note the same project gets this *right* three files away, in
`Sysvol.sortSettings()`, which uses `Path.DirectorySeparatorChar`. So a port that
uses `os.sep` will emit **more** Registry settings than this reference. **That is
correct behaviour, not a regression.** There is no way to make the unmodified C#
produce these settings on Linux: renaming the directory to literally `\Machine\`
satisfies `PolGpoFile` but then breaks `Sysvol.sortSettings()`, which looks for
`/machine/`.

### 3.2 4 of 14 `scripts.ini` script settings are dropped (local NTFS ACL read)

`Group3r/Assessment/FsAclAnalyser.cs:123,133` calls
`Directory.GetAccessControl` / `File.GetAccessControl`, which throw
`PlatformNotSupportedException` on Linux (both on mono and on .NET 8). The
exception escapes `ScriptAnalyser.Analyse`, so the **whole setting** is discarded,
not just the ACL finding. 4 `[Error] Failure processing setting from …` lines in
`original_nice.txt`; 10 of the fixture's 14 script entries survive. Missing:

```
{5CFC9C70-A964-4FA0-A1EB-91C36271CA98}/User/Scripts/scripts.ini      (2 settings)
{2CE5ACF5-D072-4267-8E45-5C8F8843DEC6}/Machine/Scripts/scripts.ini   (1 setting)
{36FA6290-EFEE-4909-845A-4A33A04D3088}/Machine/Scripts/scripts.ini   (1 setting)
```

Local-filesystem ACL analysis (`FsAclAnalyser`, `PathAnalyser.AnalyseDirPath`,
`CurrentUserSecurity`) is therefore **entirely uncovered** by this reference. It is
also inherently machine-specific (it reads the ACL of whatever local/UNC path the
policy names), so it is a poor fidelity target anyway.

### 3.3 SID → name resolution: `advapi32!LookupAccountSid` is unavailable

`LibSnaffle/ActiveDirectory/Users/Trustee.cs:58` P/Invokes
`advapi32.dll!LookupAccountSid`. On Linux the DLL does not exist, so the P/Invoke
raises `DllNotFoundException`, `GetUserFromSid` rethrows it as `UserException`, and
the `Trustee` constructor swallows it and sets `DisplayName = "Failed SID
resolution"` — **bypassing Group3r's own `GetWellKnownSid()` table**, which would
otherwise have been reached via the `err != 0` branch.

Result in `original_nice.txt`: **150** `Failed SID resolution` trustees, including
well-known SIDs such as `S-1-5-32-544` that Windows resolves to
`BUILTIN\Administrators`.

Because `GetWellKnownSid()` is pure, portable logic that a port almost certainly
*does* implement, there is a second set of outputs that exercises it:

**`original_nice_sidfallback.txt` / `original_trace_sidfallback.txt`**, produced from
`bin-sidfallback/`, which adds:

* `build/advapi32shim/advapi32_shim.c` → `libadvapi32shim.so`: exports
  `LookupAccountSid{,A,W}`, which do nothing but `errno = 1332`
  (`ERROR_NONE_MAPPED`) and return `FALSE`;
* `LibSnaffle.dll.config` with `<dllmap dll="advapi32.dll" target="libadvapi32shim.so"/>`.

That makes the P/Invoke *fail* exactly the way it fails on a real Windows box that
cannot map the SID, which is the in-code fallback path, so Group3r's own well-known
SID table runs. It resolves nothing itself. Still no C# was changed.

Effect: `Failed SID resolution` drops from 150 to 81; `S-1-5-32-544` →
`Administrators`, `S-1-5-32-549` → `Server Operators`,
`S-1-5-20` → `NT Authority\Network Service`, etc. The 81 remaining are real domain
SIDs (`S-1-5-21-1861388480-899987619-2527135411-1104`) that genuinely need a DC.

**Which file to diff against?** Use `original_nice.txt` to verify "the unmodified
original on this box". Use `original_nice_sidfallback.txt` to verify a port's
well-known-SID table. Neither covers real SAM/LDAP account lookups.

### 3.4 mono-only: `CryptographicException: Bad PKCS7 padding. Invalid length 0.`

Two GPP `Groups.xml` files carry `cpassword=""`. `GpoSetting.DecryptCpassword`
base64-decodes that to a 0-byte array and calls
`ICryptoTransform.TransformFinalBlock(empty)`. .NET Framework and .NET 8 both
return an empty array; **mono throws**. Two `[Error]` lines in the reference.

**Verified to cost nothing:** the .NET 8 cross-check run (§4.2) does *not* raise
this exception, and its printed settings and findings are byte-identical to mono's,
including all `Group` settings from those two `Groups.xml` files. So this is log
noise only — no setting is lost. Ignore these 2 `[Error]` messages (and their
stack traces) when diffing; `normalise.py --drop-stacks` removes them.

### 3.5 Not a divergence: there is no JSON printer

The task asked for JSON output. **Upstream has none.** `Group3r/View/JsonGpoPrinter.cs`
is 100 % commented out (it needed Newtonsoft.Json, which is not in
`packages.config`), and `GpoPrinterFactory.GetPrinter()` has its whole `switch`
commented out and unconditionally returns `new NiceGpoPrinter(options)`. There is
also no `--printer` argument registered in `OptionsParser` (the
`case "printer":` in the switch is dead code — no matching
`parser.Arguments.Add`). **No JSON reference output exists and none was
fabricated.**

---

## 4. Determinism — how to diff this correctly

### 4.1 Do not use `-s`/stdout

NLog's `ColoredConsoleTarget` writes multi-line messages non-atomically, and
Group3r analyses GPOs on 15 worker threads, so the stdout stream **duplicates and
interleaves fragments**: `original_stdout_nondeterministic.txt` contains 514
`| Setting - …` lines where only 344 settings exist, and the duplicate count
varies run to run (170, 163, …). This reproduces identically on .NET 8, so it is
a genuine Group3r/NLog defect, not a mono artefact — but it makes stdout useless
as ground truth. That file is kept only to document the defect.

The `-f` file target is clean: 344 settings, 49 findings, 8 `[GPO]` blocks, stable.

### 4.2 Message order still varies; use `normalise.py`

Even with `-f`, the **order** of `[GPO]` report blocks, of log messages, and of the
per-setting tables *within* a GPO varies between runs (worker pool sized by the
hard-coded `GrouperOptions.MaxSysvolThreads = 15`; note `-t/--threads` sets
`MaxThreads`, which does **not** control that pool, so you cannot serialise it).
Content is deterministic.

`normalise.py` strips timestamps, drops the two wall-clock lines, sorts the
per-setting blocks inside each `[GPO]` message and then sorts the messages:

```sh
python3 normalise.py original_nice.txt              > a.canon   # verified: 0 diff over 3 runs
python3 normalise.py --drop-stacks port_output.txt  > b.canon   # cross-language: drop [Error]+stacks
python3 normalise.py --sort-lines  x.txt            > x.lines   # pure line-multiset check
diff a.canon b.canon
```

The `*.canonical.txt` files here are `normalise.py` output for the matching
`*.txt`.

### 4.3 Cross-runtime validation (why you can trust the mono numbers)

The same upstream sources were also compiled for `net8.0`
(`build/net8-crosscheck/`) and run on .NET 8. After `normalise.py --drop-stacks`
the two outputs differ by **exactly 16 lines**, all of the form

```
| Date Created    | 1/1/0001 12:00:00 AM  |
| Date Modified   | 1/1/0001 12:00:00 AM  |
```

where .NET 8 emits U+202F (narrow no-break space) before `AM` and
mono/.NET Framework emit U+0020. **Every setting, every finding, every trustee and
every table is byte-identical.** mono/net48 is the faithful one here (.NET 8's ICU
date formatting is the outlier), which is why it is the primary reference.

The net8 build needed two shims that the mono build did **not** —
`build/net8-crosscheck/Group3r/shim/AclShim.cs` (.NET Core dropped the static
`Directory.GetAccessControl`/`File.GetAccessControl`; the shim forwards to the
`DirectoryInfo`/`FileInfo` extension methods) and `WindowsIdentityShim.cs`
(.NET Core throws from `WindowsIdentity.GetCurrent()`; the value only feeds
`TargetUserName`, read exclusively by online mode). Those shims are **not** part
of the primary mono reference.

---

## 5. Contents of this directory

| Path | What |
|---|---|
| `original_nice.txt` | **Primary reference.** `-o -y TestSysvol -f` (default triage, all settings). 3535 lines, 344 settings, 49 findings, 8 GPOs. |
| `original_nice_mintriage{1,2,3,4}.txt` | same with `-a 1` … `-a 4` |
| `original_nice_findingsonly.txt` | `-w` |
| `original_nice_enabledonly.txt` | `-e` (every fixture GPO is disabled, so this is nearly empty — 56 lines) |
| `original_nice_currentonly.txt` | `-r` (no `Policies_NTFRS_*` dirs in the fixture, so identical to the default) |
| `original_trace.txt` | `-v trace` — per-file parse decisions; the only place the dropped `Registry.pol` files are visible |
| `original_nice_sidfallback.txt`, `original_trace_sidfallback.txt` | as above but with the `advapi32` dllmap shim of §3.3, so Group3r's well-known-SID table runs |
| `*.canonical.txt` | `normalise.py` output of the matching file — order-normalised, safe to `diff` |
| `original_help.txt` | `-h` |
| `original_stdout_nondeterministic.txt` | `-s` variant. **Do not diff against this** (§4.1). |
| `normalise.py` | order-normaliser / canonicaliser |
| `bin/` | ready-to-run primary build (`mono Group3r.exe …`), incl. the 3 stub DLLs |
| `bin-sidfallback/` | same plus `libadvapi32shim.so` + `LibSnaffle.dll.config` |
| `build/Group3r/`, `build/LibSnaffle/` | the net48 SDK-style project files (compile upstream `.cs` in place) |
| `build/stubs/` | sources of the 3 stub framework assemblies |
| `build/advapi32shim/advapi32_shim.c` | source of the SID-fallback shim |
| `build/net8-crosscheck/` | the .NET 8 cross-check projects + their 2 shims |

---

## 6. Summary: what this reference does and does not validate

**Covered (real upstream code, no stubs in the path):** SYSVOL enumeration and GPO
discovery; `GPT.INI` / `.inf` / `.ini` / `.xml` / `.aas` file dispatch
(`GpoFileFactory`); `InfGpoFile` (GptTmpl.inf: privilege rights, system access,
Kerberos policy, registry values, event audit, group membership, file security);
`XmlGpoFile` (all Group Policy Preferences: Drives, Groups, Files, Folders,
Shortcuts, Services, ScheduledTasks incl. the V2 parser, Registry, EnvironmentVariables,
IniFiles, DataSources, Devices, NetworkShares, Printers); GPP `cpassword`
decryption for non-empty values; `scripts.ini`; the SDDL parser and
`SddlAnalyser`; all 25 analysers; triage/severity assignment and the
`-a`/`-w`/`-e`/`-r` filters; and the `NiceGpoPrinter` table layout, wrapping and
finding rendering.

**NOT covered — do not treat a difference here as a port bug:**

1. **Everything in online/LDAP/AD mode** — stubbed away (§2.1).
2. **All `Registry.pol` / Administrative Template settings** — upstream `\`-path bug (§3.1).
3. **Local filesystem ACL analysis**, and the 4 script settings it takes down with it (§3.2).
4. **SID → account-name resolution** via `LookupAccountSid`; and, in
   `original_nice.txt` only, Group3r's own well-known-SID table too — use
   `original_nice_sidfallback.txt` for that (§3.3).
5. **JSON output** — does not exist upstream (§3.5).
6. The 2 mono-only `Bad PKCS7 padding` `[Error]` lines are noise; they cost no
   output (§3.4).
