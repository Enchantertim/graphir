"""Known-good allowlist — noise suppression for frequency/location hunts.

A small curated set of common Windows (and ubiquitous OEM) executable basenames
that legitimately appear on nearly every host and flood anomaly-by-frequency
(rare_processes) and anomaly-by-location (unusual_executables) hunts.

HONESTY: this is a NAME-based allowlist, not a cryptographic NSRL hash match.
The graph's Executable nodes rarely carry a sha1 (shimcache/amcache don't record
one), so a hash baseline isn't possible from this evidence. A name match reduces
noise; it does NOT prove a binary is benign — a malicious file named svchost.exe
still matches. Hunts therefore use this only to DEMOTE, never to exclude from the
graph, and timestomping / temporal-anomaly / known-malware hunts deliberately do
NOT apply it (a known-good name born on the incident date is still suspicious).
"""

# Lowercased basenames. Kept intentionally small and high-confidence — common
# OS binaries + a few near-universal OEM/agent binaries seen across enterprises.
KNOWN_GOOD_NAMES = frozenset({
    # core OS / session
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "smss.exe", "explorer.exe", "taskhost.exe", "taskhostw.exe",
    "dwm.exe", "conhost.exe", "spoolsv.exe", "lsm.exe", "userinit.exe",
    "dllhost.exe", "rundll32.exe", "regsvr32.exe", "consent.exe", "logonui.exe",
    # servicing / update / search / defrag
    "wuauclt.exe", "trustedinstaller.exe", "tiworker.exe", "wmiprvse.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "defrag.exe", "mscorsvw.exe", "ngen.exe", "wsqmcons.exe", "sppsvc.exe",
    "slui.exe", "wercon.exe", "werfault.exe", "dwwin.exe", "mobsync.exe",
    # shell / management / common admin
    "cmd.exe", "conime.exe", "mmc.exe", "taskmgr.exe", "control.exe",
    "msiexec.exe", "verclsid.exe", "ctfmon.exe", "sdclt.exe", "vssvc.exe",
    "audiodg.exe", "wlanext.exe", "sihost.exe", "runtimebroker.exe",
    # OEM / virtualization / AV agents (near-universal in enterprise images)
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmupgradehelper.exe",
    "vmacthlp.exe", "tpautoconnect.exe", "tpautoconnsvc.exe",
})


def _cypher_list(names) -> str:
    """Render a frozenset as a Cypher string-list literal."""
    return "[" + ", ".join(f"'{n}'" for n in sorted(names)) + "]"


def not_known_good(name_expr: str) -> str:
    """Cypher predicate fragment: <name_expr> is NOT a known-good basename.

    name_expr should already yield a basename (e.g. p.name). Comparison is
    case-insensitive.
    """
    return f"NOT toLower({name_expr}) IN {_cypher_list(KNOWN_GOOD_NAMES)}"
