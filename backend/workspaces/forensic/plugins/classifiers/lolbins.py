"""
LOLbin (Living off the Land Binary) catalog.

Maps lowercase binary basename -> classification metadata.
Source: LOLBAS project (lolbas-project.github.io), curated for Sysmon relevance.

Usage:
    from workspaces.forensic.plugins.classifiers.lolbins import lookup_lolbin
    entry = lookup_lolbin("powershell.exe")  # returns dict or None
"""

# binary basename (lowercase) -> {category, description}
_LOLBINS: dict = {
    # ── Scripting hosts ──────────────────────────────────────────────────────
    "powershell.exe":   {"category": "Scripting host",  "label": "PowerShell"},
    "powershell_ise.exe": {"category": "Scripting host","label": "PowerShell ISE"},
    "wscript.exe":      {"category": "Scripting host",  "label": "Windows Script Host (GUI)"},
    "cscript.exe":      {"category": "Scripting host",  "label": "Windows Script Host (console)"},
    "mshta.exe":        {"category": "Scripting host",  "label": "Microsoft HTML Application Host"},

    # ── DLL / code loaders ───────────────────────────────────────────────────
    "rundll32.exe":     {"category": "Code loader",     "label": "Run DLL as App"},
    "regsvr32.exe":     {"category": "Code loader",     "label": "COM Server Registration"},
    "regasm.exe":       {"category": "Code loader",     "label": ".NET Assembly Registration"},
    "regsvcs.exe":      {"category": "Code loader",     "label": ".NET COM+ Registration"},
    "installutil.exe":  {"category": "Code loader",     "label": ".NET Install Utility"},
    "msiexec.exe":      {"category": "Code loader",     "label": "Windows Installer"},
    "odbcconf.exe":     {"category": "Code loader",     "label": "ODBC Configuration"},

    # ── Download / transfer ──────────────────────────────────────────────────
    "certutil.exe":     {"category": "Download tool",   "label": "Certificate Utility"},
    "bitsadmin.exe":    {"category": "Download tool",   "label": "BITS Admin"},
    "expand.exe":       {"category": "Download tool",   "label": "Cabinet File Expander"},
    "esentutl.exe":     {"category": "Download tool",   "label": "Extensible Storage Engine Utility"},

    # ── Recon / enumeration ──────────────────────────────────────────────────
    "wmic.exe":         {"category": "Recon / admin",   "label": "WMI Command-line"},
    "whoami.exe":       {"category": "Recon / admin",   "label": "Current User Query"},
    "systeminfo.exe":   {"category": "Recon / admin",   "label": "System Information"},
    "ipconfig.exe":     {"category": "Recon / admin",   "label": "IP Configuration"},
    "net.exe":          {"category": "Recon / admin",   "label": "Net Command"},
    "net1.exe":         {"category": "Recon / admin",   "label": "Net Command (legacy)"},
    "nltest.exe":       {"category": "Recon / admin",   "label": "Network Location Test"},
    "dsquery.exe":      {"category": "Recon / admin",   "label": "Active Directory Query"},
    "quser.exe":        {"category": "Recon / admin",   "label": "Query User Sessions"},
    "tasklist.exe":     {"category": "Recon / admin",   "label": "Task List"},
    "netstat.exe":      {"category": "Recon / admin",   "label": "Network Statistics"},

    # ── Persistence / scheduling ─────────────────────────────────────────────
    "schtasks.exe":     {"category": "Persistence",     "label": "Task Scheduler"},
    "at.exe":           {"category": "Persistence",     "label": "AT Job Scheduler (legacy)"},
    "sc.exe":           {"category": "Persistence",     "label": "Service Control"},
    "reg.exe":          {"category": "Persistence",     "label": "Registry Command-line"},

    # ── Execution / proxy ────────────────────────────────────────────────────
    "cmd.exe":          {"category": "Shell",           "label": "Windows Command Shell"},
    "forfiles.exe":     {"category": "Execution proxy", "label": "ForFiles"},
    "pcalua.exe":       {"category": "Execution proxy", "label": "Program Compatibility Assistant"},
    "syncappvpublishingserver.exe": {"category": "Execution proxy", "label": "App-V Publishing Server"},
    "appsyncpublishingserver.exe":  {"category": "Execution proxy", "label": "App-V Publishing (alt)"},

    # ── Credential access ────────────────────────────────────────────────────
    "ntdsutil.exe":     {"category": "Credential access", "label": "NTDS Utility"},
    "procdump.exe":     {"category": "Credential access", "label": "Process Dump (Sysinternals)"},
    "mimikatz.exe":     {"category": "Credential access", "label": "Mimikatz"},
}


def lookup_lolbin(image_basename: str) -> dict | None:
    """Return LOLbin entry for a binary basename, or None if not in catalog."""
    return _LOLBINS.get(image_basename.lower())
