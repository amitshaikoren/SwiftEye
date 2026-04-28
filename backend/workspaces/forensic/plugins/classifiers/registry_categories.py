r"""
Registry key category catalog.

Maps key path prefixes (case-insensitive) to a category label.
Checked in order — first match wins.

Usage:
    from workspaces.forensic.plugins.classifiers.registry_categories import lookup_registry_category
    entry = lookup_registry_category(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\foo")
"""

# (key_path_fragment_lower, category, color)
_REGISTRY_RULES = [
    # ── Autostart (Run keys) ─────────────────────────────────────────────────
    (r"software\microsoft\windows\currentversion\run",       "Autostart",         "#ef5350"),
    (r"software\wow6432node\microsoft\windows\currentversion\run", "Autostart",   "#ef5350"),
    (r"software\microsoft\windows nt\currentversion\winlogon", "Winlogon hook",   "#ef5350"),
    (r"system\currentcontrolset\control\session manager\bootexecute", "Boot execute", "#ef5350"),

    # ── Scheduled tasks (registry-based) ────────────────────────────────────
    (r"software\microsoft\windows nt\currentversion\schedule", "Scheduled task",  "#ff7043"),

    # ── Services ─────────────────────────────────────────────────────────────
    (r"system\currentcontrolset\services",                   "Service",           "#ffb74d"),

    # ── Image File Execution Options (IFEO) ──────────────────────────────────
    (r"software\microsoft\windows nt\currentversion\image file execution options", "IFEO", "#ff8a65"),

    # ── AppInit DLLs ─────────────────────────────────────────────────────────
    (r"software\microsoft\windows nt\currentversion\windows\appinit_dlls", "AppInit DLL", "#ef5350"),

    # ── COM / ActiveX ────────────────────────────────────────────────────────
    (r"software\classes\clsid",                              "COM object",        "#ce93d8"),
    (r"software\classes",                                    "File association",  "#b39ddb"),

    # ── Security / policies ──────────────────────────────────────────────────
    (r"software\policies",                                   "Group policy",      "#81d4fa"),
    (r"software\microsoft\windows\currentversion\policies",  "Local policy",      "#81d4fa"),

    # ── Network ──────────────────────────────────────────────────────────────
    (r"system\currentcontrolset\control\network",            "Network config",    "#4fc3f7"),
    (r"system\currentcontrolset\services\tcpip",             "TCP/IP config",     "#4fc3f7"),

    # ── User settings (broad fallback) ───────────────────────────────────────
    (r"software\microsoft",                                  "Microsoft software","#a5d6a7"),
    (r"software",                                            "Software settings", "#8bc34a"),
    (r"system",                                              "System config",     "#78909c"),
]


def lookup_registry_category(key_path: str) -> dict | None:
    """Return {category, color} for a registry key path, or None if unclassified."""
    lower = key_path.lower().replace("/", "\\")
    # Strip hive prefix (HKLM, HKCU, HKEY_LOCAL_MACHINE, etc.)
    for hive in ("hkey_local_machine\\", "hkey_current_user\\", "hkey_users\\",
                 "hkey_classes_root\\", "hkey_current_config\\",
                 "hklm\\", "hkcu\\", "hku\\", "hkcr\\"):
        if lower.startswith(hive):
            lower = lower[len(hive):]
            break
    for fragment, category, color in _REGISTRY_RULES:
        if lower.startswith(fragment):
            return {"category": category, "color": color}
    return None
