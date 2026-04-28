"""
Binary type classifier — forensic insight plugin.

Classifies a process node's image path into a broad type bucket based on
path prefix and extension. Applies to all process nodes, not just LOLbins.
"""

import os
from typing import Any, Dict

from workspaces.forensic.plugins import ForensicPluginBase, ForensicAnalysisContext, UISlot, display_rows, display_tags, register_forensic_plugin

# (path_fragment_lower, type_label, color)
# Checked in order — first match wins.
_PATH_RULES = [
    # System directories
    ("\\windows\\system32\\",   "System process",   "#4fc3f7"),
    ("\\windows\\syswow64\\",   "System process",   "#4fc3f7"),
    ("\\windows\\sysnative\\",  "System process",   "#4fc3f7"),
    ("\\windows\\",             "Windows component","#81d4fa"),
    # Package managers / app stores
    ("\\windowsapps\\",         "Store app",        "#b39ddb"),
    # Common install roots
    ("\\program files (x86)\\", "Installed app",    "#a5d6a7"),
    ("\\program files\\",       "Installed app",    "#a5d6a7"),
    # User-space directories (higher suspicion for executables)
    ("\\appdata\\roaming\\",    "User AppData",     "#ffb74d"),
    ("\\appdata\\local\\",      "User AppData",     "#ffb74d"),
    ("\\users\\",               "User directory",   "#ff8a65"),
    # Temp
    ("\\temp\\",                "Temp directory",   "#ef5350"),
    ("\\tmp\\",                 "Temp directory",   "#ef5350"),
]

_EXT_RULES = [
    (".ps1",   "PowerShell script", "#f48fb1"),
    (".psm1",  "PowerShell module", "#f48fb1"),
    (".psd1",  "PowerShell data",   "#f48fb1"),
    (".vbs",   "VBScript",          "#ffb74d"),
    (".js",    "JScript",           "#ffb74d"),
    (".wsf",   "Windows Script",    "#ffb74d"),
    (".hta",   "HTML Application",  "#ff8a65"),
    (".bat",   "Batch script",      "#a5d6a7"),
    (".cmd",   "Batch script",      "#a5d6a7"),
    (".dll",   "DLL",               "#ce93d8"),
]


def _classify(image: str) -> tuple[str, str] | tuple[None, None]:
    """Return (type_label, color) or (None, None) if unclassified."""
    lower = image.lower()

    # Extension check first (scripts are identified by extension regardless of path)
    ext = os.path.splitext(lower)[1]
    for e, label, color in _EXT_RULES:
        if ext == e:
            return label, color

    # Path prefix check
    for fragment, label, color in _PATH_RULES:
        if fragment in lower:
            return label, color

    return None, None


class BinaryTypeClassifier(ForensicPluginBase):
    name = "binary_type"
    description = "Classify process image path into a broad type bucket"
    version = "0.1.0"

    def get_ui_slots(self):
        return [
            UISlot(
                slot_type="node_detail_section",
                slot_id="binary_type",
                title="Binary Type",
                priority=10,
                default_open=True,
            )
        ]

    def analyze_global(self, ctx: ForensicAnalysisContext) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        for node in ctx.nodes:
            if node.get("type") != "process":
                continue
            image = node.get("image") or ""
            if not image:
                continue
            label, color = _classify(image)
            if label is None:
                continue
            results[node["id"]] = {
                "type": label,
                "_display": [
                    *display_rows({"Type": label}),
                    display_tags([(label, color)]),
                ],
            }
        return results


register_forensic_plugin(BinaryTypeClassifier())
