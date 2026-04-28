"""
LOLbin classifier — forensic insight plugin.

For each process node, checks whether the image basename is a known
Living-off-the-Land Binary and surfaces the category + label in the
node detail panel.
"""

import os
from typing import Any, Dict

from workspaces.forensic.plugins import ForensicPluginBase, ForensicAnalysisContext, UISlot, display_rows, display_tags, register_forensic_plugin
from workspaces.forensic.plugins.classifiers.lolbins import lookup_lolbin

_CATEGORY_COLOR = {
    "Scripting host":    "#f48fb1",
    "Code loader":       "#ffb74d",
    "Download tool":     "#4fc3f7",
    "Recon / admin":     "#ce93d8",
    "Persistence":       "#ef5350",
    "Shell":             "#a5d6a7",
    "Execution proxy":   "#ff8a65",
    "Credential access": "#ff1744",
}
_DEFAULT_COLOR = "#8b949e"


class LOLbinClassifier(ForensicPluginBase):
    name = "lolbin_classifier"
    description = "Identify Living-off-the-Land Binaries in process nodes"
    version = "0.1.0"

    def get_ui_slots(self):
        return [
            UISlot(
                slot_type="node_detail_section",
                slot_id="lolbin",
                title="LOLbin",
                priority=5,
                default_open=True,
            )
        ]

    def analyze_global(self, ctx: ForensicAnalysisContext) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        for node in ctx.nodes:
            if node.get("type") != "process":
                continue
            image = node.get("image") or ""
            basename = os.path.basename(image).lower()
            entry = lookup_lolbin(basename)
            if not entry:
                continue
            category = entry["category"]
            color = _CATEGORY_COLOR.get(category, _DEFAULT_COLOR)
            results[node["id"]] = {
                "label": entry["label"],
                "category": category,
                "_display": [
                    *display_rows({"Binary": entry["label"], "Category": category}),
                    display_tags([(category, color)]),
                ],
            }
        return results


register_forensic_plugin(LOLbinClassifier())
