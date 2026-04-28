"""
Registry key category classifier — forensic insight plugin.

For each registry node, classifies the key path into a named category
(Autostart, Service, IFEO, COM object, etc.) and surfaces it in the
node detail panel.
"""

from typing import Any, Dict

from workspaces.forensic.plugins import ForensicPluginBase, ForensicAnalysisContext, UISlot, display_rows, display_tags, register_forensic_plugin
from workspaces.forensic.plugins.classifiers.registry_categories import lookup_registry_category


class RegistryKeyCategoryClassifier(ForensicPluginBase):
    name = "registry_key_category"
    description = "Classify registry key paths into functional categories"
    version = "0.1.0"

    def get_ui_slots(self):
        return [
            UISlot(
                slot_type="node_detail_section",
                slot_id="registry_key_category",
                title="Key Category",
                priority=5,
                default_open=True,
            )
        ]

    def analyze_global(self, ctx: ForensicAnalysisContext) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        for node in ctx.nodes:
            if node.get("type") != "registry":
                continue
            key = node.get("key") or ""
            if not key:
                continue
            entry = lookup_registry_category(key)
            if not entry:
                continue
            results[node["id"]] = {
                "category": entry["category"],
                "_display": [
                    *display_rows({"Category": entry["category"]}),
                    display_tags([(entry["category"], entry["color"])]),
                ],
            }
        return results


register_forensic_plugin(RegistryKeyCategoryClassifier())
