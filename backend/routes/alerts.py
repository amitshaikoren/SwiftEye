"""
Alert endpoints — serves detector findings for the AlertsPanel.
"""

from fastapi import APIRouter
from workspaces.network.store import store, _require_capture

router = APIRouter()


def _build_summary(alerts):
    return {
        "high":   sum(1 for a in alerts if a["severity"] == "high"),
        "medium": sum(1 for a in alerts if a["severity"] == "medium"),
        "low":    sum(1 for a in alerts if a["severity"] == "low"),
        "info":   sum(1 for a in alerts if a["severity"] == "info"),
        "total":  len(alerts),
    }


@router.get("/api/alerts")
async def get_alerts():
    # Allow alerts even without capture (demo mode populates store.alerts directly)
    if not store.is_loaded and not store.alerts:
        _require_capture()  # raises 404
    return {"alerts": store.alerts, "summary": _build_summary(store.alerts)}


