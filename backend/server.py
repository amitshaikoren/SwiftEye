"""
SwiftEye Backend Server

FastAPI app factory. Registers routers, middleware, logging, plugins, and
serves the frontend SPA.

Usage:
    python server.py
    # Then open http://localhost:8642
"""

import os
import sys
import time
import signal
import atexit
import logging
import importlib
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Ensure backend/ is on sys.path so imports work regardless of CWD
_backend_dir = Path(__file__).resolve().parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from workspaces.network.plugins import register_plugin
from workspaces.network.plugins.analyses import register_analysis
from workspaces.network.plugins.alerts import register_detector
from workspaces.network.research import register_chart

from routes.data import router as data_router
from routes.query import router as query_router
from routes.plugins import router as plugins_router
from routes.investigation import router as investigation_router
from routes.research import router as research_router
from routes.animation import router as animation_router
from routes.alerts import router as alerts_router
from routes.utility import router as utility_router, setup_log_handler, _log_buffer
from routes.schema import router as schema_router
from routes.llm import router as llm_router


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("swifteye")

_log_file = Path(__file__).parent / "swifteye.log"
_rfh = RotatingFileHandler(_log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
_rfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
_rfh.setLevel(logging.INFO)
logging.getLogger("swifteye").addHandler(_rfh)
logging.getLogger("uvicorn.error").addHandler(_rfh)

setup_log_handler()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SwiftEye",
    description="Network Traffic Visualization Platform",
    version="0.15.6",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Dynamic registration helper ───────────────────────────────────────────────

def _dynamic_register(specs, register_fn, label="component"):
    """Load modules dynamically and register instances. Failures log a warning and are skipped."""
    for module_path, class_name in specs:
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            register_fn(cls())
        except Exception as e:
            logger.warning(f"Could not load {label} {module_path}.{class_name}: {e}")


# ── Register plugins, analyses, charts ───────────────────────────────────────

_dynamic_register([
    ("workspaces.network.plugins.insights.os_fingerprint", "OSFingerprintPlugin"),
    ("workspaces.network.plugins.insights.network_map",    "NetworkMapPlugin"),
    ("workspaces.network.plugins.insights.tcp_flags",      "TCPFlagsPlugin"),
    ("workspaces.network.plugins.insights.dns_resolver",   "DNSResolverPlugin"),
], register_plugin, "insight plugin")

_dynamic_register([
    ("workspaces.network.plugins.analyses.node_centrality",           "NodeCentralityAnalysis"),
    ("workspaces.network.plugins.analyses.traffic_characterisation",   "TrafficCharacterisationAnalysis"),
], register_analysis, "analysis plugin")

_dynamic_register([
    ("workspaces.network.research.conversation_timeline", "ConversationTimeline"),
    ("workspaces.network.research.ttl_over_time",         "TTLOverTime"),
    ("workspaces.network.research.session_gantt",         "SessionGantt"),
    ("workspaces.network.research.seq_ack_timeline",      "SeqAckTimelineChart"),
    ("workspaces.network.research.dns_timeline",          "DNSTimeline"),
    ("workspaces.network.research.ja3_timeline",          "JA3Timeline"),
    ("workspaces.network.research.ja4_timeline",          "JA4Timeline"),
    ("workspaces.network.research.http_ua_timeline",       "HTTPUserAgentTimeline"),
], register_chart, "research chart")

_dynamic_register([
    ("workspaces.network.plugins.alerts.arp_spoofing",  "ArpSpoofingDetector"),
    ("workspaces.network.plugins.alerts.suspicious_ua", "SuspiciousUADetector"),
    ("workspaces.network.plugins.alerts.malicious_ja3", "MaliciousJA3Detector"),
    ("workspaces.network.plugins.alerts.port_scan",     "PortScanDetector"),
], register_detector, "alert detector")


# ── Mount routers ─────────────────────────────────────────────────────────────

app.include_router(data_router)
app.include_router(query_router)
app.include_router(plugins_router)
app.include_router(investigation_router)
app.include_router(research_router)
app.include_router(animation_router)
app.include_router(alerts_router)
app.include_router(utility_router)
app.include_router(schema_router)
app.include_router(llm_router)


# ── Frontend ──────────────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
VITE_DIST    = FRONTEND_DIR / "dist"
LEGACY_INDEX = FRONTEND_DIR / "index-legacy.html"


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the frontend SPA (Vite build or legacy single-file)."""
    vite_index = VITE_DIST / "index.html"
    if vite_index.exists():
        return HTMLResponse(content=vite_index.read_text(encoding="utf-8"))
    if LEGACY_INDEX.exists():
        return HTMLResponse(content=LEGACY_INDEX.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SwiftEye</h1><p>Frontend not found. Run 'npm run build' in frontend/ or place index.html there.</p>")


if VITE_DIST.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/assets", StaticFiles(directory=str(VITE_DIST / "assets")), name="vite-assets")
    if (VITE_DIST / "fonts").exists():
        app.mount("/fonts", StaticFiles(directory=str(VITE_DIST / "fonts")), name="vite-fonts")


# ── Shutdown ──────────────────────────────────────────────────────────────────

LOG_FILE = _log_file


def _save_crash_log():
    """Save buffered logs to file on shutdown."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"SwiftEye shutdown at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*60}\n")
            for line in _log_buffer[-100:]:
                f.write(line + "\n")
        print(f"\nLogs saved to {LOG_FILE}")
    except Exception as e:
        print(f"Could not save logs: {e}")


if __name__ == "__main__":
    atexit.register(_save_crash_log)

    def _handle_signal(sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        _save_crash_log()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    port = int(os.environ.get("SWIFTEYE_PORT", 8642))
    logger.info(f"Starting SwiftEye on http://localhost:{port}")
    logger.info(f"Log file: {LOG_FILE}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
