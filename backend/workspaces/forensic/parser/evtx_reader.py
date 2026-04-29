"""
Raw EVTX record reader.

Mirrors `workspaces/network/parser/dpkt_reader.py`: format-specific I/O
only, no dissection. Reads a Windows .evtx file and yields one
`RawRecord` dict per event, where each dict carries:

  - eid:         EventID as int
  - record_id:   EventRecordID as int (stable per-file)
  - time_created: datetime (from System/TimeCreated@SystemTime, UTC)
  - computer:    hostname from System/Computer
  - provider:    provider name (e.g. "Microsoft-Windows-Sysmon")
  - event_data:  {DataName: DataValue} dict from EventData/<Data Name="...">

Dissectors (one per EID) consume `RawRecord` and produce normalized `Event`.
The adapter glues them together.

Runnable as a CLI for smoke-testing:

    py backend/workspaces/forensic/parser/evtx_reader.py <path.evtx>

prints one line per record summarising EID + provider + UTC time.
"""

from __future__ import annotations

import logging
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

try:
    import Evtx.Evtx as _evtx  # provided by the `python-evtx` package
except ImportError:  # pragma: no cover — exercised only if the dep is missing
    _evtx = None

logger = logging.getLogger("swifteye.forensic.parser.evtx")

# Windows event XML namespace — all EVTX records use this.
_EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


RawRecord = Dict[str, Any]


def read_evtx(filepath: str, max_records: int = 5_000_000) -> List[RawRecord]:
    """Read an .evtx file and return a list of raw record dicts.

    In-memory list (not a generator) to match the pcap reader's shape for
    now. If this becomes a memory problem on large Sysmon logs, switch to a
    generator and adjust the adapter + dispatch accordingly.
    """
    if _evtx is None:
        raise RuntimeError(
            "python-evtx is not installed. `py -m pip install python-evtx`."
        )

    path = Path(filepath)
    records: List[RawRecord] = []
    start = time.time()
    skipped = 0

    with _evtx.Evtx(str(path)) as log:
        for raw in log.records():
            if len(records) >= max_records:
                logger.warning("evtx_reader: reached record limit (%d)", max_records)
                break
            parsed = _parse_record_xml(raw.xml())
            if parsed is None:
                skipped += 1
                continue
            records.append(parsed)

    elapsed = time.time() - start
    logger.info(
        "evtx_reader: parsed %d records (skipped %d malformed) from %s in %.2fs",
        len(records), skipped, path.name, elapsed,
    )
    return records


def _parse_record_xml(xml_str: str) -> Optional[RawRecord]:
    """Parse one EVTX record XML string into a RawRecord dict.

    Returns None for records that can't be parsed — individual bad records
    must not kill the whole read. `python-evtx` has been observed to emit
    malformed XML for some truncated chunks.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("e:System", _EVENT_NS)
    if system is None:
        return None

    eid_el = system.find("e:EventID", _EVENT_NS)
    if eid_el is None or not (eid_el.text or "").strip():
        return None
    try:
        eid = int(eid_el.text)
    except (TypeError, ValueError):
        return None

    rec: RawRecord = {
        "eid": eid,
        "record_id": _intish(system.find("e:EventRecordID", _EVENT_NS)),
        "time_created": _time_created(system),
        "computer": _text(system.find("e:Computer", _EVENT_NS)),
        "provider": _provider_name(system),
        "event_data": _event_data(root),
    }
    return rec


def _event_data(root: ET.Element) -> Dict[str, str]:
    """Flatten <EventData><Data Name="X">Y</Data>...</EventData> to {X: Y}."""
    out: Dict[str, str] = {}
    data_el = root.find("e:EventData", _EVENT_NS)
    if data_el is None:
        return out
    for data in data_el.findall("e:Data", _EVENT_NS):
        name = data.attrib.get("Name") or ""
        if not name:
            continue
        out[name] = data.text or ""
    return out


def _time_created(system: ET.Element) -> Optional[datetime]:
    """Pull SystemTime attr off <TimeCreated SystemTime="..."/>."""
    tc = system.find("e:TimeCreated", _EVENT_NS)
    if tc is None:
        return None
    val = tc.attrib.get("SystemTime") or ""
    return _parse_dt(val)


def _provider_name(system: ET.Element) -> str:
    prov = system.find("e:Provider", _EVENT_NS)
    if prov is None:
        return ""
    return prov.attrib.get("Name") or ""


def _text(el: Optional[ET.Element]) -> str:
    if el is None or el.text is None:
        return ""
    return el.text


def _intish(el: Optional[ET.Element]) -> Optional[int]:
    if el is None or not (el.text or "").strip():
        return None
    try:
        return int(el.text)
    except (TypeError, ValueError):
        return None


def _parse_dt(value: str) -> Optional[datetime]:
    """Parse an EVTX TimeCreated/SystemTime string to a datetime.

    python-evtx tends to emit values like "2019-05-14 01:29:04.306887+00:00"
    which fromisoformat accepts directly on Python 3.7+. Fall back to
    stripping a trailing Z if present.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass
    if value.endswith("Z"):
        try:
            return datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            return None
    return None


def _smoke(path: str) -> int:
    """Print a one-line summary per record. Used only from __main__."""
    records = read_evtx(path)
    print(f"read {len(records)} records from {path}")
    from collections import Counter
    counts = Counter(r["eid"] for r in records)
    print(f"EID distribution: {dict(sorted(counts.items()))}")
    for rec in records[:20]:
        print(
            f"  eid={rec['eid']:<4} "
            f"recid={rec['record_id']} "
            f"ts={rec['time_created']} "
            f"provider={rec['provider']} "
            f"data_keys={sorted(rec['event_data'].keys())[:6]}"
        )
    return 0 if records else 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    if len(sys.argv) != 2:
        print("usage: evtx_reader.py <file.evtx>", file=sys.stderr)
        sys.exit(2)
    sys.exit(_smoke(sys.argv[1]))
