import os
import io
import re
import uuid
import base64
import datetime
import logging
import tempfile

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import FileResponse

from store import store, _require_capture

logger = logging.getLogger("swifteye.routes.investigation")
router = APIRouter()


# ── Investigation notebook ────────────────────────────────────────────────────

@router.get("/api/investigation")
async def get_investigation():
    """Get investigation notebook content."""
    _require_capture()
    return store.investigation


@router.put("/api/investigation")
async def update_investigation(body: dict):
    """Update investigation notebook. Body: { markdown: str }"""
    _require_capture()
    if "markdown" in body:
        store.investigation["markdown"] = body["markdown"]
    return store.investigation


@router.post("/api/investigation/image")
async def upload_investigation_image(file: UploadFile = File(...)):
    """Upload an image for the investigation notebook. Returns an image ID for embedding."""
    _require_capture()
    content = await file.read()
    img_id = f"img_{uuid.uuid4().hex[:8]}"
    media_type = file.content_type or "image/png"
    b64 = base64.b64encode(content).decode()
    store.investigation["images"][img_id] = f"data:{media_type};base64,{b64}"
    return {"id": img_id, "url": store.investigation["images"][img_id]}


@router.get("/api/investigation/image/{img_id}")
async def get_investigation_image(img_id: str):
    """Get a specific investigation image by ID."""
    _require_capture()
    url = store.investigation.get("images", {}).get(img_id)
    if not url:
        raise HTTPException(404, "Image not found")
    return {"id": img_id, "url": url}


@router.post("/api/investigation/export")
async def export_investigation_pdf():
    """Export the investigation notebook as a PDF."""
    _require_capture()
    md = store.investigation.get("markdown", "")
    images = store.investigation.get("images", {})
    if not md.strip():
        raise HTTPException(400, "Investigation notebook is empty")

    try:
        pdf_path = _generate_investigation_pdf(md, images, store.file_name)
        return FileResponse(pdf_path, media_type="application/pdf",
                          filename=f"investigation_{store.file_name.replace(' ', '_')}.pdf")
    except Exception as e:
        logger.error(f"PDF export failed: {e}", exc_info=True)
        raise HTTPException(500, f"PDF generation failed: {str(e)}")


def _generate_investigation_pdf(markdown: str, images: dict, capture_name: str) -> str:
    """Generate a PDF from markdown and embedded images."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, HRFlowable, Preformatted
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    pdf_path = os.path.join(tempfile.gettempdir(), f"investigation_{uuid.uuid4().hex[:8]}.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                           leftMargin=20*mm, rightMargin=20*mm,
                           topMargin=20*mm, bottomMargin=20*mm)

    styles = {
        'title': ParagraphStyle('title', fontName='Helvetica-Bold', fontSize=18, spaceAfter=6*mm, textColor=HexColor('#1a1a2e')),
        'h1': ParagraphStyle('h1', fontName='Helvetica-Bold', fontSize=14, spaceBefore=5*mm, spaceAfter=3*mm, textColor=HexColor('#0d1117')),
        'h2': ParagraphStyle('h2', fontName='Helvetica-Bold', fontSize=12, spaceBefore=4*mm, spaceAfter=2*mm, textColor=HexColor('#1a1a2e')),
        'h3': ParagraphStyle('h3', fontName='Helvetica-Bold', fontSize=10, spaceBefore=3*mm, spaceAfter=2*mm, textColor=HexColor('#30363d')),
        'body': ParagraphStyle('body', fontName='Helvetica', fontSize=10, leading=14, spaceAfter=2*mm, textColor=HexColor('#1a1a2e')),
        'code': ParagraphStyle('code', fontName='Courier', fontSize=8, leading=10, spaceAfter=2*mm, backColor=HexColor('#f6f8fa'), textColor=HexColor('#24292f'), leftIndent=5*mm, rightIndent=5*mm),
        'bullet': ParagraphStyle('bullet', fontName='Helvetica', fontSize=10, leading=14, spaceAfter=1*mm, leftIndent=8*mm, bulletIndent=3*mm, textColor=HexColor('#1a1a2e')),
        'meta': ParagraphStyle('meta', fontName='Helvetica', fontSize=8, textColor=HexColor('#8b949e'), spaceAfter=4*mm),
    }

    story = []

    story.append(Paragraph("SwiftEye Investigation Report", styles['title']))
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    story.append(Paragraph(f"Capture: {capture_name}  |  Exported: {now}", styles['meta']))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#d0d7de')))
    story.append(Spacer(1, 4*mm))

    lines = markdown.split('\n')
    in_code_block = False
    code_lines = []

    for line in lines:
        if line.strip().startswith('```'):
            if in_code_block:
                code_text = '\n'.join(code_lines)
                story.append(Preformatted(code_text, styles['code']))
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
            continue
        if in_code_block:
            code_lines.append(line)
            continue

        stripped = line.strip()

        if not stripped:
            story.append(Spacer(1, 2*mm))
            continue

        if stripped.startswith('### '):
            story.append(Paragraph(stripped[4:], styles['h3']))
            continue
        if stripped.startswith('## '):
            story.append(Paragraph(stripped[3:], styles['h2']))
            continue
        if stripped.startswith('# '):
            story.append(Paragraph(stripped[2:], styles['h1']))
            continue

        if stripped in ('---', '***', '___'):
            story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#d0d7de')))
            continue

        if stripped.startswith('- ') or stripped.startswith('* '):
            text = _md_inline(stripped[2:])
            story.append(Paragraph(f"&bull; {text}", styles['bullet']))
            continue

        img_match = re.match(r'!\[([^\]]*)\]\(([^)]+)\)', stripped)
        if img_match:
            alt, src = img_match.group(1), img_match.group(2)
            img_data = images.get(src, src)
            if img_data.startswith('data:'):
                try:
                    header, b64data = img_data.split(',', 1)
                    img_bytes = base64.b64decode(b64data)
                    img_buf = io.BytesIO(img_bytes)
                    img = RLImage(img_buf, width=150*mm, height=90*mm, kind='proportional')
                    story.append(img)
                    if alt:
                        story.append(Paragraph(f"<i>{alt}</i>", styles['meta']))
                except Exception:
                    story.append(Paragraph(f"[Image: {alt}]", styles['body']))
            continue

        text = _md_inline(stripped)
        story.append(Paragraph(text, styles['body']))

    doc.build(story)
    return pdf_path


def _md_inline(text: str) -> str:
    """Convert inline markdown (bold, italic, code) to reportlab XML."""
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
    text = re.sub(r'_(.+?)_', r'<i>\1</i>', text)
    text = re.sub(r'`(.+?)`', r'<font face="Courier" size="9">\1</font>', text)
    return text


# ── Synthetic nodes/edges ─────────────────────────────────────────────────────

@router.get("/api/synthetic")
async def get_synthetic():
    """Return all synthetic nodes and edges."""
    _require_capture()
    return {"synthetic": list(store.synthetic.values())}


@router.post("/api/synthetic")
async def create_synthetic(body: dict):
    """
    Create a synthetic node or edge.
    Node body: { id, type:"node", ip, label?, color?, metadata? }
    Edge body: { id, type:"edge", source, target, protocol?, label?, color? }
    """
    _require_capture()
    syn_id = body.get("id")
    syn_type = body.get("type")
    if not syn_id:
        raise HTTPException(400, "id is required")
    if syn_type not in ("node", "edge"):
        raise HTTPException(400, "type must be 'node' or 'edge'")
    if syn_type == "node":
        obj = {
            "id": syn_id,
            "type": "node",
            "synthetic": True,
            "label": str(body.get("label", syn_id)),
            "ip": str(body.get("ip", "")),
            "color": str(body.get("color", "#f0883e")),
            "size": int(body.get("size", 14)),
            "metadata": body.get("metadata", {}),
            "ips": [body.get("ip", syn_id)] if body.get("ip") else [syn_id],
            "macs": [],
            "protocols": [],
            "total_bytes": 0,
            "packet_count": 0,
            "hostnames": [],
            "is_private": False,
            "is_subnet": False,
            "ttls_out": [],
            "ttls_in": [],
            "created_at": datetime.datetime.utcnow().isoformat(),
        }
    else:
        source = body.get("source", "")
        target = body.get("target", "")
        if not source or not target:
            raise HTTPException(400, "source and target are required for edge type")
        obj = {
            "id": syn_id,
            "type": "edge",
            "synthetic": True,
            "source": source,
            "target": target,
            "protocol": str(body.get("protocol", "SYNTHETIC")),
            "label": str(body.get("label", "")),
            "color": str(body.get("color", "#f0883e")),
            "total_bytes": 0,
            "packet_count": 0,
            "ports": [],
            "tls_snis": [],
            "tls_versions": [],
            "tls_ciphers": [],
            "tls_selected_ciphers": [],
            "http_hosts": [],
            "dns_queries": [],
            "ja3_hashes": [],
            "ja4_hashes": [],
            "created_at": datetime.datetime.utcnow().isoformat(),
        }
    store.synthetic[syn_id] = obj
    logger.info(f"Synthetic {syn_type} created: {syn_id!r}")
    return {"synthetic": obj}


@router.put("/api/synthetic/{syn_id}")
async def update_synthetic(syn_id: str, body: dict):
    """Update a synthetic node or edge (label, color, metadata, ip, protocol)."""
    _require_capture()
    if syn_id not in store.synthetic:
        raise HTTPException(404, f"Synthetic '{syn_id}' not found")
    obj = store.synthetic[syn_id]
    for field in ("label", "color", "metadata", "ip", "protocol", "size", "notes"):
        if field in body:
            obj[field] = body[field]
    if obj.get("type") == "node" and "ip" in body and body["ip"]:
        obj["ips"] = [body["ip"]]
    return {"synthetic": obj}


@router.delete("/api/synthetic/{syn_id}")
async def delete_synthetic(syn_id: str):
    """Delete a synthetic node or edge."""
    _require_capture()
    store.synthetic.pop(syn_id, None)
    return {"deleted": syn_id}


@router.delete("/api/synthetic")
async def clear_synthetic():
    """Clear all synthetic elements."""
    _require_capture()
    store.synthetic.clear()
    return {"cleared": True}


# ── Annotations ───────────────────────────────────────────────────────────────

@router.get("/api/annotations")
async def get_annotations():
    """Return all annotations for the current capture."""
    _require_capture()
    return {"annotations": list(store.annotations.values())}


@router.post("/api/annotations")
async def create_annotation(body: dict):
    """Create a new annotation. Body: { id, x, y, label, color? }"""
    _require_capture()
    ann_id = body.get("id")
    if not ann_id:
        raise HTTPException(400, "Annotation id is required")
    annotation = {
        "id":              ann_id,
        "x":               float(body.get("x", 0)),
        "y":               float(body.get("y", 0)),
        "label":           str(body.get("label", "")).strip(),
        "color":           str(body.get("color", "#f0883e")),
        "annotation_type": str(body.get("annotation_type", "label")),
        "text":            str(body.get("text", "")),
        "created_at":      datetime.datetime.utcnow().isoformat(),
    }
    if body.get("node_id"):
        annotation["node_id"] = str(body["node_id"])
    if body.get("edge_id"):
        annotation["edge_id"] = str(body["edge_id"])
    store.annotations[ann_id] = annotation
    logger.info(f"Annotation created: {ann_id!r} — {annotation['label']!r}")
    return {"annotation": annotation}


@router.put("/api/annotations/{ann_id}")
async def update_annotation(ann_id: str, body: dict):
    """Update an existing annotation (label, x, y, color)."""
    _require_capture()
    if ann_id not in store.annotations:
        raise HTTPException(404, f"Annotation '{ann_id}' not found")
    ann = store.annotations[ann_id]
    if "label"           in body: ann["label"]           = str(body["label"]).strip()
    if "text"            in body: ann["text"]            = str(body["text"])
    if "annotation_type" in body: ann["annotation_type"] = str(body["annotation_type"])
    if "x"               in body: ann["x"]               = float(body["x"])
    if "y"               in body: ann["y"]               = float(body["y"])
    if "color"           in body: ann["color"]           = str(body["color"])
    if "node_id"         in body: ann["node_id"]         = str(body["node_id"]) if body["node_id"] else None
    if "edge_id"         in body: ann["edge_id"]         = str(body["edge_id"]) if body["edge_id"] else None
    return {"annotation": ann}


@router.delete("/api/annotations/{ann_id}")
async def delete_annotation(ann_id: str):
    """Delete an annotation by id."""
    _require_capture()
    store.annotations.pop(ann_id, None)
    return {"deleted": ann_id}


@router.delete("/api/annotations")
async def clear_annotations():
    """Clear all annotations."""
    _require_capture()
    store.annotations.clear()
    return {"cleared": True}
