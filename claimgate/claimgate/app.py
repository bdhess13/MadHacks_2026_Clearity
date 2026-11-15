"""Clearity — AI fraud detection for car insurance claim PDFs.

3-stage inspection pipeline:
  Stage 1  Structural PDF forensics (pymupdf): white-on-white text, micro text,
           off-page text, hidden Unicode Tag blocks / zero-width joiners.
  Stage 2  Image audit: AI-generation hints in metadata + optional Gemini vision check.
  Stage 3  Combined risk score and verdict: APPROVED (green) / SUSPICIOUS (orange) / BLOCKED (red).
"""
import base64
import io
import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional

import fitz  # PyMuPDF
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image

app = FastAPI(title="Clearity", version="1.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# ---------------------------------------------------------------- Stage 1

# Unicode ranges that are invisible in normal rendering. The Tag block
# (U+E0000-U+E007F) is the classic vector for hiding AI prompt injections
# inside a PDF that a downstream AI summarizer will read but a human won't see.
HIDDEN_CHAR_RANGES = (
    (0xE0000, 0xE007F),  # Unicode Tag block (hidden AI prompting)
    (0x200B, 0x200F),   # zero-width space / joiners
    (0x2060, 0x2064),   # word joiner & invisible operators
    (0xFEFF, 0xFEFF),   # zero-width no-break space (BOM)
    (0xFFF9, 0xFFFB),   # interlinear annotation marks
)

WEIGHTS = {
    "hidden_unicode": 6,
    "white_on_white": 5,
    "micro_text": 4,
    "off_page": 3,
    "ai_generated_image": 6,
    "suspicious_image": 2,
}


def is_hidden_char(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in HIDDEN_CHAR_RANGES)


def srgb_to_rgb(color: int) -> tuple:
    return ((color >> 16) & 255, (color >> 8) & 255, color & 255)


def near_white(rgb: tuple, tol: int = 12) -> bool:
    return all(c >= 255 - tol for c in rgb)


def has_visible_backing(page, bbox) -> bool:
    """True if a dark filled shape sits behind the span, i.e. white text is
    intentionally placed on a colored background and is visible to the reader."""
    try:
        target = fitz.Rect(bbox)
        for d in page.get_drawings():
            fill = d.get("fill")
            if fill is None:
                continue
            rgb = tuple(int(c * 255) for c in fill)
            if near_white(rgb):
                continue
            r = d.get("rect")
            if r and fitz.Rect(r).contains(target):
                return True
    except Exception:
        pass
    return False


def preview_with_markers(text: str) -> str:
    """Render hidden characters as visible red tokens like [U+E0041]."""
    out = []
    for ch in text[:160]:
        if is_hidden_char(ch):
            out.append("\u3010U+%04X\u3011" % ord(ch))
        elif ch == "\n":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def stage1_forensics(doc) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    sanitized_pages: List[str] = []
    span_count = 0

    for pno, page in enumerate(doc, start=1):
        page_rect = page.rect
        padded = fitz.Rect(page_rect.x0 - 2, page_rect.y0 - 2,
                           page_rect.x1 + 2, page_rect.y1 + 2)
        page_lines: List[str] = []

        try:
            blocks = page.get_text("dict")["blocks"]
        except Exception:
            blocks = []

        for block in blocks:
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                line_parts: List[str] = []
                for span in line.get("spans", []):
                    text = span.get("text", "")
                    if not text.strip():
                        continue
                    span_count += 1
                    size = span.get("size", 0.0) or 0.0
                    bbox = span.get("bbox", (0, 0, 0, 0))
                    rgb = srgb_to_rgb(span.get("color", 0))
                    hidden = False

                    hidden_chars = [ch for ch in text if is_hidden_char(ch)]
                    if hidden_chars:
                        hidden = True
                        findings.append({
                            "type": "hidden_unicode",
                            "page": pno,
                            "label": "Hidden Unicode characters",
                            "severity": "critical",
                            "detail": ", ".join("U+%04X" % ord(c) for c in hidden_chars[:8]),
                            "preview": preview_with_markers(text),
                            "reason": ("Invisible Unicode (Tag block / zero-width joiners) "
                                       "\u2014 a common vector for hidden AI prompt injection."),
                        })

                    if near_white(rgb) and not has_visible_backing(page, bbox):
                        hidden = True
                        findings.append({
                            "type": "white_on_white",
                            "page": pno,
                            "label": "White-on-white text",
                            "severity": "critical",
                            "detail": "font color #%02X%02X%02X on white page background" % rgb,
                            "preview": text.strip()[:160] or "(whitespace only)",
                            "reason": "Text is invisible to a human reader but fully "
                                      "readable by automated systems and AI models.",
                        })

                    if 0 < size < 1.0:
                        hidden = True
                        findings.append({
                            "type": "micro_text",
                            "page": pno,
                            "label": "Microscopic text",
                            "severity": "high",
                            "detail": "font size %.2f pt (< 1.0 pt)" % size,
                            "preview": text.strip()[:160] or "(whitespace only)",
                            "reason": "Sub-1pt text is imperceptible to the eye "
                                      "but present in the document stream.",
                        })

                    if not padded.contains(fitz.Rect(bbox)):
                        hidden = True
                        findings.append({
                            "type": "off_page",
                            "page": pno,
                            "label": "Off-page text",
                            "severity": "medium",
                            "detail": "positioned at (%.0f, %.0f) outside page bounds" % (bbox[0], bbox[1]),
                            "preview": text.strip()[:160] or "(whitespace only)",
                            "reason": "Text placed outside the visible page area, "
                                      "a classic hiding technique.",
                        })

                    if hidden:
                        continue  # drop the entire hidden span from the sanitized view
                    line_parts.append("".join(ch for ch in text if not is_hidden_char(ch)))

                if line_parts:
                    page_lines.append(" ".join(line_parts))

        sanitized_pages.append("\n".join(page_lines))

    return {
        "findings": findings,
        "span_count": span_count,
        "page_count": doc.page_count,
        "sanitized_text": "\n\n".join(
            "\u2500\u2500 Page %d \u2500\u2500\n%s" % (i + 1, t)
            for i, t in enumerate(sanitized_pages) if t.strip()
        ),
    }


# ---------------------------------------------------------------- Stage 2

AI_HINTS = (
    "midjourney", "dall-e", "dall\u00b7e", "dall e", "stable diffusion",
    "stablediffusion", "sdxl", "comfyui", "firefly", "imagen",
    "novelai", "flux.1", "openai", "ai-generated", "synthetic image",
    "text-to-image", "cognisphere", "photoshop generative",
)


def gemini_image_check(image_bytes: bytes, mime_type: str) -> Optional[Dict[str, Any]]:
    """Optional Gemini vision analysis. Enabled when GEMINI_API_KEY is set
    as an app environment variable (see app.yaml)."""
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None
    payload = {
        "contents": [{
            "parts": [
                {"text": ("You are auditing a photo embedded in a car-insurance claim PDF. "
                          "Decide whether it looks AI-generated / synthetic or a genuine "
                          "photograph of vehicle damage. Look for warped geometry, "
                          "impossible reflections, inconsistent lighting, over-smooth "
                          "textures, garbled text on license plates or badges. "
                          "Reply with ONLY a JSON object: "
                          '{"verdict": "ai_generated"|"authentic"|"inconclusive", '
                          '"confidence": <0-1>, "reason": "<one sentence>"}')},
                {"inline_data": {"mime_type": mime_type,
                                 "data": base64.b64encode(image_bytes).decode()}},
            ],
        }],
        "generationConfig": {"temperature": 0.0},
    }
    req = urllib.request.Request(
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.0-flash:generateContent?key=" + key,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        text = re.sub(r"^```(json)?\s*|\s*```$", "", text)
        return json.loads(text)
    except Exception:
        return None


def thumb_b64(img: Image.Image, max_side: int = 280) -> str:
    im = img.convert("RGB")
    im.thumbnail((max_side, max_side))
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def stage2_image_audit(doc) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    seen_xrefs = set()

    for pno, page in enumerate(doc, start=1):
        try:
            images = page.get_images(full=True)
        except Exception:
            continue
        for img in images:
            xref = img[0]
            if xref in seen_xrefs:
                continue
            seen_xrefs.add(xref)
            try:
                info = doc.extract_image(xref)
                raw = info["image"]
                ext = info.get("ext", "png").lower()
            except Exception:
                continue
            try:
                pil = Image.open(io.BytesIO(raw))
                pil.load()
            except Exception:
                continue
            if pil.width < 50 or pil.height < 50:
                continue  # skip logos / decorative icons

            # ---- metadata forensics
            meta_bits: List[str] = list(pil.info.values())
            has_exif = False
            try:
                exif = pil.getexif()
                if exif:
                    has_exif = True
                    meta_bits.extend(str(v) for v in exif.values())
            except Exception:
                pass
            meta_text = " ".join(str(b) for b in meta_bits if isinstance(b, (str, int, float))).lower()

            verdict = "no_concern"
            reasons: List[str] = []
            score_hint = "none"

            if any(h in meta_text for h in AI_HINTS):
                verdict = "ai_generated"
                score_hint = "ai_generated_image"
                reasons.append("Image metadata contains AI-generation tool signatures.")
            elif not has_exif and not pil.info:
                verdict = "suspicious"
                score_hint = "suspicious_image"
                reasons.append("No camera EXIF metadata found \u2014 typical of "
                               "AI-generated or re-exported synthetic images.")
            else:
                reasons.append("Camera/EXIF metadata present; no AI-tool signatures found.")

            # ---- optional Gemini vision check
            gemini = None
            mime = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png"
            if verdict != "ai_generated":
                gemini = gemini_image_check(raw, mime)
                if gemini and gemini.get("verdict") == "ai_generated":
                    verdict = "ai_generated"
                    score_hint = "ai_generated_image"
                    reasons.append("Gemini vision analysis flags this image as "
                                   "likely AI-generated (%s)." % gemini.get("reason", ""))
                elif gemini and gemini.get("verdict") == "authentic":
                    if verdict == "suspicious":
                        verdict = "no_concern"
                        score_hint = "none"
                    reasons.append("Gemini vision analysis finds it consistent with a "
                                   "genuine photograph.")

            results.append({
                "page": pno,
                "verdict": verdict,
                "score_hint": score_hint,
                "reasons": reasons,
                "width": pil.width,
                "height": pil.height,
                "thumbnail": "data:image/png;base64," + thumb_b64(pil),
            })

    return {"images": results,
            "analyzer": "gemini+metadata" if os.getenv("GEMINI_API_KEY") else "metadata-only"}


# ---------------------------------------------------------------- Stage 3

def stage3_verdict(stage1: Dict[str, Any], stage2: Dict[str, Any]) -> Dict[str, Any]:
    risk_factors: List[Dict[str, Any]] = []
    score = 0

    for f in stage1["findings"]:
        w = WEIGHTS.get(f["type"], 1)
        score += w
        risk_factors.append({"label": f["label"], "page": f["page"],
                            "weight": w, "detail": f["detail"]})
    for img in stage2["images"]:
        if img["score_hint"] == "none":
            continue
        w = WEIGHTS.get(img["score_hint"], 1)
        score += w
        risk_factors.append({"label": ("AI-generated image" if img["score_hint"] == "ai_generated_image"
                                        else "Suspicious image metadata"),
                            "page": img["page"], "weight": w,
                            "detail": "; ".join(img["reasons"])[:200]})

    if score >= 5:
        verdict, recommendation = "BLOCKED", (
            "Critical fraud indicators detected. Route to the special investigations "
            "unit; do not auto-approve this claim.")
    elif score >= 1:
        verdict, recommendation = "SUSPICIOUS", (
            "Some anomalies were detected. Queue for manual adjuster review "
            "before approval.")
    else:
        verdict, recommendation = "APPROVED", (
            "No hidden text, AI-generated imagery, or structural anomalies detected. "
            "Safe to proceed with standard processing.")

    return {"score": score, "verdict": verdict, "risk_factors": risk_factors,
            "recommendation": recommendation}


# ---------------------------------------------------------------- Endpoints

@app.get("/")
async def index():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": "Clearity"}


@app.post("/api/inspect-claim")
async def inspect_claim(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".pdf"):
        raise HTTPException(400, "Please upload a PDF claim file.")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Uploaded file is empty.")
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception:
        raise HTTPException(400, "Could not parse the file as a PDF.")

    stage1 = stage1_forensics(doc)
    stage2 = stage2_image_audit(doc)
    stage3 = stage3_verdict(stage1, stage2)
    doc.close()

    return {
        "filename": file.filename,
        "verdict": stage3["verdict"],
        "score": stage3["score"],
        "recommendation": stage3["recommendation"],
        "stage1": stage1,
        "stage2": stage2,
        "stage3": stage3,
    }


# ---------------------------------------------------------------- Cleaning

def _span_flags(page, span, padded) -> List[str]:
    """Mirror the Stage 1 checks for a single span; returns the list of
    hiding reasons found (empty list = clean span)."""
    text = span.get("text", "")
    if not text.strip():
        return []
    reasons: List[str] = []
    if any(is_hidden_char(ch) for ch in text):
        reasons.append("hidden_unicode")
    rgb = srgb_to_rgb(span.get("color", 0))
    bbox = span.get("bbox", (0, 0, 0, 0))
    if near_white(rgb) and not has_visible_backing(page, bbox):
        reasons.append("white_on_white")
    size = span.get("size", 0.0) or 0.0
    if 0 < size < 1.0:
        reasons.append("micro_text")
    if not padded.contains(fitz.Rect(bbox)):
        reasons.append("off_page")
    return reasons


@app.post("/api/clean-claim")
async def clean_claim(file: UploadFile = File(...)):
    """Return a cleaned copy of the uploaded PDF: hidden spans are redacted,
    invisible Unicode is stripped from otherwise-visible text. Images are kept."""
    if not (file.filename or "").lower().endswith(".pdf"):
        raise HTTPException(400, "Please upload a PDF claim file.")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Uploaded file is empty.")
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception:
        raise HTTPException(400, "Could not parse the file as a PDF.")

    for page in doc:
        page_rect = page.rect
        padded = fitz.Rect(page_rect.x0 - 2, page_rect.y0 - 2,
                           page_rect.x1 + 2, page_rect.y1 + 2)
        reinsert = []  # (baseline point, clean text, size, rgb) for visible spans
        redacted = False
        try:
            blocks = page.get_text("dict")["blocks"]
        except Exception:
            continue
        for block in blocks:
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    reasons = _span_flags(page, span, padded)
                    if not reasons:
                        continue
                    text = span.get("text", "")
                    bbox = span.get("bbox", (0, 0, 0, 0))
                    rect = fitz.Rect(bbox)
                    if reasons == ["hidden_unicode"]:
                        # Visible span carrying invisible characters: redact it
                        # and re-insert the stripped text at the same spot.
                        clean = "".join(ch for ch in text if not is_hidden_char(ch))
                        if clean.strip():
                            size = span.get("size", 11.0) or 11.0
                            baseline = fitz.Point(rect.x0, rect.y1 - size * 0.22)
                            reinsert.append((baseline, clean, size,
                                             srgb_to_rgb(span.get("color", 0))))
                    try:
                        page.add_redact_annot(rect, fill=False)
                        redacted = True
                    except Exception:
                        pass
        if redacted:
            try:
                page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE,
                                      graphics=fitz.PDF_REDACT_LINE_ART_NONE)
            except (TypeError, AttributeError):
                try:
                    page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
                except TypeError:
                    page.apply_redactions()
        for pt, clean, size, rgb in reinsert:
            try:
                page.insert_text(pt, clean, fontsize=size, fontname="helv",
                                 color=tuple(c / 255 for c in rgb))
            except Exception:
                pass

    pdf_bytes = doc.tobytes(deflate=True)
    doc.close()
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", file.filename or "claim.pdf")
    if not safe.lower().endswith(".pdf"):
        safe += ".pdf"
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf",
                             headers={"Content-Disposition":
                                      'attachment; filename="cleaned_%s"' % safe})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
