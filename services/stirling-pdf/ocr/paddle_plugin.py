"""Optional Small-rec CTC token geometry bridge, with pinned skew-aware ordering.

Load with --plugin /trusted/paddle_plugin.py --jobs 1 --paddle-det-dir DIR
--paddle-rec-dir DIR --paddle-probe-sha256 SHA.  paddle_probe.py must be beside
this file.  Deployment must bind the lab code/models read-only; path/hash checks
here establish byte integrity, not a read-only mount attestation.
The expected probe SHA belongs in the reviewed root-owned wrapper/receipt;
never derive that expected value from a mutable request or current source file.

The native hocr request is normalized to fpdf2 by 17.13's coordinator, which
calls generate_ocr().  generate_hocr() is also implemented.  Only supported
language sets containing chi_sim or chi_tra select Paddle.  English-only,
sandwich, explicit Tesseract, and other language sets select original Tesseract
before processing.  Inference errors never trigger a hidden fallback.

The optional schema-2 probe retains approximate CTC feature alignment from the
same recognition pass. Native words use inverse-crop-projected token boxes when
valid; uncertain geometry retains the original whole line. Recognized text and
confidence, detector line boxes/corners and task flags are preserved. Native
renderer font/encoding/BT spacing remains upstream; only line/word geometry changes.
Line direction follows the actual recognition crop, including a tall crop's
rotation when token alignment is uncertain. Line geometry uses source-pinned renderer5 with a bounded font-em calibration
of 1.15 selected on consumed development outputs. It is not an ink-metric claim.
ActualText is not added; native font selection, encoding, per-word horizontal
scaling, word positions and baselines stay. Only vertical nominal font size grows.
The adapter applies only to marked Paddle rows, not original Tesseract rows.
These are approximate temporal boxes, not measured glyph boundaries. Exact spaces
remain in TXT; native PDF word spacing remains the renderer's responsibility.
The unchanged geometry-v2 algorithm orders whole lines using boxes/corners only.
PDF viewers may independently infer a different order from physical positions.
No preprocessing option is enabled, disabled, or rewritten by this plugin.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import types
import xml.etree.ElementTree as ET

import ocrmypdf
from ocrmypdf import hookimpl
from ocrmypdf.builtin_plugins.tesseract_ocr import TesseractOcrEngine
from ocrmypdf.exceptions import BadArgsError
from ocrmypdf.models.ocr_element import Baseline, BoundingBox, OcrClass, OcrElement
from ocrmypdf.pluginspec import OcrEngine

VERSION = "small-ctc-calibrated-5"
RENDERER_SHA256 = "fd1413696c1bd99d88c161b0482366035ec534bf6520791c20ec72c4b783fa46"
GEOMETRY_SHA256 = "cf0708101fe1ff50e4bb2353c6fe6897be8b5ebbe64cfdad1c31e1f2482e8f65"
PROBE_SHA256 = "e54d1b413a676d85b8df4738d511cc017c86f2f96be0e4b1e2683305c3509998"
LAYOUT_SHA256 = "945856f4496d2695d4731e904711c1767b4bbeaa30a73954e3c3dfbc1a195e72"
OCRMY_PDF_VERSION = "17.13.0"
ENGINE = "PP-OCRv6_tiny_det_small_rec_onnx"
SUPPORTED_LANGUAGES = frozenset({"chi_sim", "chi_tra", "eng"})
MAX_PROBE_SOURCE = 512 * 1024
MAX_TEXT = 1024 * 1024
MAX_LINES = 10000
SHA = re.compile(r"[0-9a-f]{64}\Z")
log = logging.getLogger(__name__)
_lock = threading.RLock()
_cached = None
_layout_cached = None
_renderer_cached = None


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def route(options):
    """Pure routing decision; language order never chooses a different model."""
    if options is None or getattr(options, "ocr_engine", "auto") != "auto":
        return "tesseract"
    languages = getattr(options, "languages", None)
    if (not isinstance(languages, (list, tuple, set, frozenset)) or not languages or
            any(type(value) is not str or value not in SUPPORTED_LANGUAGES
                for value in languages)):
        return "tesseract"
    if not {"chi_sim", "chi_tra"}.intersection(languages):
        return "tesseract"
    if getattr(options, "pdf_renderer", "auto") == "sandwich":
        return "tesseract"
    if getattr(options, "pdf_renderer", "auto") not in ("auto", "fpdf2", "hocr", "hocrdebug"):
        return "tesseract"
    return "paddle"


def native_flags(options):
    """Safe task metadata: values are observed, never forced or persisted."""
    flags = {}
    for name in ("clean", "deskew", "rotate_pages", "clean_final"):
        value = getattr(options, name, False)
        if type(value) is not bool:
            raise BadArgsError("Paddle bridge requires native boolean task flags.")
        flags[name] = value
    return {**flags, "preprocessing_forced": False, "route": route(options)}


def _plain_path(value):
    if not isinstance(value, (str, Path)) or not str(value):
        raise BadArgsError("Paddle bridge requires explicit local model directories.")
    path = Path(os.path.abspath(value))
    for parent in (*reversed(path.parents), path):
        try:
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise BadArgsError("Paddle bridge refuses symlinked asset paths.")
        except OSError:
            raise BadArgsError("Paddle bridge asset path is unavailable.") from None
    return path


def _source_bytes(path, expected):
    if type(expected) is not str or not SHA.fullmatch(expected):
        raise BadArgsError("Paddle bridge requires the exact probe source SHA256.")
    path = _plain_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_size > MAX_PROBE_SOURCE or before.st_mode & 0o022):
                raise BadArgsError("Paddle bridge refuses untrusted probe source metadata.")
            data = stream.read(MAX_PROBE_SOURCE + 1)
            after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (identity(before) != identity(after) or len(data) != before.st_size or
                hashlib.sha256(data).hexdigest() != expected):
            raise BadArgsError("Paddle bridge probe source integrity check failed.")
        return data
    except OSError:
        raise BadArgsError("Paddle bridge could not safely read probe source.") from None


def _configuration(options):
    if getattr(ocrmypdf, "__version__", None) != OCRMY_PDF_VERSION:
        raise BadArgsError("Paddle bridge requires the reviewed OCRmyPDF 17.13.0 runtime.")
    if type(getattr(options, "jobs", None)) is not int or options.jobs != 1:
        raise BadArgsError("Paddle bridge requires explicit --jobs 1.")
    det = _plain_path(getattr(options, "paddle_det_dir", None))
    rec = _plain_path(getattr(options, "paddle_rec_dir", None))
    if not det.is_dir() or not rec.is_dir():
        raise BadArgsError("Paddle bridge model paths must be local directories.")
    expected = getattr(options, "paddle_probe_sha256", None)
    if expected != PROBE_SHA256:
        raise BadArgsError("Small bridge requires the frozen Small adapter source.")
    path = Path(__file__).absolute().with_name("paddle_probe.py")
    data = _source_bytes(path, expected)
    _source_bytes(Path(__file__).absolute().with_name("paddle_layout_v2.py"), LAYOUT_SHA256)
    _source_bytes(Path(__file__).absolute().with_name("paddle_renderer5.py"), RENDERER_SHA256)
    _source_bytes(Path(__file__).absolute().with_name("paddle_geometry4.py"), GEOMETRY_SHA256)
    return (os.getpid(), str(path), expected, str(det), str(rec)), data


def _install_renderer():
    global _renderer_cached
    key = os.getpid(), RENDERER_SHA256
    if _renderer_cached is None or _renderer_cached[0] != key:
        path = Path(__file__).absolute().with_name("paddle_renderer5.py")
        data = _source_bytes(path, RENDERER_SHA256)
        module = types.ModuleType("_stirling_calibrated5_renderer_" + RENDERER_SHA256)
        module.__file__ = str(path)
        exec(compile(data, str(path), "exec"), module.__dict__)
        if module.GEOMETRY_SHA != GEOMETRY_SHA256:
            raise BadArgsError("Renderer5 geometry pin differs.")
        _renderer_cached = key, module
    _renderer_cached[1].install(_source_bytes, RENDERER_SHA256)


@hookimpl
def add_options(parser):
    group = parser.add_argument_group("Stirling local Paddle probe")
    group.add_argument("--paddle-det-dir", type=Path, default=None)
    group.add_argument("--paddle-rec-dir", type=Path, default=None)
    group.add_argument("--paddle-probe-sha256", default=None)


@hookimpl
def check_options(options):
    if route(options) == "paddle":
        _configuration(options)  # Source bytes only; no ORT import/model load.
        _install_renderer()  # Explicit geometry-only adapter; no model load.
        flags = native_flags(options)
        log.info("Paddle bridge selected; native clean=%s deskew=%s rotate_pages=%s clean_final=%s; preprocessing_forced=false",
                 flags["clean"], flags["deskew"], flags["rotate_pages"], flags["clean_final"])
    elif getattr(options, "pdf_renderer", None) == "sandwich":
        log.info("Paddle bridge routes sandwich to original Tesseract before processing.")


def _probe(options):
    global _cached
    key, source = _configuration(options)
    if _cached is not None and _cached[0] == key:
        return _cached[1]
    _cached = None  # Never keep two model pairs resident after a configuration change.
    name = "_stirling_paddle_probe_" + key[2]
    module = types.ModuleType(name)
    module.__file__ = key[1]
    sys.modules[name] = module
    try:
        # Execute exactly the bytes whose SHA was checked; never reopen for import.
        exec(compile(source, key[1], "exec"), module.__dict__)
        probe = module.PaddleProbe(Path(key[3]), Path(key[4]))
    except Exception:
        sys.modules.pop(name, None)
        raise RuntimeError("Pinned Paddle probe initialization failed; no fallback was attempted.") from None
    _cached = key, probe
    return probe


def validated_result(result):
    """Validate geometry/text without rewriting the probe's order or transcription."""
    def refuse():
        raise RuntimeError("Pinned Paddle probe returned an invalid result envelope.")
    if not isinstance(result, dict) or result.get("schema") != 2 or type(result.get("schema")) is not int or result.get("engine") != ENGINE:
        refuse()
    width, height = result.get("width"), result.get("height")
    if (type(width) is not int or type(height) is not int or width <= 0 or height <= 0 or
            width * height > 250_000_000):
        refuse()
    dpi = result.get("dpi")
    if (not isinstance(dpi, (list, tuple)) or len(dpi) != 2 or
            any(not _number(v) or v <= 0 for v in dpi) or
            abs(dpi[0] - dpi[1]) > max(dpi) * 0.001):
        refuse()  # OCRmyPDF rasterizes square pixels; don't misplace an anisotropic page.
    for label in ("model_sha256", "config_sha256"):
        pins = result.get(label)
        if (not isinstance(pins, dict) or set(pins) != {"det", "rec"} or
                any(type(v) is not str or not SHA.fullmatch(v) for v in pins.values())):
            refuse()
    if (type(result.get("token_geometry_version")) is not int or result.get("token_geometry_version") != 1 or
            type(result.get("token_geometry_extra_recognition_passes")) is not int or
            result.get("token_geometry_extra_recognition_passes") != 0):
        refuse()
    lines = result.get("lines")
    if not isinstance(lines, list) or len(lines) > MAX_LINES:
        refuse()
    for line in lines:
        if not isinstance(line, dict):
            refuse()
        text, box, poly = line.get("text"), line.get("box"), line.get("polygon")
        if (type(text) is not str or
                any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in text) or
                len(text.encode("utf-8")) > MAX_TEXT):
            refuse()
        if (not isinstance(box, (list, tuple)) or len(box) != 4 or
                any(not _number(v) for v in box) or
                not (0 <= box[0] < box[2] <= width and 0 <= box[1] < box[3] <= height)):
            refuse()
        if (not isinstance(poly, (list, tuple)) or len(poly) != 4 or
                any(not isinstance(p, (list, tuple)) or len(p) != 2 or
                    not _number(p[0]) or not _number(p[1]) or
                    not (0 <= p[0] <= width and 0 <= p[1] <= height) for p in poly)):
            refuse()
        area_twice = sum(poly[n][0] * poly[(n + 1) % 4][1] -
                         poly[(n + 1) % 4][0] * poly[n][1] for n in range(4))
        if area_twice == 0:
            refuse()
        confidence = line.get("confidence")
        if not _number(confidence) or not 0 <= confidence <= 1:
            refuse()
    if sum(_validate_token_geometry(line, width, height) for line in lines) > MAX_SEGMENTS_PER_PAGE:
        refuse()
    text = result.get("text")
    if (type(text) is not str or text != "\n".join(line["text"] for line in lines) or
            len(text.encode("utf-8")) > MAX_TEXT):
        refuse()
    return result


MAX_SEGMENTS_PER_PAGE = 50_000
MAX_SEGMENTS_PER_LINE = 8192


def _validate_token_geometry(line, width, height):
    """Validate approximate native selection boxes without changing transcription."""
    geometry = line.get("token_geometry")
    def refuse():
        raise RuntimeError("Pinned token probe returned invalid geometry metadata.")
    if (not isinstance(geometry, dict) or type(geometry.get("schema")) is not int or
            geometry.get("schema") != 1 or geometry.get("source") != "same_ctc_argmax" or
            geometry.get("character_bounds") != "approximate_feature_centers_and_full_crop_height" or
            type(geometry.get("extra_recognition_passes")) is not int or
            geometry.get("extra_recognition_passes") != 0 or
            geometry.get("status") not in ("aligned", "fallback", "empty") or
            type(geometry.get("reason")) is not str or not 0 < len(geometry["reason"]) <= 128 or
            any(ord(c) < 32 for c in geometry["reason"])):
        refuse()
    segments = geometry.get("segments")
    angle = geometry.get("textangle_degrees")
    direction_source = geometry.get("text_direction_source")
    if angle is None:
        if direction_source != "original_detector" or geometry["status"] == "aligned":
            refuse()
        if (geometry["status"] == "fallback" and
                line["box"][3] - line["box"][1] >= 1.5 * (line["box"][2] - line["box"][0])):
            refuse()  # An unknown tall direction must not silently render horizontally.
    elif (not _number(angle) or not -180 <= angle <= 180 or
            direction_source not in ("exact_crop_rectangle", "inverse_crop")):
        refuse()
    if not isinstance(segments, list) or len(segments) > MAX_SEGMENTS_PER_LINE:
        refuse()
    for segment in segments:
        if not isinstance(segment, dict) or set(segment) != {"text", "kind", "box", "polygon"}:
            refuse()
        text, box, poly = segment["text"], segment["box"], segment["polygon"]
        if (type(text) is not str or not text or segment["kind"] not in ("word", "space") or
                segment["kind"] == "space" and not text.isspace()):
            refuse()
        if (not isinstance(box, (list, tuple)) or len(box) != 4 or
                any(not _number(v) for v in box) or
                not (0 <= box[0] < box[2] <= width and 0 <= box[1] < box[3] <= height)):
            refuse()
        if (not isinstance(poly, (list, tuple)) or len(poly) != 4 or
                any(not isinstance(point, (list, tuple)) or len(point) != 2 or
                    any(not _number(v) for v in point) or
                    not (0 <= point[0] <= width and 0 <= point[1] <= height) or
                    not (line["box"][0] - 2 <= point[0] <= line["box"][2] + 2 and
                         line["box"][1] - 2 <= point[1] <= line["box"][3] + 2)
                    for point in poly)):
            refuse()
        envelope = [min(point[0] for point in poly), min(point[1] for point in poly),
                    max(point[0] for point in poly), max(point[1] for point in poly)]
        if any(abs(a - b) > 1e-6 for a, b in zip(envelope, box)):
            refuse()
        crosses = []
        for i in range(4):
            a, b, c = poly[i], poly[(i + 1) % 4], poly[(i + 2) % 4]
            crosses.append((b[0] - a[0]) * (c[1] - b[1]) - (b[1] - a[1]) * (c[0] - b[0]))
        if not (all(c > 0 for c in crosses) or all(c < 0 for c in crosses)):
            refuse()
    if "".join(segment["text"] for segment in segments) != line["text"]:
        refuse()
    if geometry["status"] == "empty":
        if line["text"] or segments:
            refuse()
    elif geometry["status"] == "fallback":
        if (not line["text"] or len(segments) != 1 or segments[0] !=
                {"text": line["text"], "kind": "word", "box": line["box"], "polygon": line["polygon"]}):
            refuse()
    elif not segments or not line["text"]:
        refuse()
    if geometry["status"] == "aligned":
        first = segments[0]["polygon"]
        observed = -math.degrees(math.atan2(first[1][1] - first[0][1], first[1][0] - first[0][0]))
        if abs((angle - observed + 180) % 360 - 180) > .01:
            refuse()
    return len(segments)


def _raster_path(input_file):
    """Resolve only OCRmyPDF's same-work-folder raster links, not user links.

17.13 create_ocr_image() links unchanged rasters to *_ocr.png.  The standalone
probe correctly refuses symlinks.  This narrow framework boundary hands it the
regular raster target while retaining that rule for every other input path.
"""
    path = Path(os.path.abspath(input_file))
    if not path.is_symlink():
        return path
    parent = _plain_path(path.parent)
    if not parent.name.startswith("ocrmypdf.io."):
        raise BadArgsError("Paddle bridge refuses non-framework raster symlinks.")
    for _ in range(4):
        before = path.lstat()
        if not stat.S_ISLNK(before.st_mode):
            if not stat.S_ISREG(before.st_mode):
                raise BadArgsError("Paddle bridge raster target is not regular.")
            return path
        link = os.readlink(path)
        after = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after):
            raise BadArgsError("Paddle bridge raster symlink changed while reading.")
        target = Path(link)
        path = Path(os.path.abspath(target if target.is_absolute() else parent / target))
        if path.parent != parent or path.suffix.lower() not in (".png", ".jpg", ".jpeg"):
            raise BadArgsError("Paddle bridge raster link leaves its framework directory.")
    raise BadArgsError("Paddle bridge raster link chain is too deep.")


def _layout_order(result):
    """A geometry-only full permutation; text is never passed to the consumer."""
    global _layout_cached
    key = os.getpid(), LAYOUT_SHA256
    if _layout_cached is None or _layout_cached[0] != key:
        path = Path(__file__).absolute().with_name("paddle_layout_v2.py")
        source = _source_bytes(path, LAYOUT_SHA256)
        module = types.ModuleType("_stirling_small_geometry_v2_" + LAYOUT_SHA256)
        module.__file__ = str(path)
        exec(compile(source, str(path), "exec"), module.__dict__)
        _layout_cached = key, module
    metadata = _layout_cached[1].reading_order(
        [line["box"] for line in result["lines"]], result["width"], result["height"],
        polygons=[line["polygon"] for line in result["lines"]])
    if (not isinstance(metadata, dict) or type(metadata.get("schema")) is not int or
            metadata.get("schema") != 2 or
            metadata.get("algorithm") != "skew-normalized-two-column-bands-v2" or
            not isinstance(metadata.get("diagnostic"), dict) or
            metadata.get("diagnostic", {}).get("geometry_only") is not True or
            metadata.get("diagnostic", {}).get("text_read") is not False):
        raise RuntimeError("Pinned geometry consumer returned incompatible metadata.")
    order = metadata.get("order")
    if (metadata.get("status") not in ("reordered", "abstained", "unchanged") or not isinstance(order, list) or
            any(type(index) is not int for index in order) or sorted(order) != list(range(len(result["lines"])))):
        raise RuntimeError("Frozen geometry consumer returned an invalid complete permutation.")
    lines = [result["lines"][index] for index in order]
    result = {**result, "lines": lines, "text": "\n".join(line["text"] for line in lines),
              "layout": {**metadata, "source_sha256": LAYOUT_SHA256,
                         "word_or_script_replacements": False}}
    log.info("Small bridge geometry status=%s reason=%s; word_or_script_replacements=false",
             metadata["status"], metadata.get("reason", "unspecified"))
    return validated_result(result)


def _recognize(input_file, options):
    if route(options) != "paddle":
        raise RuntimeError("Paddle recognition was called outside its selected route.")
    with _lock:
        try:
            raster = _raster_path(input_file)
            result = _probe(options).recognize(raster)
        except BadArgsError:
            raise
        except Exception:
            raise RuntimeError("Pinned Paddle inference failed; no fallback was attempted.") from None
        return _layout_order(validated_result(result))


def _line_angle(line):
    """Use the actual crop's text direction, including its tall-line rotation."""
    geometry = line["token_geometry"]
    if geometry["textangle_degrees"] is not None:
        return geometry["textangle_degrees"]
    polygon = line["polygon"]
    return -math.degrees(math.atan2(polygon[1][1] - polygon[0][1],
                                   polygon[1][0] - polygon[0][0]))


def result_tree(result, page_number=0):
    result = validated_result(result)
    if type(page_number) is not int or page_number < 0:
        raise ValueError("Paddle page number must be a non-negative integer.")
    paragraphs = []
    for line in result["lines"]:
        if not line["text"]:
            continue
        words = []
        for segment in line["token_geometry"]["segments"]:
            if segment["kind"] == "space":
                continue  # Exact spaces stay in the sidecar; native renderer spaces words.
            words.append(OcrElement(ocr_class=OcrClass.WORD, bbox=BoundingBox(*segment["box"]),
                poly=[tuple(p) for p in segment["polygon"]], text=segment["text"], confidence=line["confidence"]))
        if not words:
            continue  # A whitespace-only recognized line contains no searchable glyphs.
        box = BoundingBox(*line["box"])
        poly = [tuple(p) for p in line["polygon"]]
        angle = _line_angle(line)
        row = OcrElement(ocr_class=OcrClass.LINE, bbox=box, poly=poly,
                         baseline=Baseline(), textangle=angle, children=words)
        row._stirling_quad_renderer = "stirling-paddle-calibrated-v5"
        paragraphs.append(OcrElement(ocr_class=OcrClass.PARAGRAPH, bbox=box, children=[row]))
    page = OcrElement(ocr_class=OcrClass.PAGE,
                      bbox=BoundingBox(0, 0, result["width"], result["height"]),
                      dpi=float(result["dpi"][0]), page_number=page_number, children=paragraphs)
    return page, result["text"]


def result_hocr(result):
    result = validated_result(result)
    root = ET.Element("html", {"xmlns": "http://www.w3.org/1999/xhtml"})
    head = ET.SubElement(root, "head")
    ET.SubElement(head, "meta", {"http-equiv": "Content-Type", "content": "text/html; charset=utf-8"})
    body = ET.SubElement(root, "body")
    page = ET.SubElement(body, "div", {"class": "ocr_page", "id": "page_1",
        "title": f'bbox 0 0 {result["width"]} {result["height"]}; scan_res {result["dpi"][0]} {result["dpi"][1]}'})
    bounds = lambda box: " ".join(str(v) for v in (math.floor(box[0]), math.floor(box[1]), math.ceil(box[2]), math.ceil(box[3])))
    for number, line in enumerate(result["lines"], 1):
        if not line["text"]:
            continue
        para = ET.SubElement(page, "p", {"class": "ocr_par", "id": f"par_{number}", "title": "bbox " + bounds(line["box"])})
        row = ET.SubElement(para, "span", {"class": "ocr_line", "id": f"line_{number}", "title": "bbox " + bounds(line["box"]) + f"; baseline 0 0; textangle {_line_angle(line)}"})
        for index, segment in enumerate(line["token_geometry"]["segments"], 1):
            if segment["kind"] == "space":
                continue
            word = ET.SubElement(row, "span", {"class": "ocrx_word", "id": f"word_{number}_{index}",
                "title": "bbox " + bounds(segment["box"]) + f'; x_wconf {round(line["confidence"] * 100)}'})
            word.text = segment["text"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class PaddleEngine(OcrEngine):
    @staticmethod
    def version():
        return "PP-OCRv6 tiny-det/small-rec ONNX geometry bridge " + VERSION

    @staticmethod
    def creator_tag(options):
        return PaddleEngine.version()

    def __str__(self):
        return self.version()

    @staticmethod
    def languages(options):
        return SUPPORTED_LANGUAGES

    @staticmethod
    def get_orientation(input_file, options):
        return TesseractOcrEngine.get_orientation(input_file, options)

    @staticmethod
    def get_deskew(input_file, options):
        return TesseractOcrEngine.get_deskew(input_file, options)

    @staticmethod
    def supports_generate_ocr():
        return True

    @staticmethod
    def generate_ocr(input_file, options, page_number=0):
        return result_tree(_recognize(input_file, options), page_number)

    @staticmethod
    def generate_hocr(input_file, output_hocr, output_text, options):
        result = _recognize(input_file, options)
        Path(output_hocr).write_bytes(result_hocr(result))
        Path(output_text).write_text(result["text"], encoding="utf-8")

    @staticmethod
    def generate_pdf(input_file, output_pdf, output_text, options):
        raise RuntimeError("Paddle bridge does not render sandwich; select original Tesseract before processing.")


@hookimpl
def get_ocr_engine(options):
    if route(options) == "paddle":
        _install_renderer()
        return PaddleEngine()
    return None
