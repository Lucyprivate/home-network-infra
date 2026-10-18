#!/usr/bin/env python3
"""Optional CTC-token geometry prototype, same tiny-det/small-rec ONNX (CPU, batch one).

DB/CTC preprocessing and postprocessing are adapted from PaddleX v3.7.0,
Copyright (c) 2024 PaddlePaddle Authors, Apache-2.0. See third-party/PaddleX-LICENSE and third-party/PaddleX-NOTICE.md.
This module deliberately has no Paddle/PaddleX, download, subprocess or network
dependency. Heavy imports happen only when constructing PaddleProbe. Row order
is the official SortQuadBoxes order, NOT semantic multi-column reading order.
The caller must enforce the shared cgroup, single-job and wall-clock limits.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

MODEL_PINS = {
    "det": {"inference.onnx": "193bab7a04fca699a6c82e6abb5b81bdb28177f0abd4062552b04908dafb19f8",
            "inference.yml": "3ac018be6f97499a08faa3bbdeb33640968d9307f6736d152902747a9f259593"},
    "rec": {"inference.onnx": "5435fd747c9e0efe15a96d0b378d5bd157e9492ed8fd80edf08f30d02fa24634",
            "inference.yml": "ab078671bb49f06228eadccd34f1bb501e157f7a047095ffb943ba81512c77d1"},
}
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_PIXELS = 100_000_000
MAX_DIMENSION = 20_000  # upstream quadrilaterals use int16
MAX_LINES = 3000
DETECTION_SIDE = 960


class ProbeError(ValueError):
    """Fail closed without exposing recognized text or private paths."""


def _read_regular(path, limit):
    """Open each path component without following symlinks; bounded exact bytes.

    This proves regular-file identity during the read, not deployment RO mounts
    or root ownership. Those are the release/installer's responsibility.
    """
    path = Path(os.path.abspath(os.fspath(path)))
    parts = path.parts
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            before = os.fstat(child)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                raise ProbeError("input is not a bounded nonempty regular file")
            chunks, count = [], 0
            while True:
                block = os.read(child, min(65536, limit + 1 - count))
                if not block:
                    break
                chunks.append(block)
                count += len(block)
                if count > limit:
                    raise ProbeError("file exceeds byte limit")
            after = os.fstat(child)
            if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) != (after.st_ino, after.st_dev, after.st_size,
                                           after.st_mtime_ns, after.st_ctime_ns):
                raise ProbeError("file changed while being read")
            if count != before.st_size:
                raise ProbeError("file length changed")
            return b"".join(chunks)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def _pinned(path, expected, limit):
    data = _read_regular(path, limit)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ProbeError("official model or configuration SHA256 mismatch")
    return data


def detector_size(height, width, side=DETECTION_SIDE):
    """Official max-side resize, then nearest multiple of 32 (no upscaling)."""
    if (type(height) is not int or type(width) is not int or min(height, width) < 1
            or max(height, width) > MAX_DIMENSION or height * width > MAX_PIXELS):
        raise ProbeError("image dimensions exceed bounds")
    # Official tiny-image padding takes place before resize.
    h, w = (max(32, height), max(32, width)) if height + width < 64 else (height, width)
    ratio = min(1.0, side / max(h, w))
    rh, rw = int(h * ratio), int(w * ratio)
    return max(int(round(rh / 32) * 32), 32), max(int(round(rw / 32) * 32), 32)


def recognition_size(height, width):
    if min(height, width) <= 0:
        raise ProbeError("empty recognition crop")
    padded = min(3200, int(48 * max(320 / 48, width / height)))
    return min(padded, int(math.ceil(48 * width / height))), padded


def sort_quad_boxes(boxes):
    """PaddleX SortQuadBoxes; ten ORIGINAL-image pixels is intentional."""
    ordered = sorted(boxes, key=lambda b: (b[0][1], b[0][0]))
    for i in range(len(ordered) - 1):
        for j in range(i, -1, -1):
            if (abs(ordered[j + 1][0][1] - ordered[j][0][1]) < 10
                    and ordered[j + 1][0][0] < ordered[j][0][0]):
                ordered[j], ordered[j + 1] = ordered[j + 1], ordered[j]
            else:
                break
    return ordered


def decode_ctc(indices, probabilities, characters):
    """Official CTC: collapse repeats BEFORE removing blank (index zero)."""
    if len(indices) != len(probabilities):
        raise ProbeError("CTC shape mismatch")
    selected, scores, previous = [], [], None
    for index, confidence in zip(indices, probabilities):
        index, confidence = int(index), float(confidence)
        if not 0 <= index < len(characters) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ProbeError("invalid CTC class or confidence")
        if index != previous and index != 0:
            selected.append(characters[index])
            scores.append(confidence)
        previous = index
    return "".join(selected), sum(scores) / len(scores) if scores else 0.0


def _mini_boxes(cv2, contour):
    rectangle = cv2.minAreaRect(contour)
    p = sorted(list(cv2.boxPoints(rectangle)), key=lambda x: x[0])
    a, d = (0, 1) if p[1][1] > p[0][1] else (1, 0)
    b, c = (2, 3) if p[3][1] > p[2][1] else (3, 2)
    return [p[a], p[b], p[c], p[d]], min(rectangle[1])


def _box_score(np, cv2, probability, points):
    h, w = probability.shape
    x0 = max(0, min(math.floor(points[:, 0].min()), w - 1))
    x1 = max(0, min(math.ceil(points[:, 0].max()), w - 1))
    y0 = max(0, min(math.floor(points[:, 1].min()), h - 1))
    y1 = max(0, min(math.ceil(points[:, 1].max()), h - 1))
    mask = np.zeros((y1 - y0 + 1, x1 - x0 + 1), dtype=np.uint8)
    local = points.copy()
    local[:, 0] -= x0
    local[:, 1] -= y0
    cv2.fillPoly(mask, local.reshape(1, -1, 2).astype(np.int32), 1)
    return float(cv2.mean(probability[y0:y1 + 1, x0:x1 + 1], mask)[0])


def db_boxes(probability, width, height, np, cv2, pyclipper):
    """PaddleX DBPostProcess quad/fast path with fixed pinned YAML settings."""
    if (probability.ndim != 2 or not probability.size or not np.isfinite(probability).all()
            or probability.min() < 0 or probability.max() > 1):
        raise ProbeError("invalid detection probability map")
    contours = cv2.findContours((probability > .2).astype(np.uint8) * 255,
                               cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)[-2]
    mh, mw = probability.shape
    boxes = []
    for contour in contours[:MAX_LINES]:
        points, short = _mini_boxes(cv2, contour)
        if short < 3:
            continue
        points = np.asarray(points)
        if _box_score(np, cv2, probability, points) < .4:
            continue
        perimeter = cv2.arcLength(points, True)
        if perimeter <= 0:
            continue  # defensive degenerate-geometry guard
        distance = cv2.contourArea(points) * 1.4 / perimeter
        offset = pyclipper.PyclipperOffset()
        offset.AddPath(points, pyclipper.JT_ROUND, pyclipper.ET_CLOSEDPOLYGON)
        expanded = offset.Execute(distance)
        if not expanded:
            continue
        # Match upstream's first-path fallback for ragged multiple paths.
        try:
            expanded = np.asarray(expanded).reshape(-1, 1, 2)
        except ValueError:
            expanded = np.asarray(expanded[0]).reshape(-1, 1, 2)
        points, short = _mini_boxes(cv2, expanded.astype(np.float32))
        if short < 5:
            continue
        box = []
        for x, y in points:
            box.append([max(0, min(round(float(x) * width / mw), width)),
                        max(0, min(round(float(y) * height / mh), height))])
        boxes.append(box)
    return boxes


def crop_quad(image, points, np, cv2):
    """Official CropByPolys min-area quad perspective crop, BGR preserved."""
    points, _ = _mini_boxes(cv2, np.asarray(points, dtype=np.int32))
    points = np.asarray(points, dtype=np.float32)
    width = int(max(np.linalg.norm(points[0] - points[1]), np.linalg.norm(points[2] - points[3])))
    height = int(max(np.linalg.norm(points[0] - points[3]), np.linalg.norm(points[1] - points[2])))
    if min(width, height) < 1 or width * height > MAX_PIXELS:
        raise ProbeError("invalid recognition crop geometry")
    target = np.float32([[0, 0], [width, 0], [width, height], [0, height]])
    matrix = cv2.getPerspectiveTransform(points, target)
    crop = cv2.warpPerspective(image, matrix, (width, height), flags=cv2.INTER_CUBIC,
                               borderMode=cv2.BORDER_REPLICATE)
    return np.rot90(crop) if height / width >= 1.5 else crop


TOKEN_GEOMETRY_VERSION = 1
MAX_CTC_STEPS = 8192


class TokenGeometryUnavailable(ValueError):
    """A bounded alignment can be kept as an unchanged whole line instead."""


def decode_ctc_alignment(indices, probabilities, characters):
    """Preserve the exact decoder result and retain its nonblank emission runs.

    A selected dictionary entry may contain multiple Unicode code points. The
    original dictionary entry is atomic; it is never split into invented cells.
    CTC run locations are approximate feature alignments, not glyph boundaries.
    """
    text, confidence = decode_ctc(indices, probabilities, characters)
    if not 0 < len(indices) <= MAX_CTC_STEPS:
        return text, confidence, {"steps": len(indices), "tokens": [], "available": False}
    tokens, previous = [], None
    for step, (index, probability) in enumerate(zip(indices, probabilities)):
        index = int(index)
        if index != previous and index != 0:
            tokens.append({"text": characters[index], "start_step": step,
                           "end_step": step + 1, "confidence": float(probability)})
        elif index != 0:
            tokens[-1]["end_step"] = step + 1
        previous = index
    if "".join(token["text"] for token in tokens) != text:
        raise ProbeError("CTC token concatenation differs from original decode")
    return text, confidence, {"steps": len(indices), "tokens": tokens, "available": True}


def _cjk_token(text):
    """Unicode range classification only; no dictionary or transcription edits."""
    def cjk(char):
        cp = ord(char)
        return (0x3400 <= cp <= 0x4dbf or 0x4e00 <= cp <= 0x9fff or 0x20000 <= cp <= 0x2ebef or
                0x30000 <= cp <= 0x3134f or 0x3040 <= cp <= 0x30ff or
                0x31f0 <= cp <= 0x31ff or 0xac00 <= cp <= 0xd7af or
                0x1100 <= cp <= 0x11ff or 0x3130 <= cp <= 0x318f or
                0xa960 <= cp <= 0xa97f or 0xd7b0 <= cp <= 0xd7ff or
                0x3000 <= cp <= 0x303f or 0xff00 <= cp <= 0xffef)
    return bool(text) and all(cjk(char) for char in text)


def _token_groups(tokens):
    """Retain CJK emissions, group other runs and spaces without editing text."""
    groups = []
    for index, token in enumerate(tokens):
        value = token["text"]
        kind = "space" if value and value.isspace() else "word"
        joinable = kind == "space" or (not _cjk_token(value) and not any(c.isspace() for c in value))
        category = "space" if kind == "space" else ("other" if joinable else "atomic")
        if groups and category in ("space", "other") and groups[-1]["category"] == category:
            groups[-1]["text"] += value
            groups[-1]["last_token"] = index
        else:
            groups.append({"text": value, "kind": kind, "category": category,
                           "first_token": index, "last_token": index})
    return groups


def _transform_point(matrix, x, y):
    if (not isinstance(matrix, (tuple, list)) or len(matrix) != 3 or
            any(not isinstance(row, (tuple, list)) or len(row) != 3 for row in matrix) or
            any(type(v) not in (int, float) or not math.isfinite(v) for row in matrix for v in row)):
        raise TokenGeometryUnavailable("invalid_inverse_crop_transform")
    divisor = matrix[2][0] * x + matrix[2][1] * y + matrix[2][2]
    if not math.isfinite(divisor) or abs(divisor) < 1e-12:
        raise TokenGeometryUnavailable("singular_inverse_crop_transform")
    point = [(matrix[0][0] * x + matrix[0][1] * y + matrix[0][2]) / divisor,
             (matrix[1][0] * x + matrix[1][1] * y + matrix[1][2]) / divisor]
    if not all(math.isfinite(v) for v in point):
        raise TokenGeometryUnavailable("nonfinite_inverse_crop_projection")
    return point


def _aligned_segments(text, alignment, crop, image_width, image_height, line_box):
    """Project CTC midpoint cells through the actual crop inverse transform.

    Cell boundaries are midpoints of consecutive emission-run centers, including
    recognized spaces. They are derived from model timesteps, never uniform text
    lengths. All segments use the exact full crop height: vertical glyph bounds
    are unavailable from CTC and are not claimed to be measured.
    """
    if (not isinstance(alignment, dict) or alignment.get("available") is not True or type(alignment.get("steps")) is not int or
            not 0 < alignment["steps"] <= MAX_CTC_STEPS):
        raise TokenGeometryUnavailable("ctc_alignment_unavailable")
    tokens = alignment.get("tokens")
    if (not isinstance(tokens, list) or len(tokens) > MAX_CTC_STEPS or
            any(not isinstance(token, dict) or type(token.get("text")) is not str or not token["text"] for token in tokens) or
            "".join(token["text"] for token in tokens) != text):
        raise TokenGeometryUnavailable("ctc_alignment_text_mismatch")
    if not isinstance(crop, dict):
        raise TokenGeometryUnavailable("invalid_crop_metadata")
    width, height = crop.get("width"), crop.get("height")
    resized, padded = alignment.get("resized_width"), alignment.get("padded_width")
    if (any(type(v) is not int or v <= 0 for v in (width, height, resized, padded)) or
            resized > padded or padded > 3200 or min(image_width, image_height) < 1):
        raise TokenGeometryUnavailable("invalid_crop_or_padding_metadata")
    centers, previous_end = [], 0
    for token in tokens:
        start, end = token.get("start_step"), token.get("end_step")
        if (type(start) is not int or type(end) is not int or not previous_end <= start < end <= alignment["steps"]):
            raise TokenGeometryUnavailable("nonmonotonic_ctc_alignment")
        center = ((start + end) / 2) * padded / alignment["steps"]
        if not 0 < center < resized:
            raise TokenGeometryUnavailable("ctc_emission_in_padding_or_on_edge")
        centers.append(center / resized * width)
        previous_end = end
    if not centers:
        if text:
            raise TokenGeometryUnavailable("nonempty_text_without_ctc_tokens")
        return []
    if len(centers) == 1:
        raise TokenGeometryUnavailable("single_ctc_emission_has_no_width_evidence")
    if any(b - a <= 1e-9 for a, b in zip(centers, centers[1:])):
        raise TokenGeometryUnavailable("coincident_ctc_centers")
    boundaries = [max(0.0, centers[0] - (centers[1] - centers[0]) / 2)]
    boundaries.extend((a + b) / 2 for a, b in zip(centers, centers[1:]))
    boundaries.append(min(float(width), centers[-1] + (centers[-1] - centers[-2]) / 2))
    segments = []
    for group in _token_groups(tokens):
        left, right = boundaries[group["first_token"]], boundaries[group["last_token"] + 1]
        if not 0 <= left < right <= width:
            raise TokenGeometryUnavailable("invalid_ctc_midpoint_interval")
        quad = [_transform_point(crop.get("inverse"), x, y)
                for x, y in ((left, 0.0), (right, 0.0), (right, float(height)), (left, float(height)))]
        if any(not (0 <= x <= image_width and 0 <= y <= image_height) for x, y in quad):
            raise TokenGeometryUnavailable("token_projection_leaves_page")
        # Min-area crop rectangles can extend slightly beyond rounded detector
        # corners. Anything beyond this two-pixel envelope retains whole-line OCR.
        if any(not (line_box[0] - 2 <= x <= line_box[2] + 2 and
                    line_box[1] - 2 <= y <= line_box[3] + 2) for x, y in quad):
            raise TokenGeometryUnavailable("token_projection_leaves_detector_envelope")
        area = sum(quad[i][0] * quad[(i + 1) % 4][1] -
                   quad[(i + 1) % 4][0] * quad[i][1] for i in range(4))
        if not math.isfinite(area) or abs(area) < 1e-9:
            raise TokenGeometryUnavailable("degenerate_token_projection")
        segments.append({"text": group["text"], "kind": group["kind"], "polygon": quad,
                         "box": [min(p[0] for p in quad), min(p[1] for p in quad),
                                 max(p[0] for p in quad), max(p[1] for p in quad)]})
    if "".join(segment["text"] for segment in segments) != text:
        raise ProbeError("Projected token concatenation differs from original decode")
    return segments


def _crop_text_direction(crop):
    """Keep the recognition crop direction even when CTC geometry abstains."""
    if not isinstance(crop, dict):
        return None, "original_detector"
    angle = crop.get("textangle_degrees")
    if type(angle) in (int, float) and math.isfinite(angle) and -180 <= angle <= 180:
        return float(angle), "exact_crop_rectangle"
    width = crop.get("width")
    if type(width) is not int or width <= 0:
        return None, "original_detector"
    try:
        a = _transform_point(crop.get("inverse"), 0, 0)
        b = _transform_point(crop.get("inverse"), width, 0)
    except TokenGeometryUnavailable:
        return None, "original_detector"
    dx, dy = b[0] - a[0], b[1] - a[1]
    if math.hypot(dx, dy) < 1e-9:
        return None, "original_detector"
    return -math.degrees(math.atan2(dy, dx)), "inverse_crop"


def line_token_geometry(text, alignment, crop, polygon, image_width, image_height):
    """Known alignment uncertainty never changes text or discards a line."""
    bounds = [min(p[0] for p in polygon), min(p[1] for p in polygon),
              max(p[0] for p in polygon), max(p[1] for p in polygon)]
    angle, direction_source = _crop_text_direction(crop)
    common = {"schema": TOKEN_GEOMETRY_VERSION, "source": "same_ctc_argmax",
              "character_bounds": "approximate_feature_centers_and_full_crop_height",
              "extra_recognition_passes": 0, "textangle_degrees": angle,
              "text_direction_source": direction_source}
    if not text:
        return {**common, "status": "empty", "reason": "blank_decode", "segments": []}
    try:
        segments = _aligned_segments(text, alignment, crop, image_width, image_height, bounds)
    except TokenGeometryUnavailable as error:
        return {**common, "status": "fallback", "reason": str(error),
                "segments": [{"text": text, "kind": "word", "box": bounds, "polygon": polygon}]}
    return {**common, "status": "aligned", "reason": "ctc_midpoints_inverse_crop",
            "segments": segments}


def crop_quad_with_geometry(image, points, np, cv2):
    """Identical raster crop plus its exact inverse boundary-coordinate mapping.

    np.rot90 maps boundary coordinates (x,y) back to (old_width-y,x).
    Geometry metadata is optional; an unavailable inverse preserves the crop and
    causes line_token_geometry() to choose the unchanged whole-line fallback.
    """
    points, _ = _mini_boxes(cv2, np.asarray(points, dtype=np.int32))
    points = np.asarray(points, dtype=np.float32)
    width = int(max(np.linalg.norm(points[0] - points[1]), np.linalg.norm(points[2] - points[3])))
    height = int(max(np.linalg.norm(points[0] - points[3]), np.linalg.norm(points[1] - points[2])))
    if min(width, height) < 1 or width * height > MAX_PIXELS:
        raise ProbeError("invalid recognition crop geometry")
    target = np.float32([[0, 0], [width, 0], [width, height], [0, height]])
    matrix = cv2.getPerspectiveTransform(points, target)
    crop = cv2.warpPerspective(image, matrix, (width, height), flags=cv2.INTER_CUBIC,
                               borderMode=cv2.BORDER_REPLICATE)
    rotated = height / width >= 1.5
    if rotated:
        crop = np.rot90(crop)
    try:
        inverse = np.linalg.inv(matrix)
        if rotated:
            inverse = inverse @ np.asarray([[0., -1., float(width)], [1., 0., 0.], [0., 0., 1.]])
        inverse = inverse.tolist() if np.isfinite(inverse).all() else None
    except np.linalg.LinAlgError:
        inverse = None
    start, end = (points[1], points[2]) if rotated else (points[0], points[1])
    angle = -math.degrees(math.atan2(float(end[1] - start[1]), float(end[0] - start[0])))
    return crop, {"width": int(crop.shape[1]), "height": int(crop.shape[0]),
                  "rotated_ccw_90": rotated, "inverse": inverse,
                  "textangle_degrees": angle}


class PaddleProbe:
    def __init__(self, det_dir, rec_dir):
        started = time.monotonic()
        blobs = {}
        for kind, directory in (("det", det_dir), ("rec", rec_dir)):
            blobs[kind] = {name: _pinned(Path(directory) / name, sha,
                                        32 * 1024 * 1024 if name.endswith("onnx") else 512 * 1024)
                           for name, sha in MODEL_PINS[kind].items()}
        for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                    "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
            os.environ[key] = "1"
        import numpy as np
        import cv2
        import onnxruntime as ort
        import pyclipper
        import yaml
        cv2.setNumThreads(1)
        self.np, self.cv2, self.pyclipper = np, cv2, pyclipper
        det = yaml.safe_load(blobs["det"]["inference.yml"])
        rec = yaml.safe_load(blobs["rec"]["inference.yml"])
        if (det["Global"]["model_name"] != "PP-OCRv6_tiny_det"
                or rec["Global"]["model_name"] != "PP-OCRv6_small_rec"
                or rec["PostProcess"]["name"] != "CTCLabelDecode"):
            raise ProbeError("unsupported official configuration")
        characters = rec["PostProcess"]["character_dict"]
        if not isinstance(characters, list) or not characters or not all(isinstance(c, str) for c in characters):
            raise ProbeError("invalid official recognition dictionary")
        self.characters = ["blank", *characters, " "]
        self.sessions = {}
        for kind in ("det", "rec"):
            options = ort.SessionOptions()
            options.intra_op_num_threads = 1
            options.inter_op_num_threads = 1
            options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
            options.add_session_config_entry("session.intra_op.allow_spinning", "0")
            options.add_session_config_entry("session.inter_op.allow_spinning", "0")
            session = ort.InferenceSession(blobs[kind]["inference.onnx"], sess_options=options,
                                           providers=["CPUExecutionProvider"])
            inputs = session.get_inputs()
            if len(inputs) != 1 or inputs[0].type != "tensor(float)" or len(inputs[0].shape) != 4:
                raise ProbeError("unexpected ONNX input contract")
            if session.get_providers() != ["CPUExecutionProvider"]:
                raise ProbeError("non-CPU inference provider refused")
            self.sessions[kind] = (session, inputs[0].name)
        self.report_pins = {
            "model_sha256": {k: p["inference.onnx"] for k, p in MODEL_PINS.items()},
            "config_sha256": {k: p["inference.yml"] for k, p in MODEL_PINS.items()},
            "detector": {"limit_type": "max", "limit_side_len": DETECTION_SIDE,
                         "thresh": .2, "box_thresh": .4, "unclip_ratio": 1.4,
                         "max_candidates": MAX_LINES},
            "recognizer": {"height": 48, "minimum_padded_width": 320,
                           "maximum_padded_width": 3200, "batch_size": 1},
            "threads": 1, "provider": "CPUExecutionProvider",
            "reading_order": "PaddleX SortQuadBoxes; may interleave columns",
        }
        self.initialization_seconds = time.monotonic() - started

    def _run(self, kind, tensor):
        session, name = self.sessions[kind]
        output = session.run(None, {name: tensor})
        if len(output) != 1:
            raise ProbeError("unexpected ONNX output count")
        return output[0]

    def _detect(self, image):
        np, cv2 = self.np, self.cv2
        h, w = image.shape[:2]
        rh, rw = detector_size(h, w)
        if h + w < 64:
            padded = np.zeros((max(h, 32), max(w, 32), 3), dtype=np.uint8)
            padded[:h, :w] = image
            image = padded
        resized = cv2.resize(image, (rw, rh)).astype(np.float32)
        for channel, (mean, std) in enumerate(zip((.485, .456, .406), (.229, .224, .225))):
            resized[:, :, channel] *= (1 / 255) / std
            resized[:, :, channel] += -mean / std
        tensor = np.ascontiguousarray(resized.transpose(2, 0, 1)[None], dtype=np.float32)
        output = self._run("det", tensor)
        if output.ndim != 4 or output.shape[:2] != (1, 1):
            raise ProbeError("unexpected detection output shape")
        return sort_quad_boxes(db_boxes(output[0, 0], w, h, np, cv2, self.pyclipper))

    def _recognize_crop(self, crop, *, with_alignment=False):
        np, cv2 = self.np, self.cv2
        resized_width, padded_width = recognition_size(*crop.shape[:2])
        resized = cv2.resize(crop, (resized_width, 48)).astype(np.float32)
        normalized = resized.transpose(2, 0, 1) / 255
        normalized -= .5
        normalized /= .5
        tensor = np.zeros((1, 3, 48, padded_width), dtype=np.float32)
        tensor[0, :, :, :resized_width] = normalized
        output = self._run("rec", tensor)
        if (output.ndim != 3 or output.shape[0] != 1 or output.shape[2] != len(self.characters)
                or not np.isfinite(output).all() or output.min() < 0 or output.max() > 1):
            raise ProbeError("unexpected recognition probabilities or dictionary shape")
        indices = output[0].argmax(axis=1).tolist()
        probabilities = output[0].max(axis=1).tolist()
        if with_alignment:
            text, confidence, alignment = decode_ctc_alignment(indices, probabilities, self.characters)
            alignment.update(resized_width=resized_width, padded_width=padded_width)
            return text, confidence, alignment
        return decode_ctc(indices, probabilities, self.characters)

    def recognize(self, image_path):
        started = time.monotonic()
        data = _read_regular(image_path, MAX_IMAGE_BYTES)
        from PIL import Image
        with Image.open(io.BytesIO(data)) as source:
            if source.format not in {"PNG", "JPEG"}:
                raise ProbeError("only PNG or JPEG raster input is supported")
            width, height = source.size
            detector_size(height, width)  # validate BEFORE decoding image pixels
            raw_dpi = source.info.get("dpi", (300, 300))
            try:
                dpi = [float(raw_dpi[0]), float(raw_dpi[1])]
            except (TypeError, ValueError, IndexError):
                raise ProbeError("invalid raster DPI metadata") from None
            if not all(math.isfinite(x) and 1 <= x <= 2400 for x in dpi):
                raise ProbeError("raster DPI metadata outside bounds")
            rgb = self.np.asarray(source.convert("RGB"))
        image = self.np.ascontiguousarray(rgb[:, :, ::-1])  # official BGR decode
        lines = []
        for polygon in self._detect(image):
            crop, crop_geometry = crop_quad_with_geometry(image, polygon, self.np, self.cv2)
            text, confidence, alignment = self._recognize_crop(crop, with_alignment=True)
            polygon = [[float(x), float(y)] for x, y in polygon]
            lines.append({"polygon": polygon,
                          "box": [min(p[0] for p in polygon), min(p[1] for p in polygon),
                                  max(p[0] for p in polygon), max(p[1] for p in polygon)],
                          "text": text, "confidence": confidence,
                          "token_geometry": line_token_geometry(text, alignment, crop_geometry, polygon, width, height)})
        return {"schema": 2, "engine": "PP-OCRv6_tiny_det_small_rec_onnx", "width": width,
                "height": height, "dpi": dpi, "lines": lines,
                "text": "\n".join(line["text"] for line in lines),
                "elapsed_seconds": time.monotonic() - started,
                "initialization_seconds": self.initialization_seconds,
                "token_geometry_version": TOKEN_GEOMETRY_VERSION,
                "token_geometry_extra_recognition_passes": 0,
                **self.report_pins}

    infer = recognize


def _write_private(path, data):
    # Exclusive create: never overwrite symlinks, source images or prior evidence.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--det-dir", required=True)
    parser.add_argument("--rec-dir", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-text", required=True)
    parser.add_argument("--public-synthetic", action="store_true",
                        help="acknowledge that these raw-text artifacts contain only public synthetic data")
    args = parser.parse_args(argv)
    if not args.public_synthetic:
        parser.error("--public-synthetic is required for raw-text CLI artifacts")
    try:
        if os.path.abspath(args.output_json) == os.path.abspath(args.output_text):
            raise ProbeError("output paths must differ")
        probe = PaddleProbe(args.det_dir, args.rec_dir)
        result = probe.recognize(args.image)
        _write_private(args.output_json, (json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode())
        _write_private(args.output_text, (result["text"] + "\n").encode())
        print(json.dumps({"status": "passed", "width": result["width"], "height": result["height"],
                          "lines": len(result["lines"]), "elapsed_seconds": result["elapsed_seconds"],
                          "initialization_seconds": result["initialization_seconds"]}, allow_nan=False))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
