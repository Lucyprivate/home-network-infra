"""Geometry-only, skew-normalized two-column reading order.

This pure function accepts bounding boxes and, optionally, their four detector
corners. It never receives text, language, confidence, images or answer keys.
Every input index is returned exactly once. A single-column or ambiguous page
keeps its original order. This is a bounded two-column heuristic, not a table,
RTL, arbitrary magazine-layout or semantic document understanding system.

Compared with v1, isolated gutter-crossing headings do not erase column evidence;
quadrilateral baselines also allow a page-wide, robust skew normalization before
column detection. Neither operation changes pixels or recognized characters.
"""
from __future__ import annotations

import math
from statistics import median

ALGORITHM = "skew-normalized-two-column-bands-v2"
MAX_BOXES = 3000
MAX_SKEW_DEGREES = 12.0


def _validate(boxes, width, height, polygons):
    if (type(width) is not int or type(height) is not int or min(width, height) < 1
            or max(width, height) > 20000 or width * height > 100_000_000):
        raise ValueError("invalid page dimensions")
    if not isinstance(boxes, (list, tuple)) or len(boxes) > MAX_BOXES:
        raise ValueError("invalid or excessive box count")
    clean = []
    for box in boxes:
        if (not isinstance(box, (list, tuple)) or len(box) != 4
                or any(type(v) not in (float, int) or not math.isfinite(v) for v in box)
                or not (0 <= box[0] < box[2] <= width and 0 <= box[1] < box[3] <= height)):
            raise ValueError("invalid finite page box")
        clean.append(tuple(float(v) for v in box))
    if polygons is None:
        return clean, None
    if not isinstance(polygons, (list, tuple)) or len(polygons) != len(clean):
        raise ValueError("polygon count must match boxes")
    corners = []
    for poly, box in zip(polygons, clean):
        if not isinstance(poly, (list, tuple)) or len(poly) != 4:
            raise ValueError("invalid detector quadrilateral")
        points = []
        for point in poly:
            if (not isinstance(point, (list, tuple)) or len(point) != 2
                    or any(type(v) not in (float, int) or not math.isfinite(v) for v in point)
                    or not (0 <= point[0] <= width and 0 <= point[1] <= height)):
                raise ValueError("invalid detector point")
            points.append(tuple(float(v) for v in point))
        crosses = []
        for i in range(4):
            a, b, c = points[i], points[(i + 1) % 4], points[(i + 2) % 4]
            crosses.append((b[0] - a[0]) * (c[1] - b[1]) -
                           (b[1] - a[1]) * (c[0] - b[0]))
        if not (all(c > 0 for c in crosses) or all(c < 0 for c in crosses)):
            raise ValueError("detector quadrilateral must be nondegenerate and convex")
        envelope = (min(p[0] for p in points), min(p[1] for p in points),
                    max(p[0] for p in points), max(p[1] for p in points))
        # The probe boxes are axis-aligned envelopes of these same corners.
        if any(abs(a - b) > 2.0 for a, b in zip(envelope, box)):
            raise ValueError("polygon and box envelopes disagree")
        corners.append(tuple(points))
    return clean, corners


def _normalized_geometry(boxes, polygons, width, height):
    diagnostic = {"source": "axis_aligned_boxes", "angle_degrees": 0.0,
                  "angle_evidence_count": 0, "angle_inlier_count": 0}
    if polygons is None:
        return boxes, diagnostic
    angles = []
    for poly in polygons:
        top, bottom = ((poly[0], poly[1]), (poly[3], poly[2]))
        edge_angles = []
        for a, b in (top, bottom):
            dx, dy = b[0] - a[0], b[1] - a[1]
            if dx <= 0:
                continue
            angle = math.atan2(dy, dx)
            if abs(math.degrees(angle)) <= MAX_SKEW_DEGREES:
                edge_angles.append(angle)
        edge_width = math.dist(*top)
        line_height = (math.dist(poly[0], poly[3]) + math.dist(poly[1], poly[2])) / 2
        if (len(edge_angles) == 2 and edge_width >= 4 * line_height
                and abs(edge_angles[0] - edge_angles[1]) <= math.radians(2)):
            angles.append(sum(edge_angles) / 2)
    diagnostic["angle_evidence_count"] = len(angles)
    if len(angles) < 4:
        diagnostic["source"] = "quadrilaterals_insufficient_angle_evidence"
        return boxes, diagnostic
    angle = median(angles)
    inliers = [a for a in angles if abs(a - angle) <= math.radians(2)]
    diagnostic["angle_inlier_count"] = len(inliers)
    if len(inliers) < .75 * len(angles):
        diagnostic["source"] = "quadrilaterals_inconsistent_angles"
        return boxes, diagnostic
    angle = median(inliers)
    cosine, sine = math.cos(angle), math.sin(angle)
    cx, cy = width / 2, height / 2
    normalized = []
    for poly in polygons:
        points = [((x - cx) * cosine + (y - cy) * sine + cx,
                   -(x - cx) * sine + (y - cy) * cosine + cy) for x, y in poly]
        normalized.append((min(p[0] for p in points), min(p[1] for p in points),
                           max(p[0] for p in points), max(p[1] for p in points)))
    diagnostic.update(source="quadrilaterals_robust_page_angle",
                      angle_degrees=round(math.degrees(angle), 6))
    return normalized, diagnostic


def _bands(boxes, line_height, height):
    groups, group, bottom = [], [], -math.inf
    threshold = max(4 * line_height, .05 * height)
    for i in sorted(range(len(boxes)), key=lambda i: (boxes[i][1], boxes[i][0], i)):
        if group and boxes[i][1] - bottom > threshold:
            groups.append(group)
            group = []
            bottom = -math.inf
        group.append(i)
        bottom = max(bottom, boxes[i][3])
    if group:
        groups.append(group)
    return groups


def _line_order(indices, boxes, line_height):
    """Top-to-bottom lines; fragments on one baseline read left-to-right."""
    rows, row = [], []
    for i in sorted(indices, key=lambda i: ((boxes[i][1] + boxes[i][3]) / 2,
                                             boxes[i][0], i)):
        center = (boxes[i][1] + boxes[i][3]) / 2
        if row and center - median((boxes[j][1] + boxes[j][3]) / 2 for j in row) > .45 * line_height:
            rows.append(row)
            row = []
        row.append(i)
    if row:
        rows.append(row)
    return [i for row in rows for i in sorted(row, key=lambda j: (boxes[j][0], j))]


def _candidate(cut, indices, evidence, boxes, width, line_height):
    left = [i for i in evidence if boxes[i][2] <= cut]
    right = [i for i in evidence if boxes[i][0] >= cut]
    if min(len(left), len(right)) < 4 or min(len(left), len(right)) < .30 * max(len(left), len(right)):
        return None
    extents = [(min(boxes[i][0] for i in side), max(boxes[i][2] for i in side),
                min(boxes[i][1] for i in side), max(boxes[i][3] for i in side))
               for side in (left, right)]
    if min(e[1] - e[0] for e in extents) < .20 * width:
        return None  # Parallel short labels are not substantial text columns.
    overlap = min(e[3] for e in extents) - max(e[2] for e in extents)
    if overlap < 4 * line_height or overlap < .60 * max(e[3] - e[2] for e in extents):
        return None
    gutter = (max(boxes[i][2] for i in left), min(boxes[i][0] for i in right))
    if gutter[1] - gutter[0] < max(.008 * width, .35 * line_height):
        return None
    crossing = [i for i in indices if boxes[i][0] < cut < boxes[i][2]]
    crossing_set = set(crossing)
    column = [i for i in indices if i not in crossing_set]
    for i in crossing:
        # An isolated line can separate page zones, irrespective of whether the
        # heading is full-page width. It must not overlap text beside the gutter.
        if boxes[i][2] - boxes[i][0] < .18 * width:
            return None
        if any(min(boxes[i][3], boxes[j][3]) - max(boxes[i][1], boxes[j][1]) > .20 * line_height
               for j in column):
            return None
    return {"cut": cut, "gutter": gutter, "left": left, "right": right,
            "crossing": crossing, "column": column,
            "overlap_ratio": overlap / max(e[3] - e[2] for e in extents)}


def _band_order(indices, boxes, width, line_height):
    evidence = [i for i in indices
                if .08 * width <= boxes[i][2] - boxes[i][0] <= .65 * width
                and .4 * line_height <= boxes[i][3] - boxes[i][1] <= 3 * line_height]
    diagnostic = {"box_count": len(indices), "evidence_count": len(evidence)}
    if len(evidence) < 8:
        return None, "insufficient_two_column_evidence", diagnostic
    # Bounded grid includes narrow gutters; candidate intervals are assessed
    # against exact box edges, so no pixel quantization is applied to the output.
    step = width / 200
    candidates = []
    for n in range(40, 161):
        candidate = _candidate(n * step, indices, evidence, boxes, width, line_height)
        if candidate is not None:
            candidates.append(candidate)
    if not candidates:
        return None, "no_supported_two_column_gutter", diagnostic
    clusters = []
    for candidate in candidates:
        if not clusters or candidate["cut"] - clusters[-1][-1]["cut"] > 1.5 * step:
            clusters.append([])
        clusters[-1].append(candidate)
    diagnostic["qualifying_gutter_count"] = len(clusters)
    if len(clusters) != 1:
        return None, "multiple_gutters_or_three_columns", diagnostic
    supported = clusters[0]
    candidate = supported[len(supported) // 2]
    cut = candidate["cut"]
    diagnostic.update(gutter=list(candidate["gutter"]), cut=cut,
                      left_evidence_count=len(candidate["left"]),
                      right_evidence_count=len(candidate["right"]),
                      vertical_overlap_ratio=round(candidate["overlap_ratio"], 6),
                      isolated_spanning_count=len(candidate["crossing"]))
    anchors = _line_order(candidate["crossing"], boxes, line_height)
    remaining = set(candidate["column"])
    order = []

    def append_zone(zone):
        order.extend(_line_order([i for i in zone if boxes[i][2] <= cut], boxes, line_height))
        order.extend(_line_order([i for i in zone if boxes[i][0] >= cut], boxes, line_height))

    for anchor in anchors:
        zone = {i for i in remaining if boxes[i][3] <= boxes[anchor][1]}
        append_zone(zone)
        remaining -= zone
        order.append(anchor)
    append_zone(remaining)
    if sorted(order) != sorted(indices):
        return None, "ambiguous_unassigned_geometry", diagnostic
    return order, "supported_skew_normalized_two_column_gutter", diagnostic


def reading_order(boxes, width, height, polygons=None):
    """Return a complete index permutation using geometry only.

    ``polygons`` is optional and has the same length as ``boxes``; each item is
    the detector's TL, TR, BR, BL four corners. Input boxes and polygons are never
    mutated. Failed evidence returns the original permutation, with diagnostics.
    """
    boxes, polygons = _validate(boxes, width, height, polygons)
    original = list(range(len(boxes)))
    normalized, normalization = _normalized_geometry(boxes, polygons, width, height)
    base = {"schema": 2, "algorithm": ALGORITHM, "order": original,
            "diagnostic": {"geometry_only": True, "text_read": False,
                           "box_count": len(boxes), "normalization": normalization,
                           "bands": []}}
    if len(boxes) < 8:
        return {**base, "status": "abstained", "reason": "too_few_boxes"}
    line_height = median(box[3] - box[1] for box in normalized)
    groups = _bands(normalized, line_height, height)
    base["diagnostic"].update(median_line_height=line_height, horizontal_band_count=len(groups))
    order, changed_bands = [], 0
    for group in groups:
        result, reason, diagnostic = _band_order(group, normalized, width, line_height)
        base["diagnostic"]["bands"].append({**diagnostic, "reason": reason})
        if reason in {"multiple_gutters_or_three_columns", "ambiguous_unassigned_geometry"}:
            return {**base, "status": "abstained", "reason": reason}
        if result is None:
            order.extend(sorted(group))
        else:
            order.extend(result)
            changed_bands += 1
    if not changed_bands:
        return {**base, "status": "abstained", "reason": "no_confident_two_column_band"}
    if sorted(order) != original:
        raise AssertionError("layout output must be a complete permutation")
    return {**base, "order": order, "status": "unchanged" if order == original else "reordered",
            "reason": "supported_skew_normalized_two_column_gutter"}
