# PaddleX source references for paddle_probe.py

Upstream: https://github.com/PaddlePaddle/PaddleX/tree/v3.7.0
License: Apache-2.0; full upstream LICENSE is included here.
Copyright (c) 2024 PaddlePaddle Authors.
The upstream reference modules are not redistributed or imported by the adapter.
The complete Apache-2.0 license is in PaddleX-LICENSE.

## Adapted operations

`../paddle_probe.py` adapts these limited operations from PaddleX v3.7.0:

| Upstream module | Adapted behavior |
| --- | --- |
| `text_detection_predictor.py` | `PP-OCRv6_tiny_det` uses `max-side=960` by default. |
| `text_detection_processors.py` | `DetResizeForTest`, BGR `NormalizeImage`, and the quad/fast score path in `DBPostProcess`. The model's exact `inference.yml` sets probability threshold 0.2, box threshold 0.4, unclip ratio 1.4, and max candidates 3000. No dilation, polygon mode, slow score, table, or VL processing. |
| `sort_boxes.py` | The unchanged original-pixel ten-pixel comparator from `SortQuadBoxes`. |
| `crop_image_regions.py` | The min-area quad perspective crop and vertical-line rotation from `CropByPolys`. Only one original-resolution line crop exists at a time. No all-crop list or angle-classifier model. |
| `text_recognition_processors.py` | `OCRReisizeNormImg`, batch one, BGR, height 48, and padded width from 320 to 3200. `CTCLabelDecode` uses blank-first decoding and the dictionary from the checked official YAML plus a space. No language conversion, extra softmax, spelling correction, or text substitution. |
| `ocr_pipeline.py` | Detector line sort and line-text correspondence. Recognition runs sequentially instead of ratio batches. Final lines retain the official detector order. Blank-only CTC output stays an empty string. |

## Defensive changes

- Module import needs only the Python standard library. Construction imports optional CPU libraries.
- Pinned ONNX/YAML SHA256 checks and bounded reads reject symbolic links and non-regular files. Sessions receive the checked ONNX bytes. They do not read a path after the hash check.
- Execution uses `CPUExecutionProvider` only. ORT runs sequentially with one intra/inter thread and no spinning. OpenCV uses one thread. BLAS/OpenMP thread variables use one.
- Input permits PNG/JPEG only. Limits are <=64MiB encoded, <=100 million pixels, and <=20000 per dimension. The dimension cap prevents upstream int16 quadrilateral overflow. These bounds do not guarantee that every maximum-size input fits in deployment memory.
- Empty or degenerate geometry and malformed or nonfinite model output fail closed.
- No implicit downloads, subprocesses, network clients, or hidden Tesseract fallback.
- Raw text output requires CLI `--public-synthetic` and exclusive mode600 outputs.

## Known limits

`SortQuadBoxes` uses row-major order, not semantic reading order.
Double-column pages can interleave columns.
The adapter applies no GT-driven or semantic correction.

Output geometry describes lines. It does not infer characters or individual words.
It does not model paragraph, table, heading, or document orientation semantics.
Outer OCRmyPDF/Tesseract can supply requested deskew and orientation.

The standalone adapter does not enforce the overall 900-second process-group deadline or total cgroup memory limit.
The orchestrator must retain those guards, the one-job lock, and the original clean/deskew controls.
Model size does not estimate RAM use.
Real A4 runtime and RSS need deployment acceptance tests.
These sources and local tests do not establish accuracy or performance.

## Offline assets

The adapter expects these files:

```text
det/inference.onnx
det/inference.yml
rec/inference.onnx
rec/inference.yml
```

`paddle_probe.MODEL_PINS` holds the four SHA256 constants.
The upstream asset receipt also preserves `inference.json`.
The adapter does not read that file.
See `../../assets/models.lock.json` for immutable official model commit pins.
