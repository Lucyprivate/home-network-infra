"""Pinned OCRmyPDF17.13 fpdf2 bounded em-calibration adapter for Paddle lines.

No model or transcription change. Native font selection, glyph encoding, spacing,
BT emission and invisible rendering remain upstream. A bounded 1.15 font-em calibration was chosen on consumed development outputs,
not claimed as an outline/ink measurement. Native words retain their measured
horizontal extents and baseline positions. The replacement is
line/word geometry derived from actual projected polygon vertices, avoiding an
axis-aligned bbox being inverse-rotated a second time. No image/page hook exists.
Installation is explicit and source-pinned; unmarked Tesseract rows use upstream.
"""
from __future__ import annotations
import hashlib,math,threading,types
from pathlib import Path
GEOMETRY_SHA='cf0708101fe1ff50e4bb2353c6fe6897be8b5ebbe64cfdad1c31e1f2482e8f65'
UPSTREAM_SHA='fea1ea214520cf0aa82cfec8ffed23441516e539376bfd15400c00639e605106'
MARKER='stirling-paddle-calibrated-v5'
FONT_EM_CALIBRATION=1.15
_lock=threading.RLock()
_installed=None


def render_marked(native,geometry,renderer,pdf,line):
    if not renderer.invisible_text:raise RuntimeError('Paddle calibrated5 only renders invisible text.')
    if line.poly is None or line.textangle is None:raise RuntimeError('Paddle calibrated5 requires actual polygon and crop direction.')
    convert=renderer.coord_transform.px_to_pt
    points=[(convert(x),convert(y))for x,y in line.poly]
    frame=geometry.frame(points,line.textangle,normalize_font=False)
    size=frame['height']*FONT_EM_CALIBRATION # Explicit bounded development calibration; not font-metric measurement.
    bx,by=frame['baseline_origin']
    matrix=native.Matrix().translated(bx,by).rotated(-line.textangle)
    words=[]
    for word in line.children:
        if word.ocr_class!=native.OcrClass.WORD or not word.text:continue
        if word.poly is None:raise RuntimeError('Paddle calibrated5 word polygon is required.')
        extent=geometry.word_extent([(convert(x),convert(y))for x,y in word.poly],frame,tolerance=min(4.,convert(2*math.sqrt(2))))
        manager=renderer.multi_font_manager.select_font_for_word(word.text,line.language)
        family=renderer._register_font(pdf,manager);pdf.set_font(family,size=size)
        rtl=renderer.invisible_text and native._is_rtl_text(word.text)
        shaped=not renderer.invisible_text or (not rtl and native._needs_complex_shaping(word.text))
        if shaped:natural=pdf.get_string_width(word.text)
        else:
            saved=pdf.text_shaping
            try:pdf.text_shaping=None;natural=pdf.get_string_width(word.text)
            finally:pdf.text_shaping=saved
        scale=extent['width']/natural*100 if natural>0 else 100.
        words.append(native.WordRenderData(text=word.text,x_baseline=extent['x_baseline'],font_family=family,
            word_tz=scale,is_rtl=rtl,shaped=shaped,width=extent['width']))
    if words:renderer._emit_line_bt_block(pdf,words,matrix,size,-line.textangle)


def install(source_loader,expected_source_sha256):
    """Call in CLI/main and workers; source_loader must verify fixed source hash."""
    global _installed
    if not isinstance(expected_source_sha256,str) or len(expected_source_sha256)!=64 or any(c not in '0123456789abcdef' for c in expected_source_sha256):
        raise RuntimeError('Renderer5 requires an explicit frozen own-source SHA256.')
    import ocrmypdf.fpdf_renderer.renderer as native
    with _lock:
        source_loader(Path(native.__file__),UPSTREAM_SHA)
        data=source_loader(Path(__file__).absolute().with_name('paddle_geometry4.py'),GEOMETRY_SHA)
        if _installed is not None:
            if native.Fpdf2PdfRenderer._render_line is not _installed:raise RuntimeError('Renderer changed after calibrated5 installation.')
            return
        original=native.Fpdf2PdfRenderer._render_line
        if getattr(original,'_stirling_quad5_source_sha256',None)==expected_source_sha256:
            # A fork inherits the already-patched class but may reload this
            # adapter in a new PID. Reuse the exact pinned inherited method.
            source_loader(Path(original.__globals__['__file__']),expected_source_sha256)
            _installed=original;return
        if original.__module__!=native.__name__ or original.__qualname__!='Fpdf2PdfRenderer._render_line':
            raise RuntimeError('Unreviewed renderer override already installed.')
        geometry=types.ModuleType('_stirling_calibrated5_geometry_'+GEOMETRY_SHA)
        geometry.__file__=str(Path(__file__).absolute().with_name('paddle_geometry4.py'))
        exec(compile(data,geometry.__file__,'exec'),geometry.__dict__)
        def marked(self,pdf,line):
            if getattr(line,'_stirling_quad_renderer',None)!=MARKER:return original(self,pdf,line)
            return render_marked(native,geometry,self,pdf,line)
        marked._stirling_quad5_source_sha256=expected_source_sha256
        native.Fpdf2PdfRenderer._render_line=marked
        _installed=marked
