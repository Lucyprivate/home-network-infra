"""Experimental exact-quad renderer geometry, not an installed OCR plugin.

Pure geometry only: source text, model scores, GT and service state are not inputs.
Unlike fpdf2's inverse axis-aligned bbox, this uses projected actual polygon
vertices, so a one-degree skew cannot inflate a 10pt line into a 30pt font.
The caller still needs a renderer integration and fresh independent qualification.
"""
from __future__ import annotations
import math

class UnsupportedGeometry(ValueError):pass

def require(v,message):
    if not v:raise UnsupportedGeometry(message)

def polygon(value):
    require(isinstance(value,(list,tuple)) and len(value)==4,'four_vertices_required')
    require(all(isinstance(p,(list,tuple)) and len(p)==2 and all(type(v) in (int,float) and math.isfinite(v)for v in p)for p in value),'finite_vertices_required')
    out=[(float(x),float(y))for x,y in value]
    cross=[]
    for i in range(4):
        a,b,c=out[i],out[(i+1)%4],out[(i+2)%4]
        cross.append((b[0]-a[0])*(c[1]-b[1])-(b[1]-a[1])*(c[0]-b[0]))
    require(all(v>0 for v in cross)or all(v<0 for v in cross),'strict_convex_quad_required')
    return out

def frame(poly,textangle_degrees,*,ascent=1.160,descent=-.288,normalize_font=False):
    points=polygon(poly)
    require(type(textangle_degrees) in (int,float) and math.isfinite(textangle_degrees) and -180<=textangle_degrees<=180,'trusted_finite_crop_angle_required')
    require(all(type(v) in (int,float) and math.isfinite(v)for v in (ascent,descent)) and 0<ascent<=3 and -2<=descent<0,'finite_font_metrics_required')
    theta=math.radians(textangle_degrees)
    u=(math.cos(theta),-math.sin(theta));v=(-u[1],u[0])
    uv=[(x*u[0]+y*u[1],x*v[0]+y*v[1])for x,y in points]
    lo_u,hi_u=min(p[0]for p in uv),max(p[0]for p in uv)
    lo_v,hi_v=min(p[1]for p in uv),max(p[1]for p in uv)
    width,height=hi_u-lo_u,hi_v-lo_v
    require(width>1e-6 and height>1e-6,'positive_oriented_extents_required')
    # Quad may be perspective-distorted but each long edge must still align
    # reasonably with the actual recognizer's declared text direction.
    best=max(abs((points[(i+1)%4][0]-points[i][0])*u[0]+(points[(i+1)%4][1]-points[i][1])*u[1])for i in range(4))
    require(best>=.80*width,'crop_angle_inconsistent_with_quad')
    require(type(normalize_font) is bool,'normalization_flag_must_be_boolean')
    size=height/(ascent-descent) if normalize_font else height
    baseline_v=hi_v+descent*size if normalize_font else hi_v
    baseline=(lo_u*u[0]+baseline_v*v[0],lo_u*u[1]+baseline_v*v[1])
    return {'schema':1,'u':u,'v':v,'u_min':lo_u,'u_max':hi_u,'v_min':lo_v,'v_max':hi_v,
        'width':width,'height':height,'font_size':size,'baseline_origin':baseline,
        'textangle_degrees':float(textangle_degrees),'geometry_source':'actual_quad_projection',
        'aabb_inverse_used':False,'font_metric_normalization':normalize_font,'text_read':False}

def word_extent(poly,line,*,tolerance=1e-6):
    require(type(tolerance) in (int,float) and math.isfinite(tolerance) and 0<=tolerance<=4,'bounded_projection_tolerance_required')
    points=polygon(poly);u,v=line['u'],line['v']
    uv=[(x*u[0]+y*u[1],x*v[0]+y*v[1])for x,y in points]
    left,right=min(p[0]for p in uv),max(p[0]for p in uv)
    top,bottom=min(p[1]for p in uv),max(p[1]for p in uv)
    require(line['u_min']-tolerance<=left<right<=line['u_max']+tolerance and line['v_min']-tolerance<=top<bottom<=line['v_max']+tolerance,'word_outside_oriented_line')
    return {'x_baseline':left-line['u_min'],'width':right-left,'top_offset':top-line['v_min'],
            'height':bottom-top,'geometry_source':'actual_quad_projection','aabb_width_used':False}
