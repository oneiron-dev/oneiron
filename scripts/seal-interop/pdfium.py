#!/usr/bin/env python3
"""PDFium structural parse: require a signature object with ByteRange covering EOF.
No CMS cryptography or certificate trust check is performed.
"""
import ctypes, importlib.metadata, json, os, re, sys
try:
 import pypdfium2 as pdfium
except ModuleNotFoundError as e:
 print(json.dumps({"reader":"pdfium","version":"unavailable","mode":"parse","status":"unavailable","detail":str(e)})); raise SystemExit(77)
version=importlib.metadata.version("pypdfium2")
def result(status,detail,code):
 print(json.dumps({"reader":"pdfium","version":version,"mode":"parse","status":status,"detail":detail})); raise SystemExit(code)
try:
 raw=pdfium.raw
 with open(sys.argv[1],"rb") as f: data=f.read()
 doc=pdfium.PdfDocument(sys.argv[1])
 required=("FPDF_GetSignatureCount","FPDF_GetSignatureObject","FPDFSignatureObj_GetByteRange")
 missing=[name for name in required if not hasattr(raw,name)]
 if missing:
  doc.close(); result("unavailable","pypdfium2 binding lacks required signature API: "+", ".join(missing),77)
 count=int(raw.FPDF_GetSignatureCount(doc.raw))
 if count<1:
  doc.close(); result("fail",f"pages={len(doc)}; PDFium found no signature objects",1)
 covers=[]
 for idx in range(count):
  sig=raw.FPDF_GetSignatureObject(doc.raw,idx)
  if not sig: doc.close(); result("fail",f"signature object {idx} could not be read",1)
  buf=(ctypes.c_int*4)()
  n=raw.FPDFSignatureObj_GetByteRange(sig,buf,4)
  # Some generated ctypes declarations return void. In that case the populated
  # four-int array is the contract; otherwise require at least four values.
  vals=[int(buf[i]) for i in range(4)]
  if isinstance(n,int) and n not in (0,4):
   doc.close(); result("unavailable",f"unexpected PDFium ByteRange API length={n}",77)
  a,b,c,d=vals
  covers.append(a==0 and b>=0 and c>=b and d>=0 and c+d==len(data))
 pages=len(doc); doc.close()
 if not all(covers): result("fail",f"pages={pages}; signature_objects={count}; byte_range_covers_file={covers}",1)
 result("pass",f"pages={pages}; signature_objects={count}; byte_range_covers_file=true; no CMS cryptography or certificate trust check",0)
except SystemExit: raise
except Exception as e:
 result("fail",f"{type(e).__name__}: {e}",1)
