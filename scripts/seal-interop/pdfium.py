#!/usr/bin/env python3
"""PDFium structural parse: each signature covers its own signed revision.
No CMS cryptography, later-change policy, or certificate trust check is performed.
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
 ends=[]
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
  end=c+d
  well_formed=(a==0 and b>=0 and c>=b and d>=0 and end<=len(data)
               and data[:end].rstrip(b"\0\t\n\f\r ").endswith(b"%%EOF"))
  if not well_formed:
   covers.append(False); continue
  # Parse the exact signed prefix and find this ByteRange in that revision.
  # Do not confuse an earlier, complete revision with the final file EOF.
  revision=pdfium.PdfDocument(data[:end])
  try:
   revision_ranges=[]
   for j in range(int(raw.FPDF_GetSignatureCount(revision.raw))):
    item=raw.FPDF_GetSignatureObject(revision.raw,j)
    if not item:
     revision_ranges=[]; break
    values=(ctypes.c_int*4)()
    raw.FPDFSignatureObj_GetByteRange(item,values,4)
    revision_ranges.append([int(values[k]) for k in range(4)])
   covers.append(vals in revision_ranges)
  finally:
   revision.close()
  ends.append(end)
 pages=len(doc); doc.close()
 if not all(covers): result("fail",f"pages={pages}; signature_objects={count}; signed_revision_coverage={covers}",1)
 final_coverage=max(ends)==len(data)
 result("pass",f"pages={pages}; signature_objects={count}; signatures={count}; signed_revision_coverage=true; final_document_coverage={str(final_coverage).lower()}; later revisions are not a permitted-change assessment; no CMS cryptography or certificate trust check",0)
except SystemExit: raise
except Exception as e:
 result("fail",f"{type(e).__name__}: {e}",1)
