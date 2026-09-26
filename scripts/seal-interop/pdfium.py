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

def gap_is_signature_contents(data, b, c, end, sig, raw):
 # The excluded bytes must be the *same signature object's* hex /Contents,
 # not simply any gap in a parseable signed prefix. PDFium supplies its
 # decoded contents; the raw gap supplies the exact on-disk boundaries.
 if not re.search(rb"/Contents[ \t\n\f\r\x00]*$", data[max(0,b-64):b]):
  return False
 gap=data[b:c]
 encoded=re.fullmatch(rb"<([0-9a-fA-F \t\n\f\r\x00]+)>", gap)
 if not encoded:
  return False
 hex_bytes=re.sub(rb"[ \t\n\f\r\x00]", b"", encoded.group(1))
 if not hex_bytes or len(hex_bytes)%2:
  return False
 size=raw.FPDFSignatureObj_GetContents(sig,None,0)
 if size!=len(hex_bytes)//2:
  return False
 contents=(ctypes.c_ubyte*size)()
 if raw.FPDFSignatureObj_GetContents(sig,contents,size)!=size:
  return False
 decoded=bytes(contents)
 if decoded!=bytes.fromhex(hex_bytes.decode("ascii")):
  return False
 # Reject ambiguous copies even if the hex blob uses different case or
 # whitespace. The one matching /Contents string must occupy exactly this gap.
 matches=0
 for item in re.finditer(rb"/Contents[ \t\n\f\r\x00]*(<([0-9a-fA-F \t\n\f\r\x00]+)>)", data[:end]):
  candidate=re.sub(rb"[ \t\n\f\r\x00]", b"", item.group(2))
  if len(candidate)==len(hex_bytes) and bytes.fromhex(candidate.decode("ascii"))==decoded:
   matches+=1
   if item.span(1)!=(b,c):
    return False
 return matches==1

try:
 raw=pdfium.raw
 with open(sys.argv[1],"rb") as f: data=f.read()
 doc=pdfium.PdfDocument(sys.argv[1])
 required=("FPDF_GetSignatureCount","FPDF_GetSignatureObject","FPDFSignatureObj_GetByteRange","FPDFSignatureObj_GetContents")
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
  # Both signed spans must contain bytes. A matching ByteRange in the
  # parsed revision does not itself prove that the revision was signed.
  well_formed=(a==0 and b>0 and c>b and d>0 and end<=len(data)
               and data[:end].rstrip(b"\0\t\n\f\r ").endswith(b"%%EOF")
               and gap_is_signature_contents(data,b,c,end,sig,raw))
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
