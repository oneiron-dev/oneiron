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

def signature_source_offsets(path):
 # PDFium exposes decoded /Contents and ByteRange but no source offset or
 # signature dictionary reference. Use the pinned strict PDF parser for the
 # xref identity only; this is still a structural, not a CMS, check.
 from pyhanko.pdf_utils.reader import PdfFileReader
 from pyhanko.pdf_utils.generic import ByteStringObject
 with open(path,"rb") as stream:
  reader=PdfFileReader(stream,strict=True)
  sources=[]
  for signature in reader.embedded_signatures:
   ref=signature.sig_object.container_ref
   if ref is None:
    return []
   offset=reader.xrefs.get_historical_ref(ref,signature.signed_revision)
   source_value=signature.sig_object.raw_get("/Contents")
   if not isinstance(source_value,ByteStringObject):
    return []  # Indirect or non-hex contents: no proven source span.
   sources.append((tuple(signature.byte_range),bytes(source_value),
                   ref.idnum,ref.generation,offset))
  return sources

def contents_name(name):
 # PDF name escapes are legal: /Con#74ents is /Contents.
 def unescape(match):
  return bytes.fromhex(match.group(1).decode("ascii"))
 return re.sub(rb"#([0-9A-Fa-f]{2})",unescape,name)==b"Contents"

def gap_is_signature_contents(data,b,c,end,values,sig,raw,sources):
 size=raw.FPDFSignatureObj_GetContents(sig,None,0)
 if not size:
  return False
 contents=(ctypes.c_ubyte*size)()
 if raw.FPDFSignatureObj_GetContents(sig,contents,size)!=size:
  return False
 decoded=bytes(contents)
 # An equal blob elsewhere in the file cannot stand in for this signature.
 owners=[(obj,gen,offset) for rng,blob,obj,gen,offset in sources
         if rng==tuple(values) and blob==decoded]
 if len(owners)!=1:
  return False
 obj,gen,offset=owners[0]
 if not isinstance(offset,int) or not 0<=offset<b<c<=end:
  return False  # E.g. an object stream has no raw dictionary span here.
 header=re.match(rb"[ \t\n\f\r]*"+str(obj).encode()+rb"[ \t\n\f\r]+"
                 +str(gen).encode()+rb"[ \t\n\f\r]+obj\b",data[offset:])
 if not header:
  return False
 tail=re.search(rb"\bendobj\b",data[offset:end])
 if not tail or c>offset+tail.start():
  return False
 # Inspect only the xref-selected signature dictionary, never global text.
 # Accept a single direct hex value named /Contents (including PDF name
 # escapes), whose source span is precisely the excluded ByteRange interval.
 matches=[]
 region=data[offset+header.end():offset+tail.start()]
 for item in re.finditer(rb"/([A-Za-z0-9#]+)[ \t\n\f\r]*(<([0-9A-Fa-f \t\n\f\r]+)>)",region):
  if contents_name(item.group(1)):
   matches.append((offset+header.end()+item.start(2),
                   offset+header.end()+item.end(2),item.group(3)))
 if len(matches)!=1 or matches[0][:2]!=(b,c):
  return False
 hex_bytes=re.sub(rb"[ \t\n\f\r]",b"",matches[0][2])
 return bool(hex_bytes) and len(hex_bytes)%2==0 and bytes.fromhex(hex_bytes.decode("ascii"))==decoded

try:
 raw=pdfium.raw
 with open(sys.argv[1],"rb") as f: data=f.read()
 doc=pdfium.PdfDocument(sys.argv[1])
 try:
  sources=signature_source_offsets(sys.argv[1])
 except ModuleNotFoundError as e:
  doc.close(); result("unavailable","signature source parser unavailable: "+str(e),77)
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
               and gap_is_signature_contents(data,b,c,end,vals,sig,raw,sources))
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
