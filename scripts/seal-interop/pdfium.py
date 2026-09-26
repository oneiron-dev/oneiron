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

PDF_SPACE=b" \t\n\f\r\x00"
PDF_DELIMITERS=b"()<>[]{}/%"

def pdf_token(data,pos,limit):
 # Narrow PDF lexer for an xref-selected, direct signature dictionary.
 # Comments and literal strings are consumed as whole tokens, so neither
 # /Contents in a comment nor endobj in a string is structural syntax.
 while pos<limit:
  if data[pos] in PDF_SPACE:
   pos+=1; continue
  if data[pos]==37:  # % comment ends at the next line ending
   while pos<limit and data[pos] not in b"\r\n": pos+=1
   continue
  break
 if pos>=limit: return None
 start=pos
 if data.startswith(b"<<",pos): return ("dict_open",b"<<",start,pos+2)
 if data.startswith(b">>",pos): return ("dict_close",b">>",start,pos+2)
 ch=data[pos]
 if ch==40:  # balanced literal string, including escaped parentheses
  depth=1;pos+=1
  while pos<limit and depth:
   if data[pos]==92: pos+=2; continue
   if data[pos]==40: depth+=1
   elif data[pos]==41: depth-=1
   pos+=1
  return ("literal",data[start:pos],start,pos) if depth==0 else None
 if ch==60:  # hex string, not a dictionary
  close=data.find(b">",pos+1,limit)
  return ("hex",data[start:close+1],start,close+1) if close>=0 else None
 if ch==47:
  pos+=1
  while pos<limit and data[pos] not in PDF_SPACE+PDF_DELIMITERS: pos+=1
  return ("name",data[start+1:pos],start,pos)
 if ch in PDF_DELIMITERS:
  return ("delimiter",data[start:start+1],start,start+1)
 while pos<limit and data[pos] not in PDF_SPACE+PDF_DELIMITERS: pos+=1
 return ("word",data[start:pos],start,pos)

def signature_contents_span(data,offset,end,obj,gen):
 if not isinstance(offset,int) or not 0<=offset<end<=len(data): return None
 header=re.match(rb"[ \t\n\f\r]*"+str(obj).encode()+rb"[ \t\n\f\r]+"
                 +str(gen).encode()+rb"[ \t\n\f\r]+obj\b",data[offset:end])
 if not header: return None
 pos=offset+header.end()
 token=pdf_token(data,pos,end)
 if token is None or token[0]!="dict_open": return None
 pos=token[3];stack=["dict"];found=[]
 while stack:
  token=pdf_token(data,pos,end)
  if token is None: return None
  kind,value,begin,pos=token
  if kind=="dict_open": stack.append("dict")
  elif kind=="dict_close":
   if stack[-1]!="dict": return None
   stack.pop()
  elif kind=="delimiter" and value==b"[": stack.append("array")
  elif kind=="delimiter" and value==b"]":
   if stack[-1]!="array": return None
   stack.pop()
  elif stack==["dict"] and kind=="name" and contents_name(value):
   token=pdf_token(data,pos,end)
   if token is None or token[0]!="hex": return None
   found.append(token)
   pos=token[3]
 # A stream or unrelated token is not a direct signature dictionary end.
 terminator=pdf_token(data,pos,end)
 if terminator is None or terminator[:2]!=("word",b"endobj") or len(found)!=1:
  return None
 return found[0][2:4],found[0][1]

def gap_is_signature_contents(data,b,c,end,values,sig,raw,sources):
 size=raw.FPDFSignatureObj_GetContents(sig,None,0)
 if not size: return False
 contents=(ctypes.c_ubyte*size)()
 if raw.FPDFSignatureObj_GetContents(sig,contents,size)!=size: return False
 decoded=bytes(contents)
 owners=[(obj,gen,offset) for rng,blob,obj,gen,offset in sources
         if rng==tuple(values) and blob==decoded]
 if len(owners)!=1: return False
 obj,gen,offset=owners[0]
 source=signature_contents_span(data,offset,end,obj,gen)
 if source is None: return False
 span,encoded=source
 if span!=(b,c): return False
 hex_bytes=re.sub(rb"[ \t\n\f\r\x00]",b"",encoded[1:-1])
 return bool(hex_bytes) and len(hex_bytes)%2==0 and bool(re.fullmatch(rb"[0-9a-fA-F]+",hex_bytes)) and bytes.fromhex(hex_bytes.decode("ascii"))==decoded

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
