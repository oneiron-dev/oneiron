#!/usr/bin/env node
// pdf.js parse-only wrapper. Finds signature fields but cannot expose their /V ByteRange.
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const home=process.env.SEAL_INTEROP_HOME || '/mnt/wd16/w8-build/seal-interop';
let pkg;
try { pkg=require(process.env.SEAL_PDFJS_PACKAGE_JSON || `${home}/npm/node_modules/pdfjs-dist/package.json`); }
catch(e) { console.log(JSON.stringify({reader:'pdfjs',version:'unavailable',mode:'parse',status:'unavailable',detail:String(e)})); process.exit(77); }
let pdfjs;
try { pdfjs=await import(process.env.SEAL_PDFJS_MODULE || `${home}/npm/node_modules/pdfjs-dist/legacy/build/pdf.mjs`); }
catch(e) { console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'unavailable',detail:String(e)})); process.exit(77); }
try {
 const data=new Uint8Array(fs.readFileSync(process.argv[2]));
 const task=pdfjs.getDocument({data,disableFontFace:true,useSystemFonts:false,isEvalSupported:false});
 const doc=await task.promise;
 const fields=await doc.getFieldObjects();
 const sigs=Object.values(fields||{}).flat().filter(f=>
   f?.type==='signature' || f?.fieldType==='signature' || f?.fieldType==='/Sig');
 // pdf.js does not expose each signature field's /V dictionary here. A raw
 // document-wide /ByteRange scan can be spoofed by unrelated comments or
 // streams, so this row makes no signed-byte coverage claim.
 if(!sigs.length) { console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'fail',detail:`pages=${doc.numPages}; signature_fields=0; ByteRange not inspected; no signature cryptography performed`})); await doc.destroy(); process.exit(1); }
 console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'pass',detail:`pages=${doc.numPages}; signature_fields=${sigs.length}; ByteRange not inspected; no signature cryptography performed`}));
 await doc.destroy();
} catch(e) {
 console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'fail',detail:`${e?.name||'Error'}: ${e?.message||e}`})); process.exit(1);
}
