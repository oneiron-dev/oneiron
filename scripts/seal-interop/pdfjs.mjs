#!/usr/bin/env node
// pdf.js parse-only wrapper. Reads one local PDF and reports the page count.
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
 const bytes=Buffer.from(fs.readFileSync(process.argv[2]));
 const data=Uint8Array.from(bytes);
 const task=pdfjs.getDocument({data,disableFontFace:true,useSystemFonts:false,isEvalSupported:false});
 const doc=await task.promise;
 const fields=await doc.getFieldObjects();
 const sigs=Object.values(fields||{}).flat().filter(f=>String(f?.type||f?.fieldType||'').toLowerCase().includes('sig') || String(f?.fieldType||'').toLowerCase()==='signature');
 const ranges=[...bytes.toString('latin1').matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)].map(m=>m.slice(1).map(Number));
 const covers=ranges.length>0 && ranges.every(([a,b,c,d])=>a===0 && b>=0 && c>=b && d>=0 && c+d===bytes.length);
 if(!sigs.length || !covers) { console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'fail',detail:`pages=${doc.numPages}; signature_fields=${sigs.length}; byte_range_covers_file=${covers}; no signature cryptography performed`})); await doc.destroy(); process.exit(1); }
 console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'pass',detail:`pages=${doc.numPages}; signature_fields=${sigs.length}; byte_range_entries=${ranges.length}; byte_range_covers_file=true; no signature cryptography performed`}));
 await doc.destroy();
} catch(e) {
 console.log(JSON.stringify({reader:'pdfjs',version:pkg.version,mode:'parse',status:'fail',detail:`${e?.name||'Error'}: ${e?.message||e}`})); process.exit(1);
}
