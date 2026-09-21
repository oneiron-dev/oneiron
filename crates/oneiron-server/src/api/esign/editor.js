"use strict";
let pack = {schema_version:1,fields:[]}, pages = [];
const message = document.getElementById("status");
async function renderEditor() {
  if (!pages.length) return;
  const selected=pack.fields.filter(f=>f.item===Number(document.getElementById("current-item").value));
  const response = await fetch("/sign/layout", {method:"POST",credentials:"omit",cache:"no-store",headers:{"Content-Type":"application/json"},body:JSON.stringify({fields:selected,values:{},pages})});
  if (!response.ok) throw new Error("The geography pack is invalid for this PDF.");
  const model = await response.json();
  EsignFieldRenderer.preview(document.getElementById("preview"),model);
  const rows = document.getElementById("fields"); rows.replaceChildren();
  model.fields.forEach((layout,index) => {
    const field = selected[index], row = document.createElement("fieldset"), legend = document.createElement("legend");
    legend.textContent = `${layout.presentation.control.kind} · ${field.id}`; row.append(legend);
    for (const key of ["page","x_percent","y_percent","width_percent","height_percent"]) {
      const label = document.createElement("label");label.append(document.createTextNode(`${key} `));
      const input = document.createElement("input");input.type="number";input.step=key==="page"?"1":"0.1";input.value=field.geometry[key];
      input.onchange=async()=>{const old=field.geometry[key];field.geometry[key]=Number(input.value);try{await renderEditor();}catch(error){field.geometry[key]=old;input.value=old;message.textContent=error.message;}};
      label.append(input);row.append(label);
    }
    const remove=document.createElement("button"); remove.textContent="Remove field";
    remove.onclick=()=>{pack.fields=pack.fields.filter(candidate=>candidate.id!==field.id);renderEditor().catch(error=>message.textContent=error.message);};
    row.append(remove);rows.append(row);
  });
}
document.getElementById("pdf-file").onchange=async event=>{try{const file=event.target.files[0];if(!file)return;if(file.size>16*1024*1024)throw new Error("This browser upload is limited to 16 MiB.");const response=await fetch("/sign/geometry",{method:"POST",credentials:"omit",cache:"no-store",body:file});if(!response.ok)throw new Error("Cannot inspect this PDF safely.");pages=(await response.json()).pages;await renderEditor();}catch(error){message.textContent=error.message;}};
document.getElementById("pack-file").onchange=async event=>{try{const file=event.target.files[0];if(!file)return;if(file.size>1024*1024)throw new Error("Pack is too large.");const candidate=JSON.parse(await file.text());if(candidate.schema_version!==1||!Array.isArray(candidate.fields))throw new Error("Invalid geography pack.");pack=candidate;await renderEditor();}catch(error){message.textContent=error.message;}};
document.getElementById("save").onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(pack,null,2)],{type:"application/json"}));const link=document.createElement("a");link.href=url;link.download="field-geography.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};

document.getElementById("current-item").onchange=()=>renderEditor().catch(error=>message.textContent=error.message);
document.getElementById("add").onclick=async()=>{
  try {
    if (!pages.length) throw new Error("Load the PDF first.");
    const recipient=document.getElementById("recipient").value.trim();
    if (!/^[0-9a-f]{32}$/.test(recipient)) throw new Error("Use a canonical recipient reference from the document.");
    const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");
    const kind=document.getElementById("field-kind").value;
    const meta=kind==="text"?{kind,max_bytes:4096}:kind==="select"?{kind,options:document.getElementById("select-options").value.split("\n").map(value=>value.trim()).filter(Boolean)}:{kind};
    if(kind==="select" && (!meta.options.length || meta.options.length>256 || new Set(meta.options).size!==meta.options.length)) throw new Error("Give 1–256 distinct select options, one per line.");
    pack.fields.push({id,item:Number(document.getElementById("current-item").value),recipient,required:true,geometry:{page:1,x_percent:10,y_percent:10,width_percent:30,height_percent:8},meta});
    await renderEditor();
  } catch(error) {message.textContent=error.message;}
};
