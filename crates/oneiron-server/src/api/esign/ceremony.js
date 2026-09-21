"use strict";
const token = location.hash.slice(1);
history.replaceState(null, "", location.pathname);
const status = document.getElementById("status");
const fields = document.getElementById("fields");
async function post(path, value) {
  const response = await fetch(path, {method: "POST", credentials: "omit", cache: "no-store", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token, ...value})});
  if (!response.ok) throw new Error("The signing request is unavailable. Reopen the invitation or contact its sender.");
  return response;
}
async function action(value) {
  const result = await (await post("/sign/action", {action: value})).json();
  if (result.data?.item_count) {
    const select = document.getElementById("item");
    if (select.options.length !== result.data.item_count) {
      select.replaceChildren();
      for (let i = 0; i < result.data.item_count; i++) { const option = document.createElement("option"); option.value = i; option.textContent = `PDF ${i + 1}`; select.append(option); }
    }
  }
  if (result.outcome !== "page") { status.textContent = result.data?.status || result.outcome.replaceAll("_", " "); return result; }
  status.textContent = "Changes are saved as you fill each field.";
  document.getElementById("title").textContent = result.data.title;
  return result;
}
function report(error) { status.textContent = error.message; }
const imageURLs = new Map();
async function refreshPreview() {
  const model = await (await post("/sign/preview", {item:Number(document.getElementById("item").value || 0)})).json();
  for (const field of model.fields) {
    for (const mark of field.marks) {
      if (mark.kind === "signature" && !imageURLs.has(mark.image_ref)) {
        const response = await post("/sign/signature", {image_ref:mark.image_ref});
        imageURLs.set(mark.image_ref, URL.createObjectURL(await response.blob()));
      }
    }
  }
  EsignFieldRenderer.preview(document.getElementById("preview"), model, ref => imageURLs.get(ref));
}
async function start() {
  const result = await action({action:"load"});
  if (result.outcome !== "page") return;
  for (const presentation of result.data.presentations) {
    const save = async input => {
      try {
        let next;
        if (presentation.control.kind === "signature") {
          const file=input.files[0]; if (!file) return;
          if (file.size>2*1024*1024) throw new Error("Use a PNG or JPEG image under 2 MiB.");
          const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=reject;reader.readAsDataURL(file);});
          const image=await (await post("/sign/image",{png_or_jpeg_base64:data.split(",")[1]})).json();
          next={kind:"signature",value:{image_ref:image.image_ref}};
        } else next=presentation.control.kind==="checkbox"?{kind:"checked",value:input.checked}:{kind:"text",value:input.value};
        const saved=await action({action:"save_field",field:presentation.id,value:next});
        const actual=saved.data?.values?.[presentation.id]?.value;
        if (actual?.kind==="text") input.value=actual.value;
        await refreshPreview();
      } catch (error) {report(error);}
    };
    const {row,input}=EsignFieldRenderer.control(presentation,save);fields.append(row);
    if (presentation.control.server_computed && !presentation.value) await save(input);
  }
  await refreshPreview();
}
document.getElementById("item").onchange=()=>refreshPreview().catch(report);
window.addEventListener("pagehide",()=>{for(const url of imageURLs.values())URL.revokeObjectURL(url);imageURLs.clear();});
document.getElementById("complete").onclick = () => action({action: "complete", consent: document.getElementById("consent").checked, next: null}).catch(report);
document.getElementById("reject").onclick = () => { const reason = prompt("Reason for rejection"); if (reason !== null) { const text = reason.trim(); if (!text || new TextEncoder().encode(text).length > 4096) { status.textContent = "Give a non-empty reason of at most 4096 bytes."; return; } action({action: "reject", reason: text}).catch(report); } };
document.getElementById("download").onclick = async () => { try { const response = await post("/sign/pdf", {item: Number(document.getElementById("item").value || 0)}); const url = URL.createObjectURL(await response.blob()); const link = document.createElement("a"); link.href = url; link.download = `document-${Number(document.getElementById("item").value || 0) + 1}.pdf`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (error) { report(error); } };
start().catch(report);
