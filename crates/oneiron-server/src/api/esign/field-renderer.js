"use strict";
// A small SVG/DOM adapter. All geometry, marks, typography, and controls come
// from the Rust presentation model used by PDF export. It never interprets HTML.
const EsignFieldRenderer = (() => {
  const svgNS = "http://www.w3.org/2000/svg";
  function svg(name, attrs) { const node = document.createElementNS(svgNS, name); for (const [k,v] of Object.entries(attrs)) node.setAttribute(k, String(v)); return node; }
  function control(presentation, save) {
    const row = document.createElement("label");
    row.style.display = "block";
    row.append(document.createTextNode(`${presentation.control.kind}${presentation.required ? " (required)" : ""} · page ${presentation.geometry.page} `));
    const kind = presentation.control.kind;
    const input = document.createElement(kind === "select" ? "select" : "input");
    if (kind === "select") {
      const placeholder = document.createElement("option"); placeholder.value = ""; placeholder.textContent = "Select…"; placeholder.disabled = true; input.append(placeholder);
      for (const value of presentation.control.options) { const option = document.createElement("option"); option.value = value; option.textContent = value; input.append(option); }
    } else input.type = kind === "signature" ? "file" : kind === "checkbox" ? "checkbox" : "text";
    if (kind === "signature") input.accept = "image/png,image/jpeg";
    if (kind === "checkbox") input.checked = presentation.value?.value === true;
    else if (kind !== "signature") input.value = presentation.value?.value || "";
    input.readOnly = presentation.control.server_computed === true;
    input.required = presentation.required;
    input.addEventListener("change", () => save(input, presentation));
    row.append(input); return {row, input};
  }
  function pageBox(page) {
    const [l,b,r,t] = page.crop;
    if (page.rotation === 0 && page.user_unit === 1) return [l,b,r,t];
    return [0,0,(page.rotation % 180 ? t-b : r-l)*page.user_unit,(page.rotation % 180 ? r-l : t-b)*page.user_unit];
  }
  function preview(container, model, imageURL = () => null) {
    container.replaceChildren();
    model.pages.forEach((page, index) => {
      const [l,b,r,t] = pageBox(page);
      const drawing = svg("svg", {viewBox: `${l} ${-t} ${r-l} ${t-b}`, role:"img", "aria-label":`Field positions on page ${index+1}`});
      drawing.style.cssText = "width:100%;max-width:600px;border:1px solid #777;background:white;display:block";
      for (const field of model.fields.filter(f => f.presentation.geometry.page === index+1)) {
        const rect = field.rect;
        drawing.append(svg("rect", {x:rect.x,y:-rect.y-rect.height,width:rect.width,height:rect.height,fill:"none",stroke:"#777","stroke-width":0.5}));
        for (const mark of field.marks) {
          let node;
          if (mark.kind === "text") { node = svg("text", {x:mark.x,y:-mark.y,"font-family":"Courier New,monospace","font-size":mark.size,fill:"black"}); node.textContent = mark.value; }
          if (mark.kind === "rectangle") node = svg("rect", {x:mark.x,y:-mark.y-mark.height,width:mark.width,height:mark.height,fill:"none",stroke:"black","stroke-width":1});
          if (mark.kind === "line") node = svg("line", {x1:mark.x1,y1:-mark.y1,x2:mark.x2,y2:-mark.y2,stroke:"black","stroke-width":1});
          if (mark.kind === "signature") { const url=imageURL(mark.image_ref); if (url) node=svg("image", {href:url,x:mark.rect.x,y:-mark.rect.y-mark.rect.height,width:mark.rect.width,height:mark.rect.height,preserveAspectRatio:"xMidYMid meet"}); }
          if (node) drawing.append(node);
        }
      }
      container.append(drawing);
    });
  }
  return {control, preview};
})();
