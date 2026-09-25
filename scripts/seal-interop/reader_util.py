#!/usr/bin/env python3
"""JSON wrappers for local Poppler/qpdf commands. No third-party deps."""
import json, os, platform, re, subprocess, sys
from pathlib import Path

def out(obj, code):
    print(json.dumps(obj, separators=(",", ":")))
    return code

def run(args, env=None):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

def version_text(command, env=None):
    p=run(command, env)
    return (p.stdout + p.stderr).splitlines()[0].strip() if p.stdout or p.stderr else "unknown"

def os_proxy():
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="): return f"linux-{arch}/" + line.split("=",1)[1].strip().strip('"')
    except OSError: pass
    return f"linux-{arch}"

def unavailable(reader, mode, detail):
    return out({"reader":reader,"version":"unavailable","os_proxy":os_proxy(),"mode":mode,"status":"unavailable","detail":detail},77)

def poppler(name, bindir, pdf):
    exe=os.path.join(bindir,"pdfsig")
    if not os.path.isfile(exe) or not os.access(exe,os.X_OK): return unavailable(name,"verify",f"pdfsig executable unavailable: {exe}")
    env=os.environ.copy()
    realbin=os.path.dirname(os.path.realpath(exe))
    prefix=os.path.dirname(realbin)
    libs=[os.path.join(prefix,"lib"),os.path.join(prefix,"lib64")]
    env["LD_LIBRARY_PATH"]=os.pathsep.join([p for p in libs if os.path.isdir(p)]+[env.get("LD_LIBRARY_PATH","")])
    vp=run([exe,"-v"],env); vers="unknown"
    text=vp.stdout+vp.stderr
    m=re.search(r"pdfsig version ([^\s]+)",text); vers=m.group(1) if m else name
    p=run([exe,pdf],env); combined=p.stdout+"\n"+p.stderr
    count=len(re.findall(r"Signature #\d+",combined))
    valids=len(re.findall(r"Signature Validation:\s*Signature is Valid\.?",combined,re.I))
    invalids=len(re.findall(r"Signature Validation:\s*Signature is (?:Invalid|Not Valid)",combined,re.I))
    ok=count>0 and valids==count and not invalids and p.returncode==0
    details=[]
    if count: details.append(f"signatures={count}, cryptographically_valid={valids==count}")
    else: details.append("no signature found")
    cert=[line.strip() for line in combined.splitlines() if "Certificate Validation:" in line]
    if cert: details.append("; ".join(cert))
    details.append("OS proxy is Linux; certificate trust is separate from signature integrity")
    obj={"reader":name,"version":vers,"os_proxy":os_proxy(),"mode":"verify","status":"pass" if ok else "fail","detail":"; ".join(details)}
    return out(obj,0 if ok else 1)

def qpdf(exe,pdf):
    if not exe or not os.path.isfile(exe) or not os.access(exe,os.X_OK): return unavailable("qpdf","check",f"qpdf executable unavailable: {exe}")
    v=run([exe,"--version"]); version_line=(v.stdout+v.stderr).splitlines()[0] if (v.stdout or v.stderr) else ""
    match=re.search(r"qpdf version ([^\s]+)",version_line); version=match.group(1) if match else "unknown"
    p=run([exe,"--check",pdf]); text=(p.stdout+"\n"+p.stderr).strip()
    if p.returncode==0: status="pass"; code=0
    elif p.returncode==3 and "WARNING" in text: status="warning"; code=0
    else: status="fail"; code=1
    if "Resources is missing or invalid" in text:
        detail="WARNING: source PDF has missing/invalid /Resources (inherited source-fixture defect); qpdf recovered; structural-clean status is not pass"
    else: detail=text[-1200:] if text else f"qpdf exit={p.returncode}"
    return out({"reader":"qpdf","version":version,"os_proxy":os_proxy(),"mode":"check","status":status,"detail":detail},code)

def main(argv):
    if len(argv)<3: print("usage: reader_util.py poppler NAME BINDIR PDF | qpdf EXE PDF | unavailable READER MODE REASON",file=sys.stderr); return 2
    if argv[1]=="poppler" and len(argv)==5: return poppler(argv[2],argv[3],argv[4])
    if argv[1]=="qpdf" and len(argv)==4: return qpdf(argv[2],argv[3])
    if argv[1]=="unavailable" and len(argv)==5: return unavailable(argv[2],argv[3],argv[4])
    return 2
if __name__=="__main__": raise SystemExit(main(sys.argv))
