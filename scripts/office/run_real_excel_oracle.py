#!/usr/bin/env python3
"""Fresh Excel cache oracle with per-vault scratch and exclusive application custody."""
import argparse, hashlib, json, os, shutil, subprocess, sys, time, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preflight(path):
    if not path.is_file(): raise ValueError('missing workbook')
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        if len(names)!=len(set(names)) or z.testzip(): raise ValueError('invalid ZIP')
        if not {'xl/workbook.xml','[Content_Types].xml','_rels/.rels'}.issubset(names): raise ValueError('not an XLSX package')
        for name in names:
            if name.startswith('/') or '..' in Path(name).parts: raise ValueError('invalid ZIP path')
            if any(x in name.lower() for x in ['vbaproject','/macrosheets/','/dialogsheets/','/activex/','/embeddings/']): raise ValueError('active content is not allowed in the oracle')
            if name.endswith(('.xml','.rels')):
                raw=z.read(name)
                if b'<!DOCTYPE' in raw or b'<!ENTITY' in raw: raise ValueError('XML declarations are not allowed')
                ET.fromstring(raw)
    return sha(path)


def run(args):
    if sys.platform!='darwin': raise RuntimeError('Excel must run on macOS')
    args.output.mkdir(parents=True,exist_ok=True)
    manifest_hash=sha(args.manifest)
    identity=dict(manifest_sha256=manifest_hash,script_sha256=sha(args.script),driver_sha256=sha(Path(__file__)))
    identity_path=args.output/'identity.json'
    if identity_path.exists() and json.loads(identity_path.read_text())!=identity: raise ValueError('oracle identity changed')
    identity_path.write_text(json.dumps(identity,indent=2)+'\n')
    records=[json.loads(line) for line in args.manifest.read_text().splitlines()]
    rows_path=args.output/'rows.jsonl'
    prior=[json.loads(line) for line in rows_path.read_text().splitlines()] if rows_path.exists() else []
    done={r['sha256'] for r in prior}
    args.lock.mkdir()
    owner=f'W7-C14 real workbook oracle {args.output}'
    (args.lock/'owner').write_text(owner+'\n')
    release=False
    # Excel is sandboxed apart from Full Disk Access: any path it is told to open or save outside its own
    # container raises the Grant File Access dialog on every call. Stage both sides inside the container.
    stage=Path.home()/'Library/Containers/com.microsoft.Excel/Data/tmp/w7-oracle'/f'{time.time_ns()}-{os.getpid()}'
    stage.mkdir(parents=True)
    try:
        for entry in records:
            if entry['sha256'] in done: continue
            if args.limit is not None and len(done)>=args.limit: break
            source=(args.corpus/entry['path']).resolve()
            if not source.is_relative_to(args.corpus.resolve()): raise ValueError('manifest path escapes corpus')
            row=dict(sha256=entry['sha256'],path=entry['path'],status='preflight-rejected')
            try:
                if preflight(source)!=entry['sha256']: raise RuntimeError('input hash mismatch')
            except (ValueError,zipfile.BadZipFile,ET.ParseError) as error:
                row['reason']=str(error)
            else:
                output=args.output/(entry['sha256']+'.xlsx')
                if output.exists(): raise ValueError('unreceipted output already exists')
                case=stage/entry['sha256']
                case.mkdir(parents=True)
                case_closed=False
                try:
                    staged_in=case/source.name
                    staged_out=case/output.name
                    shutil.copyfile(source,staged_in)
                    if preflight(staged_in)!=entry['sha256']: raise RuntimeError('staged input hash mismatch')
                    command=['/usr/bin/perl','-e','alarm 120; exec @ARGV','/usr/bin/osascript',str(args.script),str(staged_in),str(staged_out),source.name,output.name]
                    result=subprocess.run(command,capture_output=True,text=True,timeout=130)
                    (args.output/(entry['sha256']+'.driver.log')).write_text(result.stdout+result.stderr)
                    if result.returncode:
                        row.update(status='timed-out' if result.returncode in(-14,142) else 'custody-error',exit_code=result.returncode)
                        with rows_path.open('a') as rows: rows.write(json.dumps(row)+'\n')
                        raise RuntimeError('Excel operation did not restore custody; lock retained')
                    version,code,remaining,*detail=result.stdout.rstrip('\n').split('\t')
                    if remaining!='0': raise RuntimeError('Excel still has an open workbook')
                    case_closed=True
                    row.update(app_version=version,calculation='calculate full rebuild',update_links=False,final_workbooks=0)
                    if code!='0': row.update(status='excel-rejected',error_code=int(code),reason='\t'.join(detail))
                    else:
                        shutil.move(staged_out,output)
                        row.update(status='completed',output_sha256=preflight(output))
                finally:
                    if case_closed: shutil.rmtree(case)
            with rows_path.open('a') as rows: rows.write(json.dumps(row)+'\n')
            done.add(entry['sha256'])
            print(len(done),len(records),row['status'],entry['sha256'],flush=True)
        end=subprocess.run(['/usr/bin/perl','-e','alarm 120; exec @ARGV','/usr/bin/osascript','-e','tell application "Microsoft Excel"\nif (count of workbooks) is not 0 then error "Foreign workbook is open"\nquit\nend tell'],capture_output=True,text=True,timeout=130)
        if end.returncode: raise RuntimeError('Excel shutdown failed; lock retained')
        release=True
    finally:
        if release: shutil.rmtree(stage)
        (args.output/'custody.json').write_text(json.dumps(dict(owner=owner,lock_retained=not release,stage=str(stage),finished_at=time.time()),indent=2)+'\n')
        if release:
            if (args.lock/'owner').read_text().strip()!=owner: raise RuntimeError('Office lock owner changed')
            (args.lock/'owner').unlink();args.lock.rmdir()

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ['corpus','manifest','output','script']: p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--limit',type=int)
    p.add_argument('--lock',type=Path,default=Path('/Users/olety/w7-oracle/lock'))
    run(p.parse_args())
