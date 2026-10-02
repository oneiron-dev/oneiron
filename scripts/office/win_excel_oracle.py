#!/usr/bin/env python3
"""Windows Excel truth oracle (COM automation through pywin32).

Mirrors the Mac oracle (run_real_excel_oracle.py + real_workbook_recalc.applescript):
one fresh Excel instance per workbook, links never updated, macros force-disabled,
CalculateFullRebuild, SaveAs xlsx, output hashed by the same preflight.
Row keys match the Mac rows.jsonl; extra keys: platform, macros, corrupt_load, excel_build.
--reuse (10-02): one Excel instance serves many workbooks in a row (child --batch), restarted on a timeout,
a stray workbook, a crash or every --restart-every files; the per-file steps are the same as --one.
Rows then carry excel_session='shared' (fresh instance: 'fresh').
"""
import argparse, hashlib, json, os, subprocess, sys, time, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ACTIVE = ['/macrosheets/', '/dialogsheets/', '/activex/', '/embeddings/']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def preflight(path, allow_macros=False):
    path = Path(path)
    if not path.is_file(): raise ValueError('missing workbook')
    macros = False
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or z.testzip(): raise ValueError('invalid ZIP')
        if not {'xl/workbook.xml', '[Content_Types].xml', '_rels/.rels'}.issubset(names): raise ValueError('not an XLSX package')
        for name in names:
            if name.startswith('/') or '..' in Path(name).parts: raise ValueError('invalid ZIP path')
            low = name.lower()
            if 'vbaproject' in low:
                if not allow_macros: raise ValueError('active content is not allowed in the oracle')
                macros = True
                continue
            if any(x in low for x in ACTIVE): raise ValueError('active content is not allowed in the oracle')
            if name.endswith(('.xml', '.rels')):
                raw = z.read(name)
                if b'<!DOCTYPE' in raw or b'<!ENTITY' in raw: raise ValueError('XML declarations are not allowed')
                ET.fromstring(raw)
    return sha(path), macros


def excel_file_version(app):
    try:
        import win32api
        exe = os.path.join(app.Path, 'EXCEL.EXE')
        info = win32api.GetFileVersionInfo(exe, '\\')
        ms, ls = info['FileVersionMS'], info['FileVersionLS']
        return f'{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}'
    except Exception:
        return None


def one(inp, out, repair):
    """Child process: open, full rebuild, save as xlsx, close. Prints one JSON line."""
    import pythoncom, win32com.client
    pythoncom.CoInitialize()
    res = dict(code=0, detail='', final_workbooks=None)
    app = None
    try:
        app = win32com.client.DispatchEx('Excel.Application')
        app.Visible = False
        app.DisplayAlerts = False
        app.AskToUpdateLinks = False
        app.EnableEvents = False
        app.ScreenUpdating = False
        app.AutomationSecurity = 3  # msoAutomationSecurityForceDisable: macros never run
        res['app_version'] = f'{app.Version}.{app.Build}'
        res['excel_build'] = excel_file_version(app)
        res['calculation_mode_before'] = app.Calculation if app.Workbooks.Count else None
        wb = app.Workbooks.Open(Filename=str(inp), UpdateLinks=0, ReadOnly=False, IgnoreReadOnlyRecommended=True,
                                Notify=False, AddToMru=False, CorruptLoad=(1 if repair else 0))
        if wb.Name != inp.name: raise RuntimeError('Excel did not open the owned input')
        app.CalculateFullRebuild()
        t0 = time.time()
        while app.CalculationState != 0 and time.time() - t0 < 600:  # 0 = xlDone
            time.sleep(0.2)
        res['calc_seconds'] = round(time.time() - t0, 3)
        wb.SaveAs(Filename=str(out), FileFormat=51, ConflictResolution=2, CreateBackup=False)  # 51 = xlOpenXMLWorkbook
        if wb.Name != out.name: raise RuntimeError('Excel did not save the owned output')
        wb.Close(SaveChanges=False)
        res['final_workbooks'] = app.Workbooks.Count
    except Exception as e:
        res['code'] = getattr(e, 'hresult', None) or 1
        res['detail'] = str(e)[:600]
        try:
            for w in list(app.Workbooks): w.Close(SaveChanges=False)
            res['final_workbooks'] = app.Workbooks.Count
        except Exception: pass
    finally:
        try:
            if app is not None: app.Quit()
        except Exception: pass
        app = None
        pythoncom.CoUninitialize()
    print(json.dumps(res), flush=True)


def batch(list_path, repair):
    """Child process: one Excel instance for every line of LIST (sha<TAB>input<TAB>output). One JSON line per file."""
    import pythoncom, win32com.client
    pythoncom.CoInitialize()
    app = None
    try:
        app = win32com.client.DispatchEx('Excel.Application')
        app.Visible = False
        app.DisplayAlerts = False
        app.AskToUpdateLinks = False
        app.EnableEvents = False
        app.ScreenUpdating = False
        app.AutomationSecurity = 3  # msoAutomationSecurityForceDisable: macros never run
        app_version = f'{app.Version}.{app.Build}'
        excel_build = excel_file_version(app)
        for line in Path(list_path).read_text(encoding='utf-8').splitlines():
            if not line.strip(): continue
            digest, inp, out = line.split('\t')
            inp, out = Path(inp), Path(out)
            res = dict(sha256=digest, code=0, detail='', final_workbooks=None, app_version=app_version, excel_build=excel_build)
            try:
                wb = app.Workbooks.Open(Filename=str(inp), UpdateLinks=0, ReadOnly=False, IgnoreReadOnlyRecommended=True,
                                        Notify=False, AddToMru=False, CorruptLoad=(1 if repair else 0))
                if wb.Name != inp.name: raise RuntimeError('Excel did not open the owned input')
                res['calc_mode_after_open'] = app.Calculation
                app.CalculateFullRebuild()
                t0 = time.time()
                while app.CalculationState != 0 and time.time() - t0 < 600:  # 0 = xlDone
                    time.sleep(0.2)
                res['calc_seconds'] = round(time.time() - t0, 3)
                wb.SaveAs(Filename=str(out), FileFormat=51, ConflictResolution=2, CreateBackup=False)  # 51 = xlOpenXMLWorkbook
                if wb.Name != out.name: raise RuntimeError('Excel did not save the owned output')
                wb.Close(SaveChanges=False)
                res['final_workbooks'] = app.Workbooks.Count
            except Exception as e:
                res['code'] = getattr(e, 'hresult', None) or 1
                res['detail'] = str(e)[:600]
                try:
                    for w in list(app.Workbooks): w.Close(SaveChanges=False)
                    res['final_workbooks'] = app.Workbooks.Count
                except Exception:
                    res['final_workbooks'] = None
            print(json.dumps(res), flush=True)
            if res['final_workbooks'] != 0:
                sys.exit(3)  # custody lost: the parent restarts Excel for the rest
        print(json.dumps(dict(batch_done=True)), flush=True)
    finally:
        try:
            if app is not None: app.Quit()
        except Exception: pass
        app = None
        pythoncom.CoUninitialize()


def kill_excel():
    try:
        subprocess.run(['taskkill', '/F', '/IM', 'EXCEL.EXE', '/T'], capture_output=True)
    except FileNotFoundError:
        pass  # not on Windows (dry runs of the preflight path)


def finish_row(row, res, output):
    """Turn the child's JSON result for one workbook into the row's status fields."""
    row.update(app_version=res.get('app_version'), excel_build=res.get('excel_build'),
               calculation='calculate full rebuild', update_links=False, final_workbooks=res.get('final_workbooks'))
    if res.get('calc_mode_after_open') is not None: row['calc_mode_after_open'] = res['calc_mode_after_open']
    if res['code'] != 0:
        row.update(status='excel-rejected', error_code=res['code'], reason=res.get('detail', ''))
        if output.exists(): output.unlink()
    elif not output.exists():
        row.update(status='custody-error', reason='no output written')
    else:
        try:
            row.update(status='completed', output_sha256=preflight(output, False)[0], calc_seconds=res.get('calc_seconds'))
        except (ValueError, zipfile.BadZipFile, ET.ParseError) as error:
            row.update(status='output-rejected', reason=str(error))


def run_reuse(args, records, rows_path, done, counts):
    """--reuse: preflight everything, then feed one Excel instance (child --batch) file after file."""
    import threading, queue
    pending = []
    for entry in records:
        if entry['sha256'] in done: continue
        if args.limit is not None and len(done) + len(pending) >= args.limit: break
        source = (args.corpus / entry['path']).resolve()
        if not source.is_relative_to(args.corpus.resolve()): raise ValueError('manifest path escapes corpus')
        row = dict(sha256=entry['sha256'], path=entry['path'], status='preflight-rejected', platform='windows', excel_session='shared')
        try:
            digest, macros = preflight(source, args.allow_macros)
            if digest != entry['sha256']: raise RuntimeError('input hash mismatch')
        except (ValueError, zipfile.BadZipFile, ET.ParseError) as error:
            row['reason'] = str(error)
            with rows_path.open('a') as rows: rows.write(json.dumps(row) + '\n')
            done.add(entry['sha256']); counts[row['status']] = counts.get(row['status'], 0) + 1
            print(len(done), len(records), row['status'], entry['sha256'], flush=True)
            continue
        output = args.output / (entry['sha256'] + '.xlsx')
        if output.exists(): raise ValueError('unreceipted output already exists')
        row.update(macros='disabled' if macros else 'none', corrupt_load='xlRepairFile' if args.repair else 'normal')
        pending.append((entry, source, output, row))
    i = 0
    while i < len(pending):
        chunk = pending[i:i + args.restart_every]
        list_path = args.output / 'batch.tsv'
        list_path.write_text(''.join(f"{e['sha256']}\t{src}\t{out}\n" for e, src, out, r in chunk), encoding='utf-8')
        cmd = [sys.executable, str(Path(__file__).resolve()), '--batch', str(list_path)] + (['--repair'] if args.repair else [])
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        q = queue.Queue()
        def reader(pipe):
            for line in pipe: q.put(line)
            q.put(None)
        threading.Thread(target=reader, args=(proc.stdout,), daemon=True).start()
        restart = False
        for entry, source, output, row in chunk:
            t_start = time.time()
            try:
                line = q.get(timeout=args.timeout)
            except queue.Empty:
                line = None
                proc.kill(); kill_excel()
                row.update(status='timed-out', timeout_seconds=args.timeout)
                restart = True
            else:
                if line is None:
                    kill_excel(); row.update(status='custody-error', reason='excel child ended early', exit_code=proc.poll()); restart = True
                else:
                    try:
                        res = json.loads(line)
                    except Exception:
                        res = None
                    if res is None or res.get('sha256') != entry['sha256']:
                        proc.kill(); kill_excel(); row.update(status='custody-error', reason='unexpected child output'); restart = True
                    else:
                        finish_row(row, res, output)
                        if res.get('final_workbooks') != 0: restart = True
            row['wall_seconds'] = round(time.time() - t_start, 3)
            with rows_path.open('a') as rows: rows.write(json.dumps(row) + '\n')
            done.add(entry['sha256']); counts[row['status']] = counts.get(row['status'], 0) + 1
            print(len(done), len(records), row['status'], entry['sha256'], flush=True)
            i += 1
            if restart: break
        if not restart:
            try: proc.wait(timeout=60)
            except subprocess.TimeoutExpired: proc.kill()
        else:
            try: proc.wait(timeout=30)
            except subprocess.TimeoutExpired: proc.kill()
            kill_excel()
        err = proc.stderr.read() if proc.stderr else ''
        if err: (args.output / f'batch-{i}.stderr.log').write_text(err)


def run(args):
    args.output.mkdir(parents=True, exist_ok=True)
    identity = dict(manifest_sha256=sha(args.manifest), driver_sha256=sha(Path(__file__)), platform='windows',
                    allow_macros=bool(args.allow_macros), repair=bool(args.repair), reuse=bool(args.reuse))
    identity_path = args.output / 'identity.json'
    if identity_path.exists() and json.loads(identity_path.read_text()) != identity: raise ValueError('oracle identity changed')
    identity_path.write_text(json.dumps(identity, indent=2) + '\n')
    records = [json.loads(line) for line in args.manifest.read_text().splitlines() if line.strip()]
    rows_path = args.output / 'rows.jsonl'
    prior = [json.loads(line) for line in rows_path.read_text().splitlines()] if rows_path.exists() else []
    done = {r['sha256'] for r in prior}
    kill_excel()  # exclusive custody: no stray Excel before the run
    counts = {}
    if args.reuse:
        run_reuse(args, records, rows_path, done, counts)
        records = []  # the fresh-instance loop below has nothing left
    for entry in records:
        if entry['sha256'] in done: continue
        if args.limit is not None and len(done) >= args.limit: break
        source = (args.corpus / entry['path']).resolve()
        if not source.is_relative_to(args.corpus.resolve()): raise ValueError('manifest path escapes corpus')
        row = dict(sha256=entry['sha256'], path=entry['path'], status='preflight-rejected', platform='windows', excel_session='fresh')
        try:
            digest, macros = preflight(source, args.allow_macros)
            if digest != entry['sha256']: raise RuntimeError('input hash mismatch')
        except (ValueError, zipfile.BadZipFile, ET.ParseError) as error:
            row['reason'] = str(error)
        else:
            output = args.output / (entry['sha256'] + '.xlsx')
            if output.exists(): raise ValueError('unreceipted output already exists')
            row.update(macros='disabled' if macros else 'none', corrupt_load='xlRepairFile' if args.repair else 'normal')
            cmd = [sys.executable, str(Path(__file__).resolve()), '--one', str(source), str(output)] + (['--repair'] if args.repair else [])
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
            except subprocess.TimeoutExpired as t:
                kill_excel()
                (args.output / (entry['sha256'] + '.driver.log')).write_text((t.stdout or '') + (t.stderr or ''))
                row.update(status='timed-out', timeout_seconds=args.timeout)
            else:
                (args.output / (entry['sha256'] + '.driver.log')).write_text(result.stdout + result.stderr)
                last = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ''
                try:
                    res = json.loads(last)
                except Exception:
                    res = None
                if result.returncode or res is None:
                    kill_excel()
                    row.update(status='custody-error', exit_code=result.returncode)
                else:
                    if res.get('final_workbooks') != 0:
                        kill_excel()
                    finish_row(row, res, output)
        with rows_path.open('a') as rows: rows.write(json.dumps(row) + '\n')
        done.add(entry['sha256'])
        counts[row['status']] = counts.get(row['status'], 0) + 1
        print(len(done), len(records), row['status'], entry['sha256'], flush=True)
    kill_excel()
    (args.output / 'done.txt').write_text(json.dumps(dict(rows=len(done), manifest=len(records), this_run=counts, finished_at=time.strftime('%Y-%m-%dT%H:%M:%S'))) + '\n')
    print('DONE', json.dumps(counts), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--one', nargs=2, metavar=('INPUT', 'OUTPUT'))
    p.add_argument('--batch', metavar='LIST', help='child: one Excel instance for every sha<TAB>input<TAB>output line')
    p.add_argument('--reuse', action='store_true', help='one Excel instance for many workbooks (restarted on trouble)')
    p.add_argument('--restart-every', type=int, default=250, help='with --reuse: start a fresh Excel after this many files')
    p.add_argument('--repair', action='store_true', help='open with CorruptLoad=xlRepairFile (recorded in the row)')
    p.add_argument('--allow-macros', action='store_true', help='admit .xlsm; macros stay force-disabled (recorded in the row)')
    for name in ['corpus', 'manifest', 'output']: p.add_argument('--' + name, type=Path)
    p.add_argument('--limit', type=int)
    p.add_argument('--timeout', type=int, default=180)
    a = p.parse_args()
    if a.one:
        one(Path(a.one[0]), Path(a.one[1]), a.repair)
    elif a.batch:
        batch(a.batch, a.repair)
    else:
        if not (a.corpus and a.manifest and a.output): p.error('--corpus, --manifest and --output are required')
        run(a)
