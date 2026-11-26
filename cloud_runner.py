"""Public-source-only Linux baseline worker; outputs compressed evidence to job logs."""
from pathlib import Path,PurePosixPath
import argparse,base64,datetime,gzip,hashlib,json,os,shutil,subprocess,tarfile,time,urllib.request
from rule_fingerprint import fingerprint

ROOT=Path(__file__).resolve().parent
def dump(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def fetch(url,path,maximum=1073741824):
    assert url.startswith('https://');t=time.monotonic();size=0;h=hashlib.sha256()
    with urllib.request.urlopen(url,timeout=60) as response,path.open('wb') as stream:
        while data:=response.read(1024*1024):
            size+=len(data)
            if size>maximum or time.monotonic()-t>900:raise ValueError('Public download resource bound')
            stream.write(data);h.update(data)
    return {'url':url,'bytes':size,'sha256':h.hexdigest()}
def extract(archive,target):
    with tarfile.open(archive,'r:gz') as tf:
        members=tf.getmembers();prefix={PurePosixPath(m.name).parts[0] for m in members if m.name}
        assert len(prefix)==1
        for m in members:
            p=PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or '\\' in m.name:raise ValueError('Unsafe source path')
        total=0;files=[];skipped=[]
        for m in members:
            rel=PurePosixPath(*PurePosixPath(m.name).parts[1:])
            if not m.isfile():
                if not m.isdir():skipped.append({'file':str(rel),'reason':'non_regular'})
                continue
            if any(':' in part or part.endswith((' ','.')) for part in rel.parts):
                skipped.append({'file':str(rel),'reason':'same_Windows_compatible_policy_as_local'});continue
            total+=m.size
            if total>2_000_000_000 or m.size>100_000_000:raise ValueError('Source expansion bound')
            dest=target/str(rel);dest.resolve().relative_to(target.resolve());dest.parent.mkdir(parents=True,exist_ok=True)
            h=hashlib.sha256()
            with tf.extractfile(m) as inp,dest.open('wb') as out:
                while chunk:=inp.read(1024*1024):out.write(chunk);h.update(chunk)
            files.append({'file':str(rel),'bytes':m.size,'sha256':h.hexdigest()})
    return files,skipped
def command(args,name,out,timeout=2400,ok=(0,)):
    start=time.monotonic()
    with (out/(name+'.log')).open('wb') as stream:
        proc=subprocess.Popen(args,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        try:code=proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(proc.pid,signal.SIGTERM)
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
            code=124
    status={'command':args,'exit_code':code,'successful':code in ok,'elapsed_seconds':round(time.monotonic()-start,2)}
    dump(out/(name+'.status.json'),status)
    return status
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--snapshot',required=True);args=parser.parse_args()
    tasks=json.loads((ROOT/'tasks.json').read_text());task=next(t for t in tasks if t['snapshot_id']==args.snapshot)
    work=ROOT/'work'/args.snapshot;work.mkdir(parents=True,exist_ok=True);source=work/'source';out=work/'results';out.mkdir(exist_ok=True)
    dump(out/'task.json',task);summary={'date_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':'Linux GitHub standard hosted runner','snapshot':args.snapshot,'CWE_gold_not_given_to_tools':True,'paid_API_calls':0,'label_or_detection_verdicts_not_inferred':True}
    try:
        repo=task['repo_url'].removeprefix('https://github.com/');assert repo.count('/')==1 and all(x.isalnum() or x in '/-._' for x in repo)
        assert len(task['commit'])==40 and all(c in '0123456789abcdef' for c in task['commit'])
        archive=work/'source.tar.gz';dump(out/'download.json',fetch(f'https://codeload.github.com/{repo}/tar.gz/{task["commit"]}',archive))
        files,skipped=extract(archive,source);dump(out/'source_manifest.json',{'files':files,'skipped':skipped})
        suffixes={Path(f['file']).suffix for f in files};rules=work/'rules';rules.mkdir()
        lock=json.loads((ROOT/'tools_lock.json').read_text());configs=[]
        receipts=[]
        for rule in lock['semgrep_rules']:
            p=rules/rule['file'];receipt=fetch(rule['url'],p,20000000)
            receipt['file']=rule['file'];receipt['semantic_fingerprint']=fingerprint(p.read_text(encoding='utf-8'));receipts.append(receipt)
            dump(out/'rule_receipts.json',receipts)
            assert receipt['semantic_fingerprint']==rule['semantic_fingerprint'],'Rule matching configuration changed: do not mix configurations'
            configs+=['--config',str(p)]
        command(['semgrep','scan',str(source),'--json','--output='+str(out/'semgrep.json'),'--metrics=off','--disable-version-check','--no-git-ignore','--jobs=2','--timeout=10','--max-target-bytes=1000000','--dataflow-traces',*configs],'semgrep',out)
        if '.py' in suffixes:command(['bandit','-r',str(source),'-f','json','-o',str(out/'bandit.json'),'-q'],'bandit',out,ok=(0,1))
        for language,query in [('python','1.9.2'),('javascript','2.5.2')]:
            supported=('.py' in suffixes) if language=='python' else bool(suffixes & {'.js','.jsx','.mjs','.cjs','.ts','.tsx','.vue'})
            if not supported:summary[language]='no_source_for_configured_language';continue
            db=work/('db-'+language)
            create=command(['codeql','database','create',str(db),'--language='+language,'--build-mode=none','--source-root='+str(source),'--threads=2','--ram=3072'],'create-'+language,out)
            if not create['successful']:continue
            suite=f'codeql/{language}-queries@{query}:codeql-suites/{language}-code-scanning.qls'
            command(['codeql','database','analyze',str(db),suite,'--format=sarifv2.1.0','--output='+str(out/('codeql-'+language+'.sarif')),'--threads=2','--ram=4096','--max-disk-cache=1024','--rerun'],'analyze-'+language,out)
            command(['codeql','database','cleanup',str(db),'--cache-cleanup=fit','--max-disk-cache=128','-J=-Xmx512m'],'cache-'+language,out,timeout=180)
        summary['state']='execution_attempts_finished_pending_task_support_and_mechanism_review'
    except Exception as error:summary.update(state='source_or_setup_unavailable_not_a_detection_miss',error_type=type(error).__name__,error_message=str(error)[:300])
    dump(out/'summary.json',summary)
    # Logs are the transport: no artifact/cache upload, no paid storage or model service.
    # Export only this worker's reports/configuration; no credentials or source working directory.
    evidence={}
    for p in out.glob('*'):
        if p.is_file():evidence[p.name]=base64.b64encode(p.read_bytes()).decode('ascii')
    payload=gzip.compress(json.dumps(evidence,separators=(',',':')).encode(),compresslevel=6)
    encoded=base64.b64encode(payload).decode('ascii')
    print('BASELINE_EVIDENCE_BEGIN',args.snapshot,hashlib.sha256(payload).hexdigest(),len(payload),flush=True)
    for start in range(0,len(encoded),3000):print('BASELINE_EVIDENCE_CHUNK '+encoded[start:start+3000],flush=True)
    print('BASELINE_EVIDENCE_END',args.snapshot,flush=True)
    if summary['state']!='execution_attempts_finished_pending_task_support_and_mechanism_review':raise SystemExit(2)

if __name__=='__main__':main()
