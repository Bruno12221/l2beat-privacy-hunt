#!/usr/bin/env python3
"""Resume-safe free canonical-metadata enrichment of actual Ironwood raw txs.

Read-only public requests, globally paced (not per-worker), no JWT or paid API.
All decoded Ironwood transactions are retained regardless of amount/recovery.
Only matching canonical metadata permits entry into the target-height universe.
This does not verify consensus, prove note availability, or solve the challenge.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
from pathlib import Path
from analyze_challenge7_baseline import dump, write_rows
from trace_challenge7_free_near import digest

API="https://api.mainnet.cipherscan.app/api/tx/"
ANCHOR=3488703
ACTIVATION=3428143


def ironwood_queue(rows):
    selected=[]
    seen=set()
    for r in rows:
        if not r.get("ok") or r["txid"] in seen:raise ValueError("failed/duplicate raw decode")
        seen.add(r["txid"])
        if any(b.get("pool")=="ironwood" for b in r.get("bundles") or []):selected.append(r)
    return sorted(selected,key=lambda r:r["txid"])


def validate_envelope(envelope,url):
    if envelope.get("url")!=url:raise ValueError("metadata URL mismatch")
    if hashlib.sha256(envelope["rawUtf8"].encode()).hexdigest()!=envelope["responseBytesSha256"]:raise ValueError("metadata original-response hash mismatch")
    payload=json.loads(envelope["rawUtf8"])
    if "response" in envelope and envelope["response"]!=payload:raise ValueError("metadata parsed payload mismatch")
    return payload


def enrich(raw,detail,source):
    h=raw["txid"]
    if detail.get("txid")!=h:raise ValueError("metadata transaction ID mismatch")
    if detail.get("isCanonical") is not True:
        return None,"noncanonical-or-unverified"
    height=int(detail["blockHeight"]);seconds=int(detail["blockTime"])
    if not detail.get("blockHash") or not detail.get("hasIronwood"):raise ValueError("canonical metadata pool/block identity mismatch")
    if height<ACTIVATION:return None,"before-Ironwood-activation"
    if height>ANCHOR:return None,"after-target-anchor"
    if seconds>1789812071:return None,"time-height-conflict"
    return {**raw,"blockHeight":height,"blockTime":datetime.fromtimestamp(seconds,timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "isCanonical":True,"canonicalBlockHash":detail["blockHash"],"canonicalMetadataSource":source,
            "eligibilityWarning":"Indexer canonicality/height claim, not independent chain consensus or target note consumption proof."},"height-compatible"


class PacedSource:
    def __init__(self,out,fetch,maximum,interval,reuse):
        self.out,self.fetch,self.maximum,self.interval=out,fetch,maximum,interval
        self.calls=0;self.next_start=0;self.lock=threading.Lock();self.halt=threading.Event();self.reason=None
        self.existing={}
        for folder in [out]+reuse:
            for path in sorted((folder/"http-responses").glob("*.json")):
                envelope=json.loads(path.read_text());url=envelope.get("url","")
                if not url.startswith(API) or len(url[len(API):])!=64:continue
                validate_envelope(envelope,url)
                self.existing.setdefault(url,(path,envelope))

    def request(self,h):
        url=API+h
        if url in self.existing:
            path,envelope=self.existing[url]
        else:
            if not self.fetch:return {"txid":h,"state":"cache-missing"}
            with self.lock:
                if self.halt.is_set():return {"txid":h,"state":"stopped-before-request"}
                if self.calls>=self.maximum:
                    self.reason="per-run HTTP cap reached";self.halt.set();return {"txid":h,"state":"http-cap"}
                # Hold the start gate across the wait, not the HTTP request.
                # Schedule the next slot from actual start time, so delayed
                # worker wakeups cannot create a burst of reserved requests.
                self.halt.wait(max(0,self.next_start-time.monotonic()))
                if self.halt.is_set():return {"txid":h,"state":"stopped-before-request"}
                self.calls+=1;self.next_start=time.monotonic()+self.interval
            request=urllib.request.Request(url,headers={"accept":"application/json","user-agent":"l2beat-public-evidence/1.0"})
            try:
                with urllib.request.urlopen(request,timeout=30) as response:
                    code=response.status;payload=response.read()
            except urllib.error.HTTPError as exc:
                code=exc.code;payload=exc.read()
                if code in (401,403,429):
                    self.reason=f"HTTP {code}; Retry-After={exc.headers.get('Retry-After')}; stopped";self.halt.set()
            except (urllib.error.URLError,TimeoutError,OSError) as exc:
                return {"txid":h,"state":"transport-error","error":str(exc)}
            envelope={"url":url,"httpStatus":code,"fetchedAt":datetime.now(timezone.utc).isoformat(),
                      "rawUtf8":payload.decode(),"responseBytesSha256":hashlib.sha256(payload).hexdigest()}
            path=self.out/"http-responses"/(hashlib.sha256(url.encode()).hexdigest()+".json")
            dump(path,envelope)
        source={"path":str(path.resolve()),"sha256":digest(path),"url":url}
        if envelope["httpStatus"]!=200:return {"txid":h,"state":"http-error","httpStatus":envelope["httpStatus"],"source":source}
        detail=validate_envelope(envelope,url)
        return {"txid":h,"state":"metadata","detail":detail,"source":source}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw-dir",type=Path,default=Path("challenge7-pending-raw-data"))
    p.add_argument("--output-dir",type=Path,default=Path("challenge7-pending-enriched-data"))
    p.add_argument("--reuse-dir",type=Path,action="append",default=[Path("challenge7-pending-coverage-probe-data")])
    p.add_argument("--fetch",action="store_true")
    p.add_argument("--limit",type=int,default=30,help="0 processes the whole selected Ironwood inventory")
    p.add_argument("--workers",type=int,default=3)
    p.add_argument("--interval",type=float,default=1,help="Global seconds between request starts, across all workers")
    p.add_argument("--max-http-calls",type=int,default=30)
    a=p.parse_args()
    if not 1<=a.workers<=3 or a.interval<1 or a.limit<0 or a.max_http_calls<0:raise ValueError("bounded globally-paced settings required")
    if a.output_dir.resolve()==a.raw_dir.resolve():raise ValueError("separate output required")
    raw_path=a.raw_dir/"decoded-transactions.jsonl";raw_manifest=json.loads((a.raw_dir/"manifest.json").read_text())
    if not raw_manifest.get("scopeComplete") or raw_manifest["decodedSha256"]!=digest(raw_path):raise ValueError("completed hash-matching raw inventory required")
    a.output_dir.mkdir(parents=True,exist_ok=True)
    raw=ironwood_queue(map(json.loads,raw_path.open()));by_id={r["txid"]:r for r in raw}
    config={"rawLedgerSha256":digest(raw_path),"anchor":ANCHOR,"selection":"all-successfully-decoded-Ironwood-transactions-no-amount-floor-no-recovery-filter"}
    config_path=a.output_dir/"config.json"
    if config_path.exists() and json.loads(config_path.read_text())!=config:raise ValueError("raw scope changed; use separate output directory")
    dump(config_path,config)
    source=PacedSource(a.output_dir,a.fetch,a.max_http_calls,a.interval,a.reuse_dir)
    results_path=a.output_dir/"metadata-results.jsonl"
    results={r["txid"]:r for r in map(json.loads,results_path.open())} if results_path.exists() else {}
    if set(results)-set(by_id):raise ValueError("out-of-scope metadata checkpoint")
    pending=[r for r in raw if results.get(r["txid"],{}).get("state")!="metadata"]
    if a.limit:pending=pending[:a.limit]
    start=time.monotonic();processed=0;stopped=None
    try:
        with ThreadPoolExecutor(max_workers=a.workers) as executor:
            items=iter(pending);running={}
            def schedule():
                while len(running)<a.workers and not source.halt.is_set():
                    row=next(items,None)
                    if row is None:break
                    running[executor.submit(source.request,row["txid"])]=row["txid"]
            schedule()
            while running:
                finished,_=wait(running,return_when=FIRST_COMPLETED)
                for future in finished:
                    h=running.pop(future);results[h]=future.result();processed+=1
                if processed%25==0 or not running:
                    write_rows(results_path,[results[h] for h in sorted(results)])
                    print(f"canonical metadata={len([r for r in results.values() if r['state']=='metadata'])}/{len(raw)} processedThisRun={processed} newHTTP={source.calls}",flush=True)
                schedule()
    except KeyboardInterrupt:
        source.reason="user interrupt; saved completed responses are reusable";source.halt.set();stopped=source.reason
    finally:
        write_rows(results_path,[results[h] for h in sorted(results)])
        enriched,statuses=[],{}
        for h,r in results.items():
            if r["state"]!="metadata":statuses[h]=r["state"];continue
            # Reopen originals on every replay; never trust a cached derived row.
            path=Path(r["source"]["path"])
            if digest(path)!=r["source"]["sha256"]:raise ValueError("checkpoint source envelope hash mismatch")
            detail=validate_envelope(json.loads(path.read_text()),API+h)
            row,status=enrich(by_id[h],detail,r["source"]);statuses[h]=status
            if row is not None:enriched.append(row)
        write_rows(a.output_dir/"eligible-decoded-transactions.jsonl",sorted(enriched,key=lambda r:r["txid"]))
        remaining=[h for h in by_id if h not in statuses or statuses[h] in ("cache-missing","transport-error","stopped-before-request","http-cap","http-error")]
        write_rows(a.output_dir/"unresolved-transactions.jsonl",[{"txid":h,"status":statuses.get(h,"not-requested")} for h in sorted(remaining)])
        from collections import Counter
        dump(a.output_dir/"manifest.json",{**config,"challengeSolved":False,"stopped":stopped or source.reason,
             "selectedIronwoodTransactions":len(raw),"metadataTransactions":sum(r["state"]=="metadata" for r in results.values()),
             "heightEligibleTransactions":len(enriched),"unresolvedTransactions":len(remaining),"statusCounts":dict(Counter(statuses.values())),
             "newHttpCalls":source.calls,"elapsedSeconds":round(time.monotonic()-start,3),"scriptSha256":digest(Path(__file__)),
             "eligibleLedgerSha256":digest(a.output_dir/"eligible-decoded-transactions.jsonl"),
             "metadataResultsSha256":digest(results_path),"globalRequestIntervalSeconds":a.interval,
             "warning":"Mined eligibility is an explorer claim. Unknown/opaque/unsettled paths are not exclusions; no target nullifier or ownership proof."})
        print(f"{'checkpoint' if remaining else 'done'}: selected={len(raw)} metadata={sum(r['state']=='metadata' for r in results.values())} eligible={len(enriched)} unresolved={len(remaining)} stopped={stopped or source.reason} output={a.output_dir.resolve()}",flush=True)
    return 2 if remaining else 0


if __name__=="__main__":raise SystemExit(main())
