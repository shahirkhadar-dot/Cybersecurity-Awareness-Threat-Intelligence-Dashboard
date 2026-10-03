
from flask import Flask, jsonify, request, render_template
from pathlib import Path
import csv, json, sqlite3, ipaddress, re
from urllib.parse import urlparse
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parent
DATA=ROOT/"data"; DB=DATA/"dashboard.db"; CSV_FILE=DATA/"threat_intelligence_dataset.csv"
app=Flask(__name__)

SEV={"INFORMATIONAL":10,"LOW":25,"MEDIUM":50,"HIGH":75,"CRITICAL":95}
REL={"A":95,"B":80,"C":65,"D":40}
CVE_RE=re.compile(r"^CVE-\d{4}-\d{4,}$",re.I)
DOMAIN_RE=re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

def validate_indicator(value):
    v=(value or "").strip()
    try: ipaddress.ip_address(v); return {"valid":True,"indicator_type":"IP","normalized_value":v,"validation_notes":"Syntax valid; no network request made."}
    except ValueError: pass
    if CVE_RE.fullmatch(v): return {"valid":True,"indicator_type":"CVE","normalized_value":v.upper(),"validation_notes":"Syntax valid CVE identifier."}
    if len(v) in (32,40,64) and re.fullmatch(r"[0-9a-fA-F]+",v):
        return {"valid":True,"indicator_type":"FILE_HASH","normalized_value":v.lower(),"validation_notes":"Syntax-valid hash format."}
    u=urlparse(v)
    if u.scheme.lower() in ("http","https") and u.netloc:
        return {"valid":True,"indicator_type":"URL","normalized_value":v,"validation_notes":"Syntax valid; URL was not contacted."}
    if DOMAIN_RE.fullmatch(v.lower()):
        return {"valid":True,"indicator_type":"DOMAIN","normalized_value":v.lower(),"validation_notes":"Syntax valid domain."}
    return {"valid":False,"indicator_type":"UNKNOWN","normalized_value":v,"validation_notes":"Unrecognized syntax."}

def classify(score):
    if score<=20:return "INFORMATIONAL"
    if score<=40:return "LOW"
    if score<=60:return "MEDIUM"
    if score<=80:return "HIGH"
    return "CRITICAL"

def risk_score(severity,confidence,recency,observations,reliability,context):
    score=(SEV.get(severity,50)*.30+confidence*.25+recency*.15+min(100,observations*10)*.10+REL.get(reliability,40)*.10+context*.10)
    return round(max(0,min(100,score)),2)

def confidence_score(reliability,observations,validation,corroboration):
    return round(max(0,min(100,REL.get(reliability,40)*.35+min(100,observations*10)*.20+validation*.25+corroboration*.20)),2)

def db():
    DATA.mkdir(exist_ok=True); c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db()
    c.executescript("""CREATE TABLE IF NOT EXISTS threats(
    threat_id TEXT PRIMARY KEY, threat_name TEXT, category TEXT, description TEXT,
    severity TEXT, risk_score REAL, confidence_score REAL, status TEXT,
    first_seen TEXT,last_seen TEXT,indicator_type TEXT,indicator_value TEXT,
    source_name TEXT,source_reliability TEXT,mitre_tactic TEXT,mitre_technique TEXT);
    CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,threat_id TEXT,severity TEXT,
    risk_score REAL,confidence_score REAL,description TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT,threat_id TEXT,note TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS quiz_results(id INTEGER PRIMARY KEY AUTOINCREMENT,score REAL,created_at TEXT);""")
    c.commit();c.close()

def load():
    if not CSV_FILE.exists(): return []
    with CSV_FILE.open(encoding="utf-8",newline="") as f:return list(csv.DictReader(f))

def seed():
    init_db(); rs=load(); c=db(); c.execute("DELETE FROM threats"); c.execute("DELETE FROM alerts")
    for r in rs:
        c.execute("INSERT INTO threats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",tuple(r[x] for x in
        ["threat_id","threat_name","threat_category","description","severity","risk_score","confidence_score","status","first_seen","last_seen","indicator_type","indicator_value","source_name","source_reliability","mitre_tactic","mitre_technique"]))
        if float(r["risk_score"])>=75 or float(r["confidence_score"])>=90:
            c.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?,?)",(f"ALT-{r['threat_id']}",r["threat_id"],r["severity"],r["risk_score"],r["confidence_score"],"Synthetic intelligence crossed the demo alert threshold.","NEW",datetime.now(timezone.utc).isoformat()))
    c.commit();c.close()

def q(sql,args=()):
    c=db(); out=[dict(x) for x in c.execute(sql,args).fetchall()];c.close();return out

@app.get("/")
def home(): return render_template("index.html")

@app.get("/api/health")
def health(): return jsonify(status="ok",dataset_exists=CSV_FILE.exists())

@app.get("/api/dashboard/stats")
def stats():
    rs=load(); sev={};cat={};typ={};status={}
    for r in rs:
        for d,k in ((sev,r["severity"]),(cat,r["threat_category"]),(typ,r["indicator_type"]),(status,r["status"])): d[k]=d.get(k,0)+1
    return jsonify(total=len(rs),critical=sev.get("CRITICAL",0),high=sev.get("HIGH",0),
        active_indicators=sum(r["status"] in ("NEW","UNDER_REVIEW","MONITORING") for r in rs),
        open_investigations=sum(r["status"]=="UNDER_REVIEW" for r in rs),
        average_confidence=round(sum(float(r["confidence_score"]) for r in rs)/len(rs),2) if rs else 0,
        vulnerabilities_tracked=sum(r["indicator_type"]=="CVE ID" for r in rs),
        severity=sev,categories=cat,indicator_types=typ,statuses=status)

@app.get("/api/threats")
def threats():
    return jsonify(q("SELECT * FROM threats ORDER BY last_seen DESC LIMIT 100"))

@app.get("/api/threats/<tid>")
def detail(tid):
    r=q("SELECT * FROM threats WHERE threat_id=?",(tid,))
    if not r:return jsonify(error="Threat not found"),404
    r=r[0];r["alerts"]=q("SELECT * FROM alerts WHERE threat_id=?",(tid,));r["notes"]=q("SELECT * FROM notes WHERE threat_id=?",(tid,))
    return jsonify(r)

@app.get("/api/indicators/search")
def search():
    value=request.args.get("q",""); v=validate_indicator(value)
    found=q("SELECT * FROM threats WHERE indicator_value=? LIMIT 20",(v["normalized_value"],))
    return jsonify(validation=v,known_in_demo_dataset=bool(found),results=found)

@app.get("/api/alerts")
def alerts(): return jsonify(q("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100"))

@app.post("/api/threats/<tid>/notes")
def note(tid):
    data=request.get_json(silent=True) or {}; text=str(data.get("note","")).strip()
    if not text or len(text)>1000:return jsonify(error="Note must be 1-1000 characters"),400
    if not q("SELECT threat_id FROM threats WHERE threat_id=?",(tid,)):return jsonify(error="Threat not found"),404
    c=db();c.execute("INSERT INTO notes(threat_id,note,created_at) VALUES(?,?,?)",(tid,text,datetime.now(timezone.utc).isoformat()));c.commit();c.close()
    return jsonify(saved=True)

@app.get("/api/awareness/modules")
def modules(): return jsonify(json.loads((ROOT/"awareness_modules.json").read_text()))

@app.get("/api/quiz")
def quiz(): return jsonify(json.loads((ROOT/"quiz_questions.json").read_text()))

@app.post("/api/quiz/submit")
def quiz_submit():
    answers=(request.get_json(silent=True) or {}).get("answers",{})
    qs=json.loads((ROOT/"quiz_questions.json").read_text());correct=0;cats={}
    for x in qs:
        cats.setdefault(x["category"],[0,0]);cats[x["category"]][1]+=1
        if answers.get(str(x["id"]))==x["answer"]:correct+=1;cats[x["category"]][0]+=1
    score=round(correct/len(qs)*100,2); label="Needs Improvement" if score<=40 else "Basic Awareness" if score<=60 else "Good Awareness" if score<=80 else "Strong Awareness"
    c=db();c.execute("INSERT INTO quiz_results(score,created_at) VALUES(?,?)",(score,datetime.now(timezone.utc).isoformat()));c.commit();c.close()
    return jsonify(score=score,label=label,correct=correct,total=len(qs),category_scores={k:round(v[0]/v[1]*100,2) for k,v in cats.items()},recommended_modules=[k for k,v in cats.items() if v[0]/v[1]<.7])

if __name__=="__main__":
    if not CSV_FILE.exists():
        from generate_data import generate;generate(2000)
    init_db()
    if not q("SELECT threat_id FROM threats LIMIT 1"):seed()
    app.run(host="127.0.0.1",port=5000,debug=True)
