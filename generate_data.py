
from pathlib import Path
import csv,random,hashlib
from datetime import datetime,timedelta
OUT=Path(__file__).parent/"threat_intelligence_dataset.csv"
CATS=["PHISHING","MALWARE","RANSOMWARE","CREDENTIAL THREATS","WEB THREATS","NETWORK THREATS","VULNERABILITY EXPOSURE","SOCIAL ENGINEERING","DATA EXPOSURE","ACCOUNT SECURITY"]
SEVS=["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"]; TYPES=["IP ADDRESS","DOMAIN","URL","FILE HASH","EMAIL/SENDER DOMAIN","CVE ID"]
SOURCES=[("Internal SOC","A"),("Security Vendor","B"),("Public Threat Feed","B"),("Research Report","C"),("Community Submission","C"),("Unknown Source","D")]
STATUS=["NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"]; TACT=["Initial Access","Credential Access","Discovery","Command and Control","Exfiltration"]; TECH=["Phishing","Valid Accounts","Network Service Discovery","Application Layer Protocol","Data from Local System"]
def indicator(t,i):
    if t=="IP ADDRESS":return f"192.0.2.{i%254+1}"
    if t=="DOMAIN":return ["example.com","example.org","example.net","demo.invalid"][i%4]
    if t=="URL":return f"https://example.com/demo/{i}"
    if t=="FILE HASH":return hashlib.sha256(f"SYNTHETIC-{i}".encode()).hexdigest()
    if t=="EMAIL/SENDER DOMAIN":return ["example.com","example.org"][i%2]
    return f"CVE-2026-{1000+i%8000:04d}"
def generate(n=2000):
    random.seed(42); rows=[];base=datetime(2026,1,1); sv={"INFORMATIONAL":10,"LOW":25,"MEDIUM":50,"HIGH":75,"CRITICAL":95}; rel={"A":95,"B":80,"C":65,"D":40}
    for i in range(1,n+1):
        cat=random.choice(CATS);it=random.choice(TYPES);sev=random.choices(SEVS,[5,20,35,30,10])[0];src,rr=random.choice(SOURCES);conf=random.randint(35,98);obs=random.randint(1,12);rec=random.randint(20,100);ctx=random.randint(20,100)
        risk=round(min(100,sv[sev]*.30+conf*.25+rec*.15+min(100,obs*10)*.10+rel[rr]*.10+ctx*.10),2);first=base-timedelta(days=random.randint(0,365));last=first+timedelta(days=random.randint(0,30))
        rows.append({"threat_id":f"THR-2026-{i:05d}","threat_name":f"Synthetic {cat.title()} Observation","threat_category":cat,"indicator_type":it,"indicator_value":indicator(it,i),"source_name":src,"source_reliability":rr,"confidence_score":conf,"severity":sev,"risk_score":risk,"status":random.choice(STATUS),"first_seen":first.date().isoformat(),"last_seen":last.date().isoformat(),"description":"SYNTHETIC / DEMO ONLY. Defensive analytics record.","mitre_tactic":random.choice(TACT),"mitre_technique":random.choice(TECH)})
    with OUT.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
if __name__=="__main__":generate(2000);print(OUT)
