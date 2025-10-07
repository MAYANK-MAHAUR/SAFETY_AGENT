import os, hashlib, base64, requests
import tempfile
from .memory import log_scan
from .llm import query_llm

VT_HEADERS = {"x-apikey": "aa4da8b8960d2acdc39de701bf02392693f7e05ebf5aff68538b04cddb181f5a"}

def vt_check_url(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=VT_HEADERS)
        if resp.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=VT_HEADERS)
            return 0, "Pending"
        try:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        except ValueError:  
            return 0, "VT Response Invalid or Empty"
        score = stats.get("malicious",0)*10 + stats.get("suspicious",0)*5
        verdict = "Malicious" if stats.get("malicious",0)>0 else ("Suspicious" if stats.get("suspicious",0)>0 else "Safe")
        return score, verdict
    except Exception as e:
        return 0, f"VT Error: {str(e)}"

def vt_check_file(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=VT_HEADERS)
        if resp.status_code == 404:
            with open(file_path,"rb") as f:
                requests.post("https://www.virustotal.com/api/v3/files", files={"file":f}, headers=VT_HEADERS)
            return 0, "Pending"
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        score = stats.get("malicious",0)*10 + stats.get("suspicious",0)*5
        verdict = "Malicious" if stats.get("malicious",0)>0 else ("Suspicious" if stats.get("suspicious",0)>0 else "Safe")
        return score, verdict
    except Exception as e:
        return 0, f"VT Error: {str(e)}"

def scan_url(url):
    vt_score, vt_verdict = vt_check_url(url)
    ai_analysis = query_llm(f"Analyze this URL: {url}. Give risk 0-100% and verdict.")
    try:
        parts = ai_analysis.split("Risk:")[1].split("%")
        llm_score = int(parts[0].strip())
        llm_verdict = parts[1].split("Verdict:")[1].strip()
    except:
        llm_score = 0
        llm_verdict = ai_analysis.strip()
    total_risk = min(vt_score + llm_score, 100)
    verdict = llm_verdict if vt_verdict=="Pending" else vt_verdict
    log_scan("URL", url, total_risk, verdict)
    return total_risk, verdict

def scan_file(file_path):
    if not os.path.isfile(file_path):
        return None, "File not found."
    vt_score, vt_verdict = vt_check_file(file_path)
    ai_analysis = query_llm(f"Analyze file '{file_path}' for threats. Risk 0-100% and verdict.")
    try:
        parts = ai_analysis.split("Risk:")[1].split("%")
        llm_score = int(parts[0].strip())
        llm_verdict = parts[1].split("Verdict:")[1].strip()
    except:
        llm_score = 0
        llm_verdict = ai_analysis.strip()
    total_risk = min(vt_score + llm_score, 100)
    verdict = llm_verdict if vt_verdict=="Pending" else vt_verdict
    log_scan("File", file_path, total_risk, verdict)
    return total_risk, verdict


def get_local_file_path_from_id(file_id: str, session: object) -> str | None:
    """
    Retrieves the file content using the session and saves it to a temp path.
    """
    
    if os.path.exists(file_id):
        return file_id
    
    try:
        file_content_bytes = session.get_file_content(file_id) 

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_content_bytes)
            return tmp.name
            
    except Exception as e:
        print(f"File retrieval for ID {file_id} failed: {e}")
        return None


def scan_file(file_identifiers: list, session: object):
    """
    Scans a list of file IDs or local file paths using the session for retrieval.
    """
    if not file_identifiers:
        return 0, "No file identifier provided."
    
    overall_risk = 0
    overall_verdict = "Safe"
    
    for identifier in file_identifiers:
        file_path = get_local_file_path_from_id(identifier, session)
        
        if not file_path:
            log_scan("File", identifier, 0, "File Retrieval Failed")
            continue
        
        should_delete = not os.path.exists(identifier) 

        try:
            vt_score, vt_verdict = vt_check_file(file_path)
            
            ai_analysis = query_llm(f"Analyze file '{file_path}' for threats. Risk 0-100 and verdict.")
            
            try:
                parts = ai_analysis.split("Risk:")[1].split("%")
                llm_score = int(parts[0].strip())
                llm_verdict = parts[1].split("Verdict:")[1].strip()
            except:
                llm_score = 0
                llm_verdict = ai_analysis.strip()
                
            total_risk = min(vt_score + llm_score, 100)
            verdict = llm_verdict if vt_verdict=="Pending" else vt_verdict
            
            overall_risk = max(overall_risk, total_risk)
            if verdict in ["Malicious", "Suspicious"]:
                overall_verdict = verdict
            elif overall_verdict not in ["Malicious", "Suspicious"] and verdict == "Safe":
                overall_verdict = "Safe"
            
            log_scan("File", identifier, total_risk, verdict)

        finally:
            if should_delete and os.path.exists(file_path):
                os.remove(file_path) 
        
    return overall_risk, overall_verdict