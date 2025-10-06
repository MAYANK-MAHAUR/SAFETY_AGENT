scan_results = []

def log_scan(item_type, item, risk_score, verdict):
    scan_results.append({"type": item_type, "item": item, "risk": risk_score, "verdict": verdict})
