from agent.memory import scan_results
from agent.llm import query_llm

def generate_advice(item_type, item, risk, verdict):
    """
    Generate detailed human-like reasoning and security advice based on item history.
    """
    context = ""
    similar_items = [r for r in scan_results if r["type"]==item_type]
    if similar_items:
        context = f"Previously scanned {len(similar_items)} {item_type}(s) with similar characteristics."

    prompt = (
        f"You are a cybersecurity analyst. Analyze this {item_type}:\n"
        f"- Item: {item}\n"
        f"- Risk Score: {risk}%\n"
        f"- Verdict: {verdict}\n"
        f"{context}\n"
        "Provide a 3–5 sentence professional explanation of the risk, reputation, and advice for safe handling."
    )
    return query_llm(prompt)
