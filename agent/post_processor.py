
from sentient_agent_framework import ResponseHandler
from .memory import scan_results
from reasoning.analyzer import generate_advice
from .llm import query_llm

async def post_process_response(
    response_handler: ResponseHandler,
    command_result: dict,
    original_prompt: str
):
    """
    Formats the command results and streams the final output to the client.
    """
    command = command_result.get("command")
    
    await response_handler.emit_text_block(
        event_name="agent_status",
        content=f"**Processing Command:** {command.upper()}"
    )

    # --- SCAN COMMAND ---
    if command == "scan":
        item_type = command_result.get("target_type", "Item").upper()
        item = command_result.get("target_value", "N/A")
        risk = command_result.get("risk", "N/A")
        verdict = command_result.get("verdict", "N/A")
        
        await response_handler.emit_text_block(
            event_name="scan_result",
            content=f"**{item_type} Scan Completed:** Risk {risk}%, Verdict: {verdict}"
        )
        
        advice = generate_advice(item_type, item, risk, verdict)
        await response_handler.emit_text_block(
            event_name="scan_advice",
            content=f"**Security Advice:**\n{advice}"
        )

    # --- SUMMARY COMMAND ---
    elif command == "summary":
        if not scan_results:
            await response_handler.emit_text_block(
                event_name="scan_summary",
                content="No scan history available. Use a 'scan url' or attach a file first."
            )
        else:
            summary_text = "\n".join(
                [f" - {r['type'].upper()} {r['item']} → Risk {r['risk']}%, Verdict: {r['verdict']}" for r in scan_results]
            )
            await response_handler.emit_text_block(
                event_name="scan_summary",
                content=f"**Historical Scan Summary:**\n{summary_text}"
            )

    # --- ADVICE COMMAND ---
    elif command == "advice":
        query_item = command_result.get("target_value", "").strip()
        matched = [r for r in scan_results if query_item in r["item"] or query_item.lower() in r["item"].lower()]
        
        if matched:
            await response_handler.emit_text_block(
                event_name="advice_search",
                content=f"Found {len(matched)} matching historical scan result(s) for '{query_item}'. Generating advice..."
            )
            for item in matched:
                advice = generate_advice(item["type"], item["item"], item["risk"], item["verdict"])
                await response_handler.emit_text_block(
                    event_name=f"advice_for_{item['item']}",
                    content=f"**Advice for {item['type'].upper()} ({item['item']}):**\n{advice}"
                )
        else:
            await response_handler.emit_text_block(
                event_name="advice_llm_fallback",
                content=f"No matching item found in scan history. Consulting LLM for general advice on '{query_item}'."
            )
            advice_prompt = f"Provide general cybersecurity advice regarding '{query_item}' (it was not found in our history). Be brief."
            advice_from_llm = query_llm(advice_prompt)
            await response_handler.emit_text_block(
                event_name="general_advice",
                content=advice_from_llm
            )

    # --- GENERAL/LLM FALLBACK COMMAND ) ---
    elif command == "general":
        await response_handler.emit_text_block(
            event_name="general_query_start",
            content="Query does not match a specific command but is cybersecurity related. Consulting the LLM for an answer."
        )
        llm_response = query_llm(original_prompt)
        await response_handler.emit_text_block(
            event_name="final_answer",
            content=llm_response
        )
        
    # --- OUT OF SCOPE COMMAND  ---
    elif command == "out_of_scope":
        await response_handler.emit_text_block(
            event_name="out_of_scope_rejection",
            content=(
                "**Query Out of Scope:** My primary function is to perform security scans (URLs/files), provide advice, and answer questions specifically related to **cybersecurity** and **network safety**. I cannot answer general knowledge questions."
            )
        )

    # --- UNKNOWN COMMAND ---
    else:
        await response_handler.emit_text_block(
            event_name="unknown_command",
            content="Unknown command or unexpected parser output. Please rephrase your request."
        )
    
    await response_handler.complete()