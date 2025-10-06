from sentient_agent_framework import AbstractAgent, ResponseHandler
from .vt_scan import scan_url, scan_file
from .memory import scan_results, log_scan
from reasoning.analyzer import generate_advice


class SafetyAgent(AbstractAgent):
    async def assist(self, session, query, response_handler: ResponseHandler):
        msg = query.prompt.lower().strip()

        if msg.startswith("scan url"):
            url = msg[9:].strip()
            risk, verdict = scan_url(url)
            await response_handler.emit_text_block(
                event_name="scan_result",
                content=f"URL Scan Completed: Risk {risk}%, Verdict: {verdict}"
            )
            advice = generate_advice("URL", url, risk, verdict)
            await response_handler.emit_text_block(
                event_name="scan_advice",
                content=advice
            )

        elif msg.startswith("scan file"):
            path = msg[10:].strip()
            risk, verdict = scan_file(path)
            await response_handler.emit_text_block(
                event_name="scan_result",
                content=f"File Scan Completed: Risk {risk}%, Verdict: {verdict}"
            )
            advice = generate_advice("File", path, risk, verdict)
            await response_handler.emit_text_block(
                event_name="scan_advice",
                content=advice
            )

        elif msg == "summary":
            if not scan_results:
                await response_handler.emit_text_block(
                    event_name="scan_summary",
                    content="No scans yet."
                )
                return
            summary_text = "\n".join(
                [f"{r['type']} {r['item']} → Risk {r['risk']}%, Verdict {r['verdict']}" for r in scan_results]
            )
            await response_handler.emit_text_block(
                event_name="scan_summary",
                content=f"Scan Summary:\n{summary_text}"
            )

        elif msg.startswith("advice for"):
            query_item = msg[10:].strip()
            matched = [r for r in scan_results if query_item in r["item"]]
            if matched:
                for item in matched:
                    advice = generate_advice(item["type"], item["item"], item["risk"], item["verdict"])
                    await response_handler.emit_text_block(
                        event_name="scan_advice",
                        content=advice
                    )
            else:
                await response_handler.emit_text_block(
                    event_name="scan_advice",
                    content="No matching item found in scan history."
                )

        else:
            await response_handler.emit_text_block(
                event_name="unknown_command",
                content=(
                    "Unknown command. Use:\n"
                    "- 'scan url <url>'\n"
                    "- 'scan file <path>'\n"
                    "- 'summary'\n"
                    "- 'advice for <item>'"
                )
            )
