from sentient_agent_framework import AbstractAgent, ResponseHandler
from .vt_scan import scan_url, scan_file
from .query_processor import process_query
from .post_processor import post_process_response

class SafetyAgent(AbstractAgent):
    async def assist(self, session, query, response_handler: ResponseHandler):
        
        try:
            first_part = query.content.request_payload.parts[0]
            prompt = first_part.prompt
            file_ids = first_part.files_ids
        except (AttributeError, IndexError, TypeError):
            prompt = query.prompt
            file_ids = []

        command_params = process_query(prompt)
        command = command_params.get("command")
        target_value = command_params.get("target_value")
        
        command_result = command_params
        
        if command == "scan":
            item_type = command_params.get("target_type")
            
            if item_type == "url":
                risk, verdict = scan_url(target_value)
            
            elif item_type == "file":
                
              
                potential_identifiers = file_ids if file_ids else [target_value]

                identifiers_to_scan = [i for i in potential_identifiers if i is not None]
                
                if not identifiers_to_scan:
                    risk, verdict = 0, "Error: File scan requested but no file attached or name provided."
                    command_result["target_value"] = "N/A"
                else:
                    risk, verdict = scan_file(identifiers_to_scan, session) 
                    command_result["target_value"] = f"Files: {', '.join(identifiers_to_scan)}"
                
            else:
                risk, verdict = 0, "Error: Unknown scan target type."

            command_result.update({"risk": risk, "verdict": verdict})
        
        await post_process_response(
            response_handler,
            command_result,
            prompt 
        )