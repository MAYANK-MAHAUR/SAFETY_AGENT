# query_processor.py

import json
from .llm import query_llm

def is_cybsersecurity_query(prompt: str) -> bool:
    """
    Uses the LLM to determine if a query is relevant to the agent's domain.
    """
    relevance_prompt = (
        f"Is the following question primarily related to cybersecurity, malware, "
        f"internet safety, network security, or data privacy? Answer 'Yes' or 'No' ONLY. "
        f"Query: '{prompt}'"
    )
    
    response = query_llm(relevance_prompt).strip().lower()
    
    return response.startswith('yes') or response == 'yes'

def process_query(prompt: str) -> dict:
    """
    Analyzes the user's prompt using the LLM for robust Intent Classification 
    and Argument Extraction via JSON output.
    """
    system_prompt = (
        "You are an Intent Classifier and Argument Extractor for a cybersecurity agent. "
        "Analyze the user's prompt and determine the command and its parameters. "
        "Your command options are: 'scan', 'summary', 'advice', or 'general'. "
        
        "RULES FOR RESPONSE:\n"
        "1. Respond ONLY with a single valid JSON object.\n"
        "2. If the command is 'scan', set 'target_type' to 'url' or 'file', and 'target_value' to the extracted URL or file path.\n"
        "3. For 'summary' and 'general' commands, 'target_type' and 'target_value' should be null.\n"
    )
    
    llm_prompt = f"{system_prompt}\n\nUser Prompt to classify: {prompt}"

    try:
        full_llm_response = query_llm(llm_prompt)
        
       
        json_str = full_llm_response.strip()
        if json_str.startswith("```"):
             json_str = json_str.split('\n', 1)[-1].rsplit('\n', 1)[0]
        if json_str.startswith("json\n"):
             json_str = json_str[5:]
        
        parsed_command = json.loads(json_str)
        
        def safe_convert(key):
            value = parsed_command.get(key)
            if value is None:
                return None
            if isinstance(value, str) and value.lower().strip() in ["null", "none"]:
                return None
            return value

        if 'command' in parsed_command:
            command = parsed_command.get("command")
            
            parsed_command["target_type"] = safe_convert("target_type")
            parsed_command["target_value"] = safe_convert("target_value")
                
            if command == "general":
                is_relevant = is_cybsersecurity_query(prompt)
                if not is_relevant:
                    parsed_command["command"] = "out_of_scope" 
            
            return parsed_command
        
    except Exception as e:
        print(f"LLM parsing failed or validation error: {e}. Falling back to out-of-scope.")
        pass

    return {
        "command": "out_of_scope",
        "target_type": "llm",
        "target_value": prompt
    }