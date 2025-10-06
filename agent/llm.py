# =========================================================================
# File: llm.py
# =========================================================================

import openai
# You will also need to import requests to catch API errors properly
import requests  

openai.api_base = "https://qwen72b.gaia.domains/v1"
openai.api_key = "gaia-ZWFlMGYwNmQtNGVmYS00YmU5LTg1NGUtNzFlOTM3NWU3YzU2-cFu80IEd7q0m2z7j"

def query_llm(prompt):
    messages = [{"role": "user", "content": prompt}]
    
    # ADD THIS TRY...EXCEPT BLOCK
    try:
        response = openai.ChatCompletion.create(
            model="qwen72b",
            messages=messages,
            temperature=0.7,
            max_tokens=300
        )
        return response.choices[0].message['content']
    
    # Catching common API/network errors and printing them
    except (openai.error.OpenAIError, requests.exceptions.RequestException, Exception) as e:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"CRITICAL LLM API ERROR: {type(e).__name__}: {e}")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        # Return a simple, structured error response to prevent server crash
        return "Risk: 0% Verdict: LLM_API_FAILED"