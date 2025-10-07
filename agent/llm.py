
import openai
import requests  

openai.api_base = "https://qwen72b.gaia.domains/v1"
openai.api_key = "gaia-ZWFlMGYwNmQtNGVmYS00YmU5LTg1NGUtNzFlOTM3NWU3YzU2-cFu80IEd7q0m2z7j"

def query_llm(prompt):
    messages = [{"role": "user", "content": prompt}]
    
    try:
        response = openai.ChatCompletion.create(
            model="qwen72b",
            messages=messages,
            temperature=0.7,
            max_tokens=300
        )
        return response.choices[0].message['content']
    
    except (openai.error.APIError, requests.exceptions.RequestException) as e:
        print(f"LLM API Error: {e}")
        return "ERROR: Could not contact external AI service for analysis."
    except Exception as e:
        print(f"An unexpected error occurred during LLM call: {e}")
        return "ERROR: An internal error occurred during AI processing."