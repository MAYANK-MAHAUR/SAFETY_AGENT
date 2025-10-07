# 🛡️ Guardian Sentinel Agent

## Overview

The **Guardian Sentinel** is a specialized, multi-stage cybersecurity agent developed on the Sentient Agent Framework. It serves as the initial security gate, using advanced **LLM-driven intent classification** and external **VirusTotal** threat intelligence to secure conversations by analyzing URLs and files.

**Repository:** [https://github.com/MAYANK-MAHAUR/SAFETY\_AGENT.git](https://github.com/MAYANK-MAHAUR/SAFETY_AGENT.git)

-----

## ⚙️ Architecture Deep Dive (Phase 1)

The agent’s workflow is highly modular, ensuring security, stability, and future scalability.

### 1\. Request Orchestration (`safety_agent.py`)

This is the central coordinator.

  * **Input Handling:** It is the first module to receive the framework's `session` and `query` objects. It securely extracts the user's `prompt` and any attached **`file_ids`** from the request payload.
  * **Error Prevention:** It includes critical logic to filter out `None` values, preventing common runtime errors (`TypeError`) before execution.
  * **Flow Control:** Passes control to the `query_processor` and then executes the core scanning or reporting based on the classified command.

### 2\. Intent Classification (`query_processor.py`)

This module provides the intelligence for the agent's actions.

  * **LLM Interface:** Sends the user's natural language prompt to the LLM to classify intent (`scan`, `summary`, etc.) and extract parameters (`target_value`, `target_type`).
  * **Parsing Safety:** Implements a robust `safe_convert` function to guarantee that LLM output (which might be `null` or a string `"null"`) is correctly converted to Python's `None`, ensuring stability.
  * **Domain Filtering:** Prevents the agent from wasting resources on non-cybersecurity questions.

### 3\. Core Scanning Logic (`vt_scan.py`)

This is the execution powerhouse for threat analysis.

  * **URL Scanning:** Processes a single URL by checking VirusTotal and generating a composite risk score (VT Score + LLM Contextual Score).
  * **File ID $\rightarrow$ Content Solution:** This is the critical mechanism for file attachments:
    1.  It receives the file's **ID** (e.g., a ULID) and the **`session`** object.
    2.  It uses the framework capability **`session.get_file_content(file_id)`** to securely retrieve the raw binary content from the server.
    3.  It saves the binary content to a **temporary local file path** for VT scanning.
    4.  It ensures the temporary file is **immediately deleted** after scanning for security.
  * **API Stability (`llm.py`):** The LLM dependency includes essential `try...except` blocks to prevent crashes during API connection or timeout failures.

### 4\. Output & Streaming (`post_processor.py`)

Handles all user-facing output, formatting scan results, history, and advice, and streaming them back to the user via the `ResponseHandler`.

-----

## 🧪 Postman Testing Guide

You can test the agent's core intent classification and URL scanning capabilities using the following request structure.

### Request Details

| Field | Value |
| :--- | :--- |
| **Method** | `POST` |
| **URL** | `http://127.0.0.1:8000/assist` (or your deployment URL) |
| **Content-Type** | `application/json` |

### JSON Request Body

This test case challenges the LLM to classify intent and extract URLs from a complex sentence.

```json
{
    "session": {
        "processor_id": "sentient-chat-client",
        "activity_id": "01K6BEMNWZFMP3RMGJTFZBND2N",
        "request_id": "01K6BEPKY12FMR1S19Y3SE01C6",
        "interactions": []
    },
    "query": {
        "id": "01K6BEMZ2QZQ58ADNDCKBPKD51",
        "prompt": "is this site safe? hianime.to"
        "context": ""
    }
}
```

### Expected Agent Behavior & Output

| Stage | Expected Action | Notes |
| :--- | :--- | :--- |
| **Intent (LLM)** | Command classified as **`scan`**, Target Type: **`url`**. | The agent recognizes the security question. |
| **Extraction** | The LLM will extract **one primary URL** (likely `hianime.to` or `youtube.com`). | *Limitation:* The current phase is designed to extract a single target URL from a prompt. |
| **Execution** | `scan_url()` is called with the extracted URL. The VirusTotal and LLM scores are calculated. | The final risk score and verdict are determined. |
| **Output** | The agent streams the result using `post_processor.py`. | **Output will include:** `agent_status` $\rightarrow$ `scan_result` $\rightarrow$ `scan_advice`. |

-----

*Note: To test **File Scanning**, you must use the official Sentient Chat UI to upload a file, as the request payload will automatically include the required `file_ids` list, which cannot be reliably faked in a simple Postman call.*


