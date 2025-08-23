from mistralai import Mistral
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("MISTRAL_API_KEY")
client = Mistral(api_key=API_KEY)

def suggest_fixes(semgrep_results):
    suggestions = []
    for issue in semgrep_results:
        code_snippet = issue.get("code", "")
        file_name = issue.get("file", "unknown file")
        language = issue.get("language", "unknown language")
        rule = issue.get("rule", "N/A")  # fixed key
        severity = issue.get("severity", "info")
        message = issue.get("message", "Potential issue detected.")

        # Richer prompt
        prompt = f"""
You are a security expert. Analyze the following {language} code snippet from {file_name}.

Issue detected:
- Rule: {rule}
- Severity: {severity}
- Description: {message}

Code snippet:

Task:
1. Identify the vulnerability clearly.
2. Suggest a secure and efficient fix (show fixed code if possible).
3. Provide a short explanation of why the fix works.

Respond in professional, concise language without phrases like "I have...".
"""

        try:
            response = client.chat.complete(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": prompt}]
            )

            ai_content = response.choices[0].message.content if response.choices else "No response generated."

            suggestions.append({
                "file": file_name,
                "line": issue.get("line"),
                "rule": rule,
                "severity": severity,
                "message": message,
                "language": language,
                "code": code_snippet,
                "suggestion_md": ai_content  # Markdown output for frontend
            })

        except Exception as e:
            suggestions.append({
                "file": file_name,
                "line": issue.get("line"),
                "rule": rule,
                "severity": severity,
                "message": message,
                "language": language,
                "code": code_snippet,
                "suggestion_md": f"Error generating suggestion: {str(e)}"
            })

    return suggestions
