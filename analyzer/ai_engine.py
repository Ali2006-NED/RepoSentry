import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=API_KEY)

# Use Gemini model (flash = cheaper/faster, pro = better reasoning)
model = genai.GenerativeModel("gemini-1.5-flash")

def suggest_fixes(semgrep_results):
    suggestions = []
    for issue in semgrep_results:
        code_snippet = issue.get("code", "")
        file_path = issue.get("file", "unknown file")
        file_name = os.path.basename(file_path)
        language = issue.get("language", "unknown language")
        rule = issue.get("rule", "N/A")
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
{code_snippet}

Task:
1. Identify the vulnerability clearly.
2. Suggest a secure and efficient fix (show fixed code if possible).
3. Provide a short explanation of why the fix works.

return results with proper headings and subheadings.

Respond in professional, concise language without phrases like "I have...".
"""

        try:
            # Gemini API call
            response = model.generate_content([prompt])

            ai_content = response.text if response else "No response generated."

            suggestions.append({
                "file": file_name,
                "line": issue.get("line"),
                "rule": rule,
                "severity": severity,
                "message": message,
                "language": language,
                "code": code_snippet,
                "suggestion_md": ai_content
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
