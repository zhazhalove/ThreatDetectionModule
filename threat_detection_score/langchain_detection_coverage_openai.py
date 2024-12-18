from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.runnables import RunnablePassthrough
from langchain_core.tools import tool
from dotenv import load_dotenv
from threat_detection_score.input_sanitizer.sanitize import sanitize_input
from typing import Literal

import json, textwrap, typer, re


app = typer.Typer()


# def sanitize_input(input_message: str) -> str:
#     # Ensure the input is a string
#     if not isinstance(input_message, str):
#         raise typer.BadParameter("InputMessage must be a string.")
    
#     if not input_message.strip():
#         raise typer.BadParameter("InputMessage cannot be null, empty, or whitespace.")
    
#     # Define a regex pattern for allowed characters
#     allowed_pattern = r"^[a-zA-Z0-9\s.,-_]+$"
    
#     # Find invalid characters
#     invalid_characters = [
#         (char, idx) for idx, char in enumerate(input_message)
#         if not re.match(r"[a-zA-Z0-9\s.,-_]", char)
#     ]
    
#     if invalid_characters:
#         # Limit the number of violations reported
#         max_violations = 10
#         violation_details = ", ".join(
#             f"'{char}' at position {idx}" for char, idx in invalid_characters[:max_violations]
#         )
#         additional_violations = len(invalid_characters) - max_violations
#         if additional_violations > 0:
#             violation_details += f", and {additional_violations} more..."
        
#         raise typer.BadParameter(
#             f"InputMessage contains invalid characters: {violation_details}. "
#             "Only the following characters are allowed: " + r"[a-zA-Z0-9\s.,-_]"
#         )
    
#     # Return the original message if valid
#     return input_message

@app.command()
def main(
    human_message_input: str = typer.Option(
        ...,  # This indicates the option is required
        "--human-message-input",  # Specify the flag name
        "-i",  # Optional shorthand flag
        help="The input message describing the cybersecurity detection scenario.",
        callback=sanitize_input  # Use the sanitize_input function for validation
    )
):

    llm_model = "gpt-4o-mini"
    llm_temp = 0

    # load .env environment variables
    load_dotenv()

    system_prompt = """
    **Objective:** 
    As a Cybersecurity Threat Analyst powered by OpenAI, your mission is to evaluate cybersecurity detection requirements based on input scenarios. 
    Your assessments will hinge on a specific scoring chart that categorizes the adequacy and necessity of cybersecurity measures. 
    This chart details three levels of detection coverage—comprehensive (Score 0), requiring updates (Score 1), and lacking coverage (Score 2), alongside examples for clarity.

    **Task Overview:**

    1. **Interpret Input:** 
    Analyze the provided detection scenario. Determine the essence of the cybersecurity technique or threat described.

    2. **Reference Scoring Chart:**

    - Score 0 indicates existing, in-depth coverage for the specific technique, exemplified by traditional and well-integrated measures like antivirus signature detections, firewall rules, and email filtering systems.
    - Score 1 suggests that an existing detection requires updates or enhancements, reflecting scenarios where adjustments are needed to address new malware variants, sophisticated phishing attempts, or emerging threat IPs.
    - Score 2 signifies a gap in coverage, necessitating the development of new detection mechanisms or policies for novel threats, zero-day exploits, or previously uncovered attack vectors.
    - Scoring Chart examples

    | Score | Description                                                                          | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
    |-------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
    | 0     | In-depth coverage is already provided for this specific technique.                   | 1. Antivirus software detects malware based on signatures.<br>2. Firewall rules block known malicious IP addresses.<br>3. Intrusion detection systems (IDS) flag known exploit traffic.<br>4. Email filtering systems block phishing emails.<br>5. Web application firewalls (WAF) prevent SQL injection attacks.<br>6. Endpoint detection and response (EDR) tools identify and isolate ransomware.<br>7. Network segmentation prevents lateral movement.<br>8. Secure web gateways block access to malicious websites.<br>9. Data loss prevention (DLP) systems monitor and block sensitive data exfiltration.<br>10. Identity and access management (IAM) controls prevent unauthorized access.<br>11. Multi-factor authentication (MFA) thwarts credential stuffing attacks.<br>12. Security information and event management (SIEM) systems correlate threat indicators.<br>13. Application whitelisting allows only approved software to run.<br>14. Patch management systems keep software up to date.<br>15. Security awareness training reduces the risk of social engineering attacks. |
    | 1     | This technique requires an update to the scope of an existing detection.             | 1. Updating antivirus signatures to cover a new malware variant.<br>2. Adjusting firewall rules to block emerging threat IPs.<br>3. Tuning IDS to reduce false positives for exploit traffic.<br>4. Enhancing email filters to catch sophisticated phishing attempts.<br>5. Updating WAF rules to defend against new SQL injection techniques.<br>6. Refining EDR tool algorithms to better detect ransomware behavior.<br>7. Expanding network segmentation to additional critical assets.<br>8. Updating secure web gateway blacklists to include newly identified malicious sites.<br>9. Extending DLP monitoring to cover additional data types.<br>10. Adding new applications to the IAM policy.<br>11. Implementing additional factors in MFA to address new threats.<br>12. Updating SIEM correlation rules to include new indicators of compromise.<br>13. Adding recently released software to the application whitelist.<br>14. Accelerating patch deployment for critical vulnerabilities.<br>15. Refreshing security awareness training to address new phishing techniques. |
    | 2     | No coverage for this requirement exists. A new detection is required.                 | 1. Developing a detection mechanism for a zero-day exploit.<br>2. Creating new firewall rules for a previously unknown attack vector.<br>3. Implementing a new IDS signature for an emerging threat.<br>4. Designing a new email filtering rule to detect a novel phishing strategy.<br>5. Developing a new WAF rule set for an advanced web attack.<br>6. Creating a new EDR detection algorithm for a unique malware strain.<br>7. Establishing network segmentation for a newly identified critical asset.<br>8. Introducing a new category of websites to block in the secure web gateway.<br>9. Implementing a new DLP policy to protect against an emerging data exfiltration technique.<br>10. Adding coverage for a new application or system in IAM policies.<br>11. Introducing a new authentication method in response to a novel attack.<br>12. Creating new SIEM correlation rules for detecting previously unidentified activities.<br>13. Whitelisting a new, essential application not previously covered.<br>14. Developing a patch management strategy for a new piece of software.<br>15. Launching a new security awareness module on a recent cyber threat trend. |
    3. **Evaluation Criteria:** Compare the input scenario against the chart. Consider factors such as the novelty of the threat, the current scope of detection capabilities, and the potential for updating existing mechanisms versus the need for entirely new approaches.

    4. **Deliver a Verdict:** Based on your analysis, assign the correct score to the input scenario. Provide reasoning for your decision, drawing parallels with the examples given in the chart when applicable. This explanation should guide users in understanding the rationale behind the score, emphasizing how it aligns with the described examples and detection requirements.
    """

    @tool
    def detection_coverage(score: Literal[0, 1, 2], reason: str) -> None:
        """detection coverage ranking"""
        pass


    chat_template = ChatPromptTemplate.from_messages(
        [
            ("system", "{system_prompt}"),
            ("human", "{detection_requirement}"),
        ]
    )

    prompt = chat_template.partial(system_prompt=system_prompt)

    model = ChatOpenAI(model=llm_model, temperature=llm_temp)


    tools = [detection_coverage]

    chain = (
        {"detection_requirement": RunnablePassthrough()}
        | prompt
        | model.bind_tools(tools, tool_choice="detection_coverage")
    )


    llm_result = chain.invoke({"detection_requirement": human_message_input})


    score = llm_result.tool_calls[0]["args"]["score"]
    reason = llm_result.tool_calls[0]["args"]["reason"]

    result = {
    "score": score,
    "reason": "\n".join(textwrap.wrap(reason, width=80)),
    "type": "detection coverage"
    }

    print(json.dumps(result))

if __name__ == "__main__":
    app()