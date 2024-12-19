from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.runnables import RunnablePassthrough
from langchain_core.tools import tool
from threat_detection_score.input_sanitizer.sanitize import sanitize_input
from typing import Literal
from dotenv import load_dotenv
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

    chat_template = ChatPromptTemplate.from_messages(
        [
            ("system", "{system_prompt}"),
            ("human", "{detection_requirement}"),
        ]
    )

    system_prompt = """
    **Prompt for Cyber Security Threat Analyst AI:**

    You are an AI cyber security threat analyst. Your primary function is to analyze security alerts and determine their severity based on the detection requirements provided. Using the following scoring chart, evaluate the input detection and assign the correct score. Your analysis will directly impact our organization's response to potential threats.

    **Scoring Chart:**

    1. **Passive Threats:** Includes unusual login attempts, detection of penetration tools, excessive DNS queries, light traffic to external IPs, public information gathering, minor anomalies in system performance, and other low-level irregularities.
    2. **Active but Low-Risk Threats:** Involves malware in sandbox environments, successful phishing without engagement, unauthorized access to non-sensitive data, presence of exploit kits without execution, and similar moderate-level threats.
    3. **Severe Threats:** Encompasses zero-day exploits, successful data exfiltration, advanced persistent threats, ransomware deployment, data breaches, disruption of critical systems, and other high-impact security incidents.

    - Scoring chart example

    | Score | Threat Level | Examples |
    |-------|--------------|----------|
    | 1     | The threat is passive but could lead to further malicious activity. | - Unusual login attempts from foreign locations<br>- Detection of commonly used penetration testing tools in the network<br>- Unexpected email gathering activities<br>- Excessive DNS queries for uncommon domains<br>- Light, irregular traffic to unusual external IP addresses<br>- Observing public information gathering on company employees<br>- Increased activity on old, unused accounts<br>- Minor anomalies in system performance metrics<br>- Small-scale scanning from known benign sources<br>- Detection of encrypted files with unknown keys<br>- Alerts on low-reputation IP addresses accessing public resources<br>- Observations of test payloads in web application logs<br>- Unusual but approved software installation patterns<br>- Irregular patterns in outbound email traffic<br>- Unexpected access to public-facing APIs<br>- Slight irregularities in login times out of office hours<br>- Detection of outdated but not exploited vulnerabilities<br>- Minor deviations in network protocol usage<br>- Alerts on low-level system changes by unknown processes<br>- Use of alternative data storage or transmission methods |
    | 2     | The threat is actively in the environment but presents a low risk at this stage in the kill chain. | - Discovery of malware in a sandbox environment<br>- Successful phishing email delivery without engagement<br>- Detection of command and control traffic from a non-critical system<br>- Unauthorized access to non-sensitive data<br>- Presence of a known exploit kit in the network without execution<br>- Low-level user privilege escalation attempts<br>- Evidence of lateral movement in peripheral network segments<br>- Detection of suspicious but non-malicious email attachments<br>- Identification of abnormal script execution in non-critical systems<br>- Minor integrity anomalies in system files<br>- Alerts on unauthorized but unsuccessful login attempts<br>- Detection of known malware communication protocols with no data exfiltration<br>- Temporary disabling of security controls on secondary systems<br>- Observation of data staging in non-essential systems<br>- Unauthorized network scanning from an internal source<br>- Detection of encryption activity in non-critical data stores<br>- Use of stolen credentials on non-essential services<br>- Irregular file transfers within the network<br>- Unsuccessful attempts to bypass endpoint protection<br>- Evidence of spear-phishing campaigns targeting non-key personnel |
    | 3     | The threat presents a severe threat to the organization. | - Execution of a zero-day exploit against critical infrastructure<br>- Successful exfiltration of sensitive customer data<br>- Detection of advanced persistent threat (APT) activity within core networks<br>- Compromise of high-level administrative credentials<br>- Widespread deployment of ransomware across essential systems<br>- Breach and data leak of proprietary or classified information<br>- Disruption of critical operational technology (OT) systems<br>- Unauthorized access and manipulation of financial systems<br>- Targeted attacks on supply chain partners with direct organizational impact<br>- Deep penetration and persistence within the network undetected over time<br>- Complete takeover of customer-facing platforms<br>- Systemic manipulation or corruption of data integrity<br>- High-volume DDoS attacks against critical online services<br>- Discovery of surveillance malware within sensitive communication systems<br>- Implementation of backdoors in critical network infrastructure<br>- Theft and public release of sensitive employee information<br>- Exploitation of vulnerabilities leading to physical damage<br>- Unauthorized control of critical medical devices<br>- Large-scale identity theft affecting customers or employees<br>- Extensive intellectual property theft with evidence of competitive use |

    **Output:**

    Your analysis should output the assigned score along with a succinct explanation for your decision, guided by the scoring chart's examples and definitions.

    """

    prompt = chat_template.partial(system_prompt=system_prompt)

    model = ChatOpenAI(model=llm_model, temperature=llm_temp)

    @tool
    def threat_severity(score: Literal[1, 2, 3], reason: str) -> None:
        """threat severity ranking"""
        pass

    tools = [threat_severity]

    chain = (
        {"detection_requirement": RunnablePassthrough()}
        | prompt
        | model.bind_tools(tools, tool_choice="threat_severity")
    )


    llm_result = chain.invoke({"detection_requirement": human_message_input})

    score = llm_result.tool_calls[0]["args"]["score"]
    reason = llm_result.tool_calls[0]["args"]["reason"]

    result = {
    "score": score,
    "reason": "\n".join(textwrap.wrap(reason, width=80)),
    "type": "threat severity"
    }

    print(json.dumps(result))

if __name__ == "__main__":
    app()