import re
import typer

def sanitize_input(input_message: str) -> str:
    # Ensure the input is a string
    if not isinstance(input_message, str):
        raise typer.BadParameter("InputMessage must be a string.")
    
    if not input_message.strip():
        raise typer.BadParameter("InputMessage cannot be null, empty, or whitespace.")
    
    # Define a regex pattern for allowed characters
    allowed_pattern = r"^[a-zA-Z0-9\s.,-_]+$"
    
    # Find invalid characters
    invalid_characters = [
        (char, idx) for idx, char in enumerate(input_message)
        if not re.match(r"[a-zA-Z0-9\s.,-_]", char)
    ]
    
    if invalid_characters:
        # Limit the number of violations reported
        max_violations = 10
        violation_details = ", ".join(
            f"'{char}' at position {idx}" for char, idx in invalid_characters[:max_violations]
        )
        additional_violations = len(invalid_characters) - max_violations
        if additional_violations > 0:
            violation_details += f", and {additional_violations} more..."
        
        raise typer.BadParameter(
            f"InputMessage contains invalid characters: {violation_details}. "
            "Only the following characters are allowed: " + r"[a-zA-Z0-9\s.,-_]"
        )
    
    # Return the original message if valid
    return input_message
