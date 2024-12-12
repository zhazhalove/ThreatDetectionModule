<#
.SYNOPSIS
    Main function to invoke Threat Detection Score.

.DESCRIPTION
    This function orchestrates the validation of the micromamba environment and executes the Python script for Threat Detection Scoring.

.PARAMETER InputMessage
    The input message to pass to the Python script.

.PARAMETER Script
    Path to the Python script to execute. This is a mandatory parameter.

.PARAMETER PythonVersion
    The Python version to use within the micromamba environment. Defaults to 3.11.

.PARAMETER MicromambaEnvName
    The micromamba environment to use. Defaults to "langchain".

.PARAMETER MAMBA_ROOT_PREFIX
    The root prefix for the micromamba environment. Defaults to `$env:APPDATA`.

.PARAMETER Packages
    A string[] list of additional python packages to install into the mircomamba environment.

.EXAMPLE
    Invoke-THDScore -InputMessage "Sample input message" -Script "path\to\script.py"

.EXAMPLE
    Invoke-THDScore -InputMessage "Sample input message" -Script "path\to\script.py" -PythonVersion "3.10"

.EXAMPLE
    Invoke-THDScore -InputMessage "Sample input message" -Script "path\to\script.py" -PythonVersion "3.10" -Packages @("numpy", "pandas", "matplotlib")
#>
function Invoke-THDScore {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Input Message")]
        [string]$InputMessage,

        [Parameter(Mandatory = $true, HelpMessage = "Path to the Python script to execute.")]
        [string]$Script,
        
        [Parameter(Mandatory = $false, HelpMessage = "The Python version to use within the micromamba environment. Defaults to 3.11.")]
        [string]$PythonVersion = "3.11",
        
        [Parameter(Mandatory = $false, HelpMessage = "The micromamba environment to use. Defaults to `"langchain`".")]
        [string]$MicromambaEnvName = "langchain",
        
        [Parameter(Mandatory = $false, HelpMessage = "The micromamba environment to use. Defaults to `"langchain`".")]
        [string]$MAMBA_ROOT_PREFIX = "$env:APPDATA\micromamba",

        [Parameter(Mandatory = $false)]
        [string[]]$Packages
    )

    # Set MAMBA_ROOT_PREFIX environment variable
    $env:MAMBA_ROOT_PREFIX = $MAMBA_ROOT_PREFIX

    # Validate input
    Test-InputMessage -InputMessage $InputMessage

    # Ensure the micromamba environment is available
    if (-not (Test-MicromambaEnvironment -EnvName $MicromambaEnvName)) {
        Initialize-MicromambaEnvironment -EnvName $MicromambaEnvName -PythonVersion $PythonVersion -Packages $Packages
    }

    # Execute the Python script
    $thdResult = Invoke-PythonScript -ScriptPath $Script -EnvName $MicromambaEnvName -InputMessage $InputMessage

    if ($null -ne $thdResult) {
        # Write-Host "Score: $($thdResult.score)`n`nReason: $($thdResult.reason)" -ForegroundColor Green
        return "Score: $($thdResult.score)`n`nReason: $($thdResult.reason)"
    } else {
        # Write-Host "Failed to retrieve result from the Python script." -ForegroundColor Red
        return "Failed to retrieve result from the Python script."
    }
}


<#
.SYNOPSIS
    Validates and sanitizes the input message to prevent injection attacks.

.PARAMETER InputMessage
    The input message to validate and sanitize.

.EXAMPLE
    Test-InputMessage -InputMessage "Sample input"
#>
function Test-InputMessage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputMessage
    )

    # Check if the input is null, empty, or whitespace
    if ([string]::IsNullOrWhiteSpace($InputMessage)) {
        throw "InputMessage cannot be null, empty, or whitespace."
    }

    # Allow only safe characters (alphanumeric, space, and limited punctuation)
    if ($InputMessage -notmatch '^[a-zA-Z0-9\s\.\,\-_]+$') {

        # Find invalid characters
        $invalidChars = ($InputMessage -split '') | Where-Object { $_ -notmatch '[a-zA-Z0-9\s\.\,\-_]' }
        $invalidCharsList = ($invalidChars -join ', ')
        throw "InputMessage contains invalid characters: $invalidCharsList"
    }

    # # Escape remaining special characters if needed
    # $escapedMessage = $InputMessage -replace '[\`\$@<>\*\"''|;&\(\)\{\}\[\]\~\%\^\/]', {
    #     "`$_"
    # }

    # Output the sanitized input message
    Write-Host "Sanitized Input Message: $escapedMessage"
    return $escapedMessage
}

Export-ModuleMember -Function Invoke-THDScore, Test-InputMessage
