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
        
        [Parameter(Mandatory = $false, HelpMessage = "The micromamba root prefix to use. Defaults to `$env:APPDATA\micromamba.")]
        [string]$MAMBA_ROOT_PREFIX = "$env:APPDATA\micromamba",

        [Parameter(Mandatory = $false)]
        [string[]]$Packages
    )


    try {
         # Validate input - throws exception if fails
        Test-InputMessage -InputMessage $InputMessage

        # Set MAMBA_ROOT_PREFIX environment variable
        Initialize-MambaRootPrefix -MAMBA_ROOT_PREFIX $MAMBA_ROOT_PREFIX

        # Dowload micromamaba
        if ( -not (Get-MicromambaBinary) ) {
            throw [System.Exception]::new("FAIL - Download micromamba")
        }
    
        # Build micromamba environment
        if ( -not (New-MicromambaEnvironment -EnvName $MicromambaEnvName -PythonVersion $PythonVersion) )
        {
            throw [System.Exception]::new("FAIL - Create micromamba environment - $MicromambaEnvName")
        }

        # Install micromamba environment python packages
        $PkgResults = Install-PackagesInMicromambaEnvironment -EnvName $MicromambaEnvName -Packages $Packages

        foreach($result in $PkgResults) {
            if (-not $result["Success"]) {
                throw [System.Exception]::new("$($result["PackageName"]) $($result["Success"])")
            }
        }
        
        # Execute the Python script
        $thdResult = Invoke-PythonScript -ScriptPath $Script -EnvName $MicromambaEnvName -Arguments "-i $InputMessage"

        if ($null -ne $thdResult) {
            return $thdResult
        } else {
            return "Failed to retrieve result from the Python script."
        }
    }
    catch {
        throw [System.Exception]::new("Error in Invoke-THDScore: $($_.Exception.Message)", $_.Exception)
    }
    finally {
        Remove-MicromambaEnvironment -EnvName $MicromambaEnvName | Out-Null
        Remove-Micromamba | Out-Null
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
        throw [System.Exception]::new("InputMessage cannot be null, empty, or whitespace.")
    }

    # Allow only safe characters (alphanumeric, space, and limited punctuation)
    if ($InputMessage -notmatch '^[a-zA-Z0-9\s\.\,\-_]+$') {

        # Find invalid characters
        $invalidChars = ($InputMessage -split '') | Where-Object { $_ -notmatch '[a-zA-Z0-9\s\.\,\-_]' }
        $invalidCharsList = ($invalidChars -join ', ')
        throw [System.Exception]::new("InputMessage contains invalid characters: $invalidCharsList")
    }
}

Export-ModuleMember -Function Invoke-THDScore, Test-InputMessage
