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



<#
.SYNOPSIS
    Checks if the specified micromamba environment exists.

.PARAMETER EnvName
    The name of the micromamba environment to check.

.RETURNS
    [bool] indicating if the environment exists.

.EXAMPLE
    Test-MicromambaEnvironment -EnvName "langchain"
#>
function Test-MicromambaEnvironment {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EnvName
    )
    $pattern = "^\s*$EnvName\s*"
    $envList = & "$PSScriptRoot\micromamba" env list | Select-String -Pattern $pattern
    return ($null -ne $envList -and $envList.Matches.Success -and $envList.Matches.Groups[0].Value.Trim() -eq $EnvName)
}

<#
.SYNOPSIS
    Installs a list of packages in a micromamba environment.

.PARAMETER EnvName
    The name of the micromamba environment where the packages will be installed.

.PARAMETER Packages
    A list of package names to be installed.

.EXAMPLE
    Install-PackagesInMicromambaEnvironment -EnvName "langchain" -Packages @("numpy", "pandas", "matplotlib")
#>
function Install-PackagesInMicromambaEnvironment {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EnvName,
        [Parameter(Mandatory = $true)]
        [string[]]$Packages
    )

    Write-Host "Installing package in micromamba environment: $EnvName" -ForegroundColor Yellow

    foreach ($package in $Packages) {
        Write-Host "Installing package: $package" -ForegroundColor Green
        # redirect output since uipath captures the output
        & "$PSScriptRoot\micromamba" run -n $EnvName pip install $package | Out-Null

        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to install package: $package" -ForegroundColor Red
            break
        }
    }

    Write-Host "Package installation complete for environment: $EnvName" -ForegroundColor Yellow
}


<#
.SYNOPSIS
    Initializes the micromamba environment.

.PARAMETER EnvName
    The name of the micromamba environment to create.

.PARAMETER PythonVersion
    The Python version to use for the environment.

.PARAMETER Packages
    A string[] list of python packages to install into the mircomamba environment.


.EXAMPLE
    Initialize-MicromambaEnvironment -EnvName "langchain" -PythonVersion "3.11" -Packages @("numpy", "pandas", "scipy")
#>
function Initialize-MicromambaEnvironment {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EnvName,
        [Parameter(Mandatory = $true)]
        [string]$PythonVersion,
        [Parameter(Mandatory = $false)]
        [string[]]$Packages
    )
    Write-Host "Creating micromamba environment: $EnvName" -ForegroundColor Yellow

    # redirect output since uipath captures the output
    & "$PSScriptRoot\micromamba" create -n $EnvName --yes python=$PythonVersion pip -c conda-forge | Out-Null

    if ($LASTEXITCODE -eq 0 -and $Packages) {
        Install-PackagesInMicromambaEnvironment -EnvName $EnvName -Packages $Packages
    } elseif ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to create the micromamba environment: $EnvName" -ForegroundColor Red
    }
}

<#
.SYNOPSIS
    Executes the specified Python script within the micromamba environment.

.PARAMETER ScriptPath
    The full path to the Python script.

.PARAMETER EnvName
    The micromamba environment to use.

.PARAMETER InputMessage
    The input message to pass to the script.

.RETURNS
    [PSCustomObject] with the script results.

.EXAMPLE
    Invoke-PythonScript -ScriptPath "script.py" -EnvName "langchain" -InputMessage "Hello World"
#>
function Invoke-PythonScript {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$EnvName,
        [Parameter(Mandatory = $true)]
        [string]$InputMessage
    )

    Write-Host "Executing Python script: $ScriptPath" -ForegroundColor Yellow
    try {
        $finalResult = & "$PSScriptRoot\micromamba" run -n $EnvName python $ScriptPath --human-message-input "`"$InputMessage`"" | ConvertFrom-Json
        return $finalResult
    } catch {
        Write-Host "Error running Python script: $_" -ForegroundColor Red
        return $null
    }
}

Export-ModuleMember -Function Invoke-THDScore, Install-PackagesInMicromambaEnvironment, Test-InputMessage, Test-MicromambaEnvironment, Initialize-MicromambaEnvironment, Invoke-PythonScript
