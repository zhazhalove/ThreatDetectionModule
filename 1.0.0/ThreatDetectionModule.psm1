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
Sets the MAMBA_ROOT_PREFIX environment variable for micromamba.

.DESCRIPTION
The `Initialize-MambaRootPrefix` function sets the environment variable `MAMBA_ROOT_PREFIX` to the specified path for micromamba. If no path is specified, it defaults to the `$env:APPDATA\micromamba` directory. This environment variable is typically used by micromamba to define the root directory for its environments.

.PARAMETER MAMBA_ROOT_PREFIX
The path to set for the `MAMBA_ROOT_PREFIX` environment variable. If not provided, the function defaults to `$env:APPDATA\micromamba`.

.EXAMPLE
Initialize-MambaRootPrefix -MAMBA_ROOT_PREFIX "C:\mamba"
This will set the `MAMBA_ROOT_PREFIX` environment variable to "C:\mamba".

.EXAMPLE
Initialize-MambaRootPrefix
This will set the `MAMBA_ROOT_PREFIX` environment variable to the default value of `$env:APPDATA\micromamba`.

.NOTES
https://mamba.readthedocs.io/en/latest/user_guide/concepts.html#root-prefix
#>
function Initialize-MambaRootPrefix {
    param (
        [Parameter(Mandatory = $false)]
        [string]$MAMBA_ROOT_PREFIX = "$env:APPDATA\micromamba"
    )
    # Set MAMBA_ROOT_PREFIX environment variable
    $env:MAMBA_ROOT_PREFIX = $MAMBA_ROOT_PREFIX
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

.PARAMETER TrustedHost
    A switch parameter to trust the certificate for pip installation. 
    If provided, adds the --trusted-host flag to the pip install command for trusted hosts (pypi.org and files.pythonhosted.org).
    https://pip.pypa.io/en/stable/topics/https-certificates/#

.EXAMPLE
    Install-PackagesInMicromambaEnvironment -EnvName "langchain" -Packages @("numpy", "pandas", "matplotlib")

.EXAMPLE
Install-PackagesInMicromambaEnvironment -EnvName "langchain" -Packages @("numpy", "pandas") -TrustedHost
#>
function Install-PackagesInMicromambaEnvironment {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EnvName,

        [Parameter(Mandatory = $true)]
        [string[]]$Packages,

        [Parameter()]
        [switch]$TrustedHost
    )

    # Initialize an array to store results
    [PSCustomObject[]]$results = @()

    # Write-Host "Installing packages in micromamba environment: $EnvName" -ForegroundColor Yellow

    foreach ($package in $Packages) {
        # Write-Host "Installing package: $package" -ForegroundColor Green

        try {
            if ($TrustedHost) {
                # Run the install command with trusted hosts
                & "$PSScriptRoot\micromamba" run -n $EnvName pip install $package --trusted-host pypi.org --trusted-host files.pythonhosted.org | Out-Null
            }
            else {
                # Run the install command without trusted hosts
                & "$PSScriptRoot\micromamba" run -n $EnvName pip install $package | Out-Null
            }

            # Check if the installation was successful
            if ($LASTEXITCODE -eq 0) {
                # Add success result for this package
                $results += [PSCustomObject]@{
                    PackageName = $package
                    Success     = $true
                }
                # Write-Host "Successfully installed package: $package" -ForegroundColor Cyan
            }
            else {
                # Add failure result for this package
                $results += [PSCustomObject]@{
                    PackageName = $package
                    Success     = $false
                }
                # Write-Host "Failed to install package: $package" -ForegroundColor Red
            }
        }
        catch {
            # In case of an exception, log the failure for this package
            $results += [PSCustomObject]@{
                PackageName = $package
                Success     = $false
            }
            # Write-Host "Error installing package: $package" -ForegroundColor Red
        }
    }

    # Write-Host "Package installation complete for environment: $EnvName" -ForegroundColor Yellow

    return $results
}



<#
.SYNOPSIS
    Creates the micromamba environment.

.PARAMETER EnvName
    The name of the micromamba environment to create. Required

.PARAMETER PythonVersion
    The Python version to use for the environment. Defaults to 3.11

.PARAMETER TrustedHost
    A switch parameter to trust the certificate for pip installation. 
    If provided, adds the --trusted-host flag to the pip install command for trusted hosts (pypi.org and files.pythonhosted.org).
    https://pip.pypa.io/en/stable/topics/https-certificates/#

.EXAMPLE
    Initialize-MicromambaEnvironment -EnvName "langchain"

.EXAMPLE
    Initialize-MicromambaEnvironment -EnvName "langchain" -PythonVersion "3.11" -TrustedHost
#>
function New-MicromambaEnvironment {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EnvName,

        [Parameter(Mandatory = $false)]
        [string]$PythonVersion = '3.11',

        [Parameter()]
        [switch]$TrustedHost
    )

    # Write-Host "Creating micromamba environment: $EnvName" -ForegroundColor Yellow

    if ($TrustedHost) {
        # redirect output since uipath captures the output
        & "$PSScriptRoot\micromamba" create -n $EnvName --yes --ssl-verify False python=$PythonVersion pip -c conda-forge | Out-Null
    }
    else {
        # redirect output since uipath captures the output
        & "$PSScriptRoot\micromamba" create -n $EnvName --yes python=$PythonVersion pip -c conda-forge | Out-Null
    }
 
    if ($LASTEXITCODE -eq 0) {
        # Write-Host "Created the micromamba environment: $EnvName" -ForegroundColor Green
        $true
    }
    else {
        # Write-Host "Failed to create the micromamba environment: $EnvName" -ForegroundColor Red
        $false
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

Export-ModuleMember -Function Initialize-MambaRootPrefix, Invoke-THDScore, Install-PackagesInMicromambaEnvironment, Test-InputMessage, Test-MicromambaEnvironment, New-MicromambaEnvironment, Invoke-PythonScript
