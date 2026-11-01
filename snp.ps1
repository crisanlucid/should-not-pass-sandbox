# Windows launcher. Example: .\snp.ps1 -Elevate up
# -Elevate requests Windows UAC consent and writes output to .snp\elevated.log.
param(
    [switch]$Elevate,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SnpArgs
)
$ErrorActionPreference = 'Stop'

$statePath = if ($env:SNP_STATE_DIR) { $env:SNP_STATE_DIR } else { Join-Path $PSScriptRoot '.snp' }
for ($i = 0; $i -lt $SnpArgs.Count; $i++) {
    if ($SnpArgs[$i] -eq '--state-dir' -and $i + 1 -lt $SnpArgs.Count) { $statePath = $SnpArgs[$i + 1] }
    elseif ($SnpArgs[$i].StartsWith('--state-dir=')) { $statePath = $SnpArgs[$i].Substring(12) }
}
$python = $null
foreach ($candidate in @((Join-Path $statePath 'venv\Scripts\python.exe'), (Join-Path $PSScriptRoot '.snp\venv\Scripts\python.exe'))) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $python = (Resolve-Path -LiteralPath $candidate).Path; break }
}
$prefixArgs = @()
if (-not $python) {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) { $python = $launcher.Source; $prefixArgs = @('-3') }
    else {
        $interpreter = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $interpreter -or $interpreter.Source -like '*\Microsoft\WindowsApps\*') {
            throw 'Install Python 3.12+ from python.org, then open a new PowerShell window.'
        }
        $python = $interpreter.Source
    }
}
# Windows PowerShell 5.1 strips embedded double quotes from native arguments.
# Transport application argv as ASCII base64 and reconstruct it inside Python.
$applicationArgs = @((Join-Path $PSScriptRoot 'snp.py'))
if ($SnpArgs.Count) { $applicationArgs += $SnpArgs }
$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $applicationArgs -Compress)))
$bootstrap = "import base64,json,os,runpy,sys;sys.argv=json.loads(base64.b64decode(sys.argv[1]));sys.path.insert(0,os.path.dirname(sys.argv[0]));runpy.run_path(sys.argv[0],run_name='__main__')"
$arguments = @($prefixArgs) + @('-u', '-c', $bootstrap, $payload)
if (-not $Elevate) {
    & $python @arguments
    exit $LASTEXITCODE
}

function Quote-Literal([string]$value) { return "'" + $value.Replace("'", "''") + "'" }
$logFolder = Join-Path $PSScriptRoot '.snp'
New-Item -ItemType Directory -Force -Path $logFolder | Out-Null
$logPath = Join-Path $logFolder 'elevated.log'
$commandPath = Join-Path $logFolder ('elevated-' + [guid]::NewGuid().ToString('N') + '.ps1')
$resultPath = $commandPath + '.exit'
$command = '& ' + (Quote-Literal $python) + ' ' + (($arguments | ForEach-Object { Quote-Literal $_ }) -join ' ')
$script = "`$ErrorActionPreference = 'Continue'; `$env:PSModulePath = Join-Path `$PSHOME 'Modules'; Set-Location -LiteralPath $(Quote-Literal $PSScriptRoot); $command *> $(Quote-Literal $logPath); `$result = `$LASTEXITCODE; [System.IO.File]::WriteAllText($(Quote-Literal $resultPath), [string]`$result); exit `$result"
[System.IO.File]::WriteAllText($commandPath, $script, [Text.UTF8Encoding]::new($true))
$shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Write-Host "Windows will request Administrator consent. Output: $logPath"
try {
    $process = Start-Process -FilePath $shell -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $commandPath + '"'))
    # Start-Process -Wait also waits for the persistent background proxy.
    $process.WaitForExit()
    if (-not (Test-Path -LiteralPath $resultPath) -or (Get-Content -LiteralPath $resultPath -Raw).Trim() -ne [string]$process.ExitCode) {
        throw "The elevated command ended without a verified result. Inspect $logPath"
    }
    Get-Content -LiteralPath $logPath
    exit $process.ExitCode
}
finally {
    Remove-Item -LiteralPath $commandPath, $resultPath -Force -ErrorAction SilentlyContinue
}
