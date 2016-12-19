# Make it easier to attach to Microsoft Edge instance and setup the script.
Param([Parameter(Mandatory=$true)][string]$WinDbgPath)

If (-not (Test-Path $WinDbgPath)) {
    Throw "Invalid path to windbg.exe"
}

$p = Get-Process -Name MicrosoftEdgeCP
If ($p.Count -ne 1) {
    Write-Host "More than on MicrosoftEdgeCP so might spam windbg..."
}
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
ForEach ($pr in $p) {
    Write-Host ("Attaching to {0}" -f ($pr.Id))
	$args = '-p {0} -c "$<{1}"' -f ($pr.Id, (Join-Path $scriptPath "windbgscript.txt"))
	Start-Process -FilePath $WinDbgPath -ArgumentList $args
}