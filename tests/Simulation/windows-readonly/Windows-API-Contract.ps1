# Non-mutating Windows command/parameter contract test for Windows PowerShell 5.1.
# Optional -SourceRoot checks source code for known-invalid NetSecurity calls.
[CmdletBinding()]
param([string]$SourceRoot = '')
$ErrorActionPreference='Stop'
$results = New-Object 'System.Collections.Generic.List[object]'
function AddResult([string]$id,[string]$result,[string]$detail) {
    $results.Add([pscustomobject]@{Id=$id;Result=$result;Detail=$detail}) | Out-Null
}
function CheckCommand([string]$name,[string[]]$required,[string[]]$forbidden) {
    try {
        $cmd = Get-Command $name -ErrorAction Stop
        foreach ($p in $required) {
            if ($cmd.Parameters.ContainsKey($p)) { AddResult ($name+'/'+$p) 'PASS' 'Named parameter exists on actual Windows host' }
            else { AddResult ($name+'/'+$p) 'FAIL' 'Required parameter is missing' }
        }
        foreach ($p in $forbidden) {
            if ($cmd.Parameters.ContainsKey($p)) { AddResult ($name+'/Forbidden-'+$p) 'FAIL' 'Unexpected forbidden parameter exists: investigate version' }
            else { AddResult ($name+'/Forbidden-'+$p) 'PASS' 'Invalid parameter is correctly rejected by command metadata' }
        }
    } catch { AddResult ($name+'/Discovery') 'FAIL' $_.Exception.Message }
}
CheckCommand 'Set-NetFirewallAddressFilter' @('InputObject','RemoteAddress') @('AssociatedNetFirewallRule')
CheckCommand 'Get-NetFirewallAddressFilter' @('AssociatedNetFirewallRule') @()
CheckCommand 'Set-NetFirewallRule' @('RemoteAddress','Profile','Enabled','Name') @()
CheckCommand 'New-NetFirewallRule' @('Enabled','Profile','RemoteAddress','Protocol','LocalPort','Name') @()
CheckCommand 'Get-NetAdapterBinding' @('ComponentID') @()
CheckCommand 'Get-NetTCPConnection' @('State','LocalPort') @()
CheckCommand 'Get-NetFirewallRule' @('Name','PolicyStore') @()
CheckCommand 'Get-NetFirewallProfile' @('Name') @()
CheckCommand 'Get-NetIPConfiguration' @() @()
if ($SourceRoot) {
    if (-not (Test-Path $SourceRoot -PathType Container)) {
        AddResult 'SourceAudit' 'FAIL' ('Folder not found: ' + $SourceRoot)
    } else {
        $bad = @()
        $files = @(Get-ChildItem -Path $SourceRoot -Recurse -File -ErrorAction Stop | Where-Object { $_.Extension -in '.cs','.ps1' })
        foreach ($f in $files) {
            $hits = @(Select-String -Path $f.FullName -Pattern 'Set-NetFirewallAddressFilter\s+-AssociatedNetFirewallRule' -AllMatches -ErrorAction SilentlyContinue)
            foreach ($hit in $hits) { $bad += ($f.FullName + ':' + $hit.LineNumber) }
        }
        if ($bad.Count -gt 0) { AddResult 'SourceAudit-InvalidSetNetFirewallAddressFilter' 'FAIL' ($bad -join '; ') }
        else { AddResult 'SourceAudit-InvalidSetNetFirewallAddressFilter' 'PASS' ('No known invalid parameter pattern in '+$files.Count+' files') }
    }
}
try {
    $rule = Get-NetFirewallRule -Name 'FPS-*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $rule) {
        AddResult 'ActualFirewallRuleEnabledType' 'OBSERVED' ('Type='+$rule.Enabled.GetType().FullName+' Value='+[string]$rule.Enabled)
    } else { AddResult 'ActualFirewallRuleEnabledType' 'NOT_TESTED' 'No FPS rule available; do not infer a type' }
} catch { AddResult 'ActualFirewallRuleEnabledType' 'UNKNOWN' $_.Exception.Message }
$out=Join-Path $env:TEMP ('MyPC-PrintDoctor-API-Contract-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')
@{host=$env:COMPUTERNAME;timestamp_utc=[DateTimeOffset]::UtcNow.ToString('o');method='READ_ONLY_CMDLET_PARAMETER_DISCOVERY';results=@($results)} |
    ConvertTo-Json -Depth 5 | Set-Content -Path $out -Encoding UTF8
$results | Format-Table -AutoSize
Write-Host ('REPORT: '+$out)
if (@($results | Where-Object {$_.Result -eq 'FAIL'}).Count -gt 0) { exit 1 }
exit 0
