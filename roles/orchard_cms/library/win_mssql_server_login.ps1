#!powershell

# WANT_JSON
# POWERSHELL_COMMON

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

$result = @{changed = $false}

$parsed_args = Parse-Args $args -supports_check_mode $true

$server_name = Get-AnsibleParam $parsed_args "server_name" -default "(local)"
$server_login_name = Get-AnsibleParam $parsed_args "name" -failifempty $result
$server_login_type = Get-AnsibleParam $parsed_args "login_type" -failifempty $result -ValidateSet @("Windows")
$state = Get-AnsibleParam $parsed_args "state" -default "present" -ValidateSet @("present", "absent")

$check_mode = $false

# TODO: fix SQL injection vulnerabilities before actually shipping this sample
$login_exists = ((Invoke-Sqlcmd -Query "SELECT COUNT(*) as UserCount FROM sys.server_principals WHERE name='$server_login_name'").UserCount -eq 1)

If($state -eq "present" -and -not $login_exists) {
    $result.changed = $true
    If (-not $check_mode) {
        Invoke-Sqlcmd -Query "CREATE LOGIN [$server_login_name] FROM WINDOWS" | Out-Null
    }
}
ElseIf($state -eq "absent" -and $login_exists) {
    $result.changed = $true
    If (-not $check_mode) {
        Invoke-Sqlcmd -Query "DROP LOGIN [$server_login_name]" | Out-Null
    }
}

Exit-Json $result

