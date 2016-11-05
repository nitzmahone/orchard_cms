#!powershell

# WANT_JSON
# POWERSHELL_COMMON

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

$result = @{changed = $false}

$parsed_args = Parse-Args $args -supports_check_mode $true

$server_name = Get-AnsibleParam $parsed_args "server_name" -default "(local)"
$db_name = Get-AnsibleParam $parsed_args "db_name" -failifempty $result
$db_user_name = Get-AnsibleParam $parsed_args "name" -failifempty $result
$server_login_name = Get-AnsibleParam $parsed_args "server_login_name" -failifempty $result
$roles = Get-AnsibleParam $parsed_args "roles"
$state = Get-AnsibleParam $parsed_args "state" -default "present" -ValidateSet @("present", "absent")

$check_mode = $false

# TODO: fix SQL injection vulnerabilities before actually shipping this sample
$user_exists = ((Invoke-Sqlcmd -Database $db_name -Query "SELECT COUNT(*) as UserCount FROM sys.database_principals WHERE name='$db_user_name'").UserCount -eq 1)

If($state -eq "present") {
    If (-not $user_exists) {
        $result.changed = $true
        If (-not $check_mode) {
            Invoke-Sqlcmd -Database $db_name -Query "CREATE USER [$db_user_name] FOR LOGIN [$server_login_name]" | Out-Null
        }
    }
    If ($roles) {
        If ($roles -isnot [array]) {
            $roles = @($roles)
        }

        Foreach($role in $roles) {
            # TODO: we could probably do this more efficiently with a role expansion CTE or a server-side list
            $user_in_role = ((Invoke-Sqlcmd -Database $db_name -Query "SELECT IS_ROLEMEMBER('$role', '$db_user_name') as IsInRole").IsInRole -eq 1)

            If (-not $user_in_role) {
                $result.changed = $true
                If (-not $check_mode) {
                    Invoke-Sqlcmd -Database OrchardDemo -Query "ALTER ROLE [$role] ADD MEMBER [$db_user_name]" | Out-Null
                }
            }
        }
    }
}
ElseIf($state -eq "absent" -and $user_exists) {
    $result.changed = $true
    If (-not $check_mode) {
        Invoke-Sqlcmd -Database $db_name -Query "DROP USER [$db_user_name]" | Out-Null
    }
}

Exit-Json $result

