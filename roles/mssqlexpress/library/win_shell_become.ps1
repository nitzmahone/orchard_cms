#!powershell
# (c)2016, Matt Davis <mdavis@ansible.com>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# WANT_JSON
# POWERSHELL_COMMON

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

$helper_def = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace Ansible.Shell
{
    public class ProcessUtil
    {
        public static void GetProcessOutput(StreamReader stdoutStream, StreamReader stderrStream, out string stdout, out string stderr)
        {
            var sowait = new EventWaitHandle(false, EventResetMode.ManualReset);
            var sewait = new EventWaitHandle(false, EventResetMode.ManualReset);

            string so = null, se = null;

            ThreadPool.QueueUserWorkItem((s)=>
            {
                so = stdoutStream.ReadToEnd();
                sowait.Set();
            });

            ThreadPool.QueueUserWorkItem((s) =>
            {
                se = stderrStream.ReadToEnd();
                sewait.Set();
            });

            foreach(var wh in new WaitHandle[] { sowait, sewait })
                wh.WaitOne();

            stdout = so;
            stderr = se;
        }

        public static void GrantAccessToWindowStationAndDesktop(string username)
        {
            const int WindowStationAllAccess = 0x000f037f;
            GrantAccess(username, GetProcessWindowStation(), WindowStationAllAccess);
            const int DesktopRightsAllAccess = 0x000f01ff;
            GrantAccess(username, GetThreadDesktop(GetCurrentThreadId()), DesktopRightsAllAccess);
        }

        private static void GrantAccess(string username, IntPtr handle, int accessMask)
        {
            SafeHandle safeHandle = new NoopSafeHandle(handle);
            GenericSecurity security =
                new GenericSecurity(false, ResourceType.WindowObject, safeHandle, AccessControlSections.Access);

            security.AddAccessRule(
                new GenericAccessRule(new NTAccount(username), accessMask, AccessControlType.Allow));
            security.Persist(safeHandle, AccessControlSections.Access);
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetThreadDesktop(int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetCurrentThreadId();

        // All the code to manipulate a security object is available in .NET framework,
        // but its API tries to be type-safe and handle-safe, enforcing a special implementation
        // (to an otherwise generic WinAPI) for each handle type. This is to make sure
        // only a correct set of permissions can be set for corresponding object types and
        // mainly that handles do not leak.
        // Hence the AccessRule and the NativeObjectSecurity classes are abstract.
        // This is the simplest possible implementation that yet allows us to make use
        // of the existing .NET implementation, sparing necessity to P/Invoke the underlying WinAPI.

        private class GenericAccessRule : AccessRule
        {
            public GenericAccessRule(IdentityReference identity, int accessMask, AccessControlType type) :
                base(identity, accessMask, false, InheritanceFlags.None, PropagationFlags.None, type)
            {
            }
        }

        private class GenericSecurity : NativeObjectSecurity
        {
            public GenericSecurity(bool isContainer, ResourceType resType, SafeHandle objectHandle, AccessControlSections sectionsRequested)
                : base(isContainer, resType, objectHandle, sectionsRequested)
            {
            }

            new public void Persist(SafeHandle handle, AccessControlSections includeSections)
            {
                base.Persist(handle, includeSections);
            }

            new public void AddAccessRule(AccessRule rule)
            {
                base.AddAccessRule(rule);
            }

            #region NativeObjectSecurity Abstract Method Overrides

            public override Type AccessRightType
            {
                get { throw new NotImplementedException(); }
            }

            public override AccessRule AccessRuleFactory(System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
            {
                throw new NotImplementedException();
            }

            public override Type AccessRuleType
            {
                get { return typeof(AccessRule); }
            }

            public override AuditRule AuditRuleFactory(System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
            {
                throw new NotImplementedException();
            }

            public override Type AuditRuleType
            {
                get { return typeof(AuditRule); }
            }

            #endregion
        }

        // Handles returned by GetProcessWindowStation and GetThreadDesktop should not be closed
        private class NoopSafeHandle : SafeHandle
        {
            public NoopSafeHandle(IntPtr handle) :
                base(handle, false)
            {
            }

            public override bool IsInvalid
            {
                get { return false; }
            }

            protected override bool ReleaseHandle()
            {
                return true;
            }
        }

    }
}
"@

$parsed_args = Parse-Args $args $false

$raw_command_line = $(Get-AnsibleParam $parsed_args "command_line" -failifempty $true).Trim()
$chdir = Get-AnsibleParam $parsed_args "chdir"
$executable = Get-AnsibleParam $parsed_args "executable"
$creates = Get-AnsibleParam $parsed_args "creates"
$removes = Get-AnsibleParam $parsed_args "removes"

$username = Get-AnsibleParam $parsed_args "username"
$password = Get-AnsibleParam $parsed_args "password"

$result = @{changed=$true; warnings=@(); cmd=$raw_command_line}

If($creates -and $(Test-Path $creates)) {
    Exit-Json @{cmd=$raw_command_line; msg="skipped, since $creates exists"; changed=$false; skipped=$true; rc=0}
}

If($removes -and -not $(Test-Path $removes)) {
    Exit-Json @{cmd=$raw_command_line; msg="skipped, since $removes does not exist"; changed=$false; skipped=$true; rc=0}
}

Add-Type -TypeDefinition $helper_def

$exec_args = $null

If(-not $executable -or $executable -eq "powershell") {
    $exec_application = "powershell"

    # Base64 encode the command so we don't have to worry about the various levels of escaping
    $encoded_command = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($raw_command_line))

    $exec_args = @("-noninteractive", "-encodedcommand", $encoded_command)
}
Else {
    # FUTURE: support arg translation from executable (or executable_args?) to process arguments for arbitrary interpreter?
    $exec_application = $executable
    $exec_args = @("/c", $raw_command_line)
}

$proc = New-Object System.Diagnostics.Process
$psi = $proc.StartInfo
$psi.FileName = $exec_application
$psi.Arguments = $exec_args
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false

if($username -and $password) {
    # TODO: add domain parsing support
    $psi.Domain = "."
    $psi.Username = $username
    $psi.Password = $($password | ConvertTo-SecureString -AsPlainText -Force)

    [Ansible.Shell.ProcessUtil]::GrantAccessToWindowStationAndDesktop($username)
}


If ($chdir) {
    $psi.WorkingDirectory = $chdir
}

$start_datetime = [DateTime]::UtcNow

Try {
    $proc.Start() | Out-Null # will always return $true for non shell-exec cases
}
Catch [System.ComponentModel.Win32Exception] {
    # fail nicely for "normal" error conditions
    # FUTURE: this probably won't work on Nano Server
    $excep = $_
    Exit-Json @{failed=$true;changed=$false;cmd=$raw_command_line;rc=$excep.Exception.NativeErrorCode;msg=$excep.Exception.Message}
}

$stdout = $stderr = [string] $null

[Ansible.Shell.ProcessUtil]::GetProcessOutput($proc.StandardOutput, $proc.StandardError, [ref] $stdout, [ref] $stderr) | Out-Null

$result.stdout = $stdout
$result.stderr = $stderr

# TODO: decode CLIXML stderr output (and other streams?)

$proc.WaitForExit() | Out-Null

$result.rc = $proc.ExitCode

$end_datetime = [DateTime]::UtcNow

$result.start = $start_datetime.ToString("yyyy-MM-dd hh:mm:ss.ffffff")
$result.end = $end_datetime.ToString("yyyy-MM-dd hh:mm:ss.ffffff")
$result.delta = $($end_datetime - $start_datetime).ToString("h\:mm\:ss\.ffffff")

ConvertTo-Json -Depth 99 $result

