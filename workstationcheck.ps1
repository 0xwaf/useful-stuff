# Helper function to parse power settings output
function Get-PowerSettingValue {
    param(
        [string]$settingOutput,
        [string]$powerType  # 'AC' or 'DC'
    )
    try {
        # Extract the current value from powercfg output
        $pattern = if ($powerType -eq 'AC') {
            'Current AC Power Setting: (0x[0-9a-fA-F]+)'
        } else {
            'Current DC Power Setting: (0x[0-9a-fA-F]+)'
        }
        
        if ($settingOutput -match $pattern) {
            $hexValue = $matches[1]
            $decimalValue = [Convert]::ToInt32($hexValue, 16)
            return [math]::Round($decimalValue / 60, 2)  # Convert seconds to minutes
        }
        return "Not configured"
    } catch {
        return "Error parsing value"
    }
}

function Write-CheckResult {
    param (
        [string]$CheckName,
        [string]$Status,
        [bool]$Secure,
        [string]$Details = "",
        [string]$Recommendation = ""
    )
    $color = if ($Secure) { "Green" } else { "Red" }
    $securityStatus = if ($Secure) { "[SECURE]" } else { "[VULNERABLE]" }
    
    Write-Host "`n[*] $CheckName Check" -ForegroundColor Yellow
    Write-Host "  Status: $Status $securityStatus" -ForegroundColor $color
    if ($Details) {
        Write-Host "  Details: $Details" -ForegroundColor Cyan
    }
    if ($Recommendation -and -not $Secure) {
        Write-Host "  Recommendation: $Recommendation" -ForegroundColor Magenta
    }
}

function Check-SecuritySettings {
    Write-Host "`n=== Workstation Security Assessment ===" -ForegroundColor Cyan
    Write-Host "Started: $(Get-Date)" -ForegroundColor Cyan

    # UAC Settings with adjusted thresholds
    try {
        $uacSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -Name EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, PromptOnSecureDesktop -ErrorAction Stop
        
        # Updated UAC security criteria
        $isSecure = $uacSettings.EnableLUA -eq 1 -and 
                    $uacSettings.ConsentPromptBehaviorAdmin -in (2,5) -and  # Accept both notify and prompt
                    $uacSettings.ConsentPromptBehaviorUser -eq 3 -and       # Must elevate through admin credentials
                    $uacSettings.PromptOnSecureDesktop -eq 1               # Must use secure desktop
        
        # Detailed descriptions for admin prompt behavior
        $adminPromptDesc = switch($uacSettings.ConsentPromptBehaviorAdmin) {
            0 { "Elevate without prompting (Least Secure)" }
            1 { "Prompt for credentials on secure desktop" }
            2 { "Prompt for consent on secure desktop (Recommended)" }
            3 { "Prompt for credentials" }
            4 { "Prompt for consent" }
            5 { "Prompt for consent for non-Windows binaries (Recommended)" }
            default { "Unknown setting" }
        }

        # Detailed descriptions for user prompt behavior
        $userPromptDesc = switch($uacSettings.ConsentPromptBehaviorUser) {
            0 { "Automatically deny elevation requests (Most Restrictive)" }
            1 { "Prompt for credentials on secure desktop (Legacy)" }
            3 { "Prompt for admin credentials (Recommended)" }
            default { "Unknown setting" }
        }

        # Build detailed status
        $details = @(
            "UAC Status:",
            "- UAC Enabled: $($uacSettings.EnableLUA)",
            "- Secure Desktop: $($uacSettings.PromptOnSecureDesktop -eq 1)",
            "",
            "Admin Elevation Behavior:",
            "- Setting: $($uacSettings.ConsentPromptBehaviorAdmin)",
            "- Behavior: $adminPromptDesc",
            "",
            "Standard User Behavior:",
            "- Setting: $($uacSettings.ConsentPromptBehaviorUser)",
            "- Behavior: $userPromptDesc"
        )

        # Build recommendations based on current settings
        $recommendations = @()
        if (-not $uacSettings.EnableLUA) {
            $recommendations += @(
                "Enable User Account Control (UAC)"
            )
        }
        if (-not $uacSettings.PromptOnSecureDesktop) {
            $recommendations += @(
                "Enable secure desktop prompting"
            )
        }
        if ($uacSettings.ConsentPromptBehaviorAdmin -notin (2,5)) {
            $recommendations += @(
                "Set admin prompt behavior to 2 (consent) or 5 (consent for non-Windows)"
            )
        }
        if ($uacSettings.ConsentPromptBehaviorUser -ne 3) {
            $recommendations += @(
                "Set standard user behavior to 3 (require admin credentials)"
            )
        }

        Write-CheckResult -CheckName "UAC" `
            -Status "Settings checked" `
            -Secure $isSecure `
            -Details ($details -join "`n") `
            -Recommendation $(if(-not $isSecure) {
                "Recommended UAC Configuration:`n" + 
                ($recommendations -join "`n")
            })
    } catch {
        Write-CheckResult -CheckName "UAC" `
            -Status "Error checking settings" `
            -Secure $false `
            -Details $_.Exception.Message `
            -Recommendation "Verify access to UAC settings in registry"
    }

    # Login Security Settings with better error handling
    try {
        $loginSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ErrorAction Stop
        
        $dontDisplayLastUser = $loginSettings.DontDisplayLastUserName -eq 1
        $requireCAD = $loginSettings.DisableCAD -eq 0
        
        Write-CheckResult -CheckName "Login Security" `
            -Status "Settings checked" `
            -Secure ($dontDisplayLastUser -and $requireCAD) `
            -Details "Hide Last Username: $dontDisplayLastUser`nCtrl+Alt+Del Required: $requireCAD" `
            -Recommendation "Required configuration:`n" +
            "- Hide last username: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName = 1`n" +
            "- Require Ctrl+Alt+Del: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD = 0"
    } catch {
        Write-CheckResult -CheckName "Login Security" `
            -Status "Error checking settings" `
            -Secure $false `
            -Details "Unable to access login security settings" `
            -Recommendation "Verify registry permissions and policy settings"
    }

    # Last Username Display on Switch Check
    try {
        $switchSettings = @(
            # Check main policy
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "DontDisplayLastUserName"
            },
            # Check switch-specific settings
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "DontDisplayUserName"
            },
            # Check Welcome screen setting
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "HideLoggedOnUserName"
            }
        )

        $vulnerabilities = @()
        $details = @()

        foreach ($setting in $switchSettings) {
            $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
            if ($value) {
                $isHidden = $value.$($setting.Name) -eq 1
                $details += "$($setting.Name): $isHidden"
                if (-not $isHidden) {
                    $vulnerabilities += "Username display not hidden for $($setting.Name)"
                }
            }
        }

        # Check Fast User Switching
        $fastUserSwitching = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -ErrorAction SilentlyContinue
        $isFastSwitchHidden = $fastUserSwitching.HideFastUserSwitching -eq 1
        $details += "Fast User Switching Hidden: $isFastSwitchHidden"
        
        # Additional check for Welcome Screen
        $welcomeScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "ShowLogonOptions" -ErrorAction SilentlyContinue
        if ($welcomeScreen) {
            $details += "Show Logon Options: $($welcomeScreen.ShowLogonOptions -eq 1)"
            if ($welcomeScreen.ShowLogonOptions -eq 1) {
                $vulnerabilities += "Logon options displayed on welcome screen"
            }
        }

        $isSecure = $vulnerabilities.Count -eq 0
        
        Write-CheckResult -CheckName "Username Display on Switch" `
            -Status "Settings checked" `
            -Secure $isSecure `
            -Details ($details -join "`n") `
            -Recommendation $(if(-not $isSecure) {
                "Configure the following for better security:`n" +
                "- Hide last username: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName = 1`n" +
                "- Hide username on switch: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName = 1`n" +
                "- Hide logged on username: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\HideLoggedOnUserName = 1`n" +
                "- Disable Fast User Switching: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\HideFastUserSwitching = 1`n" +
                "- Hide logon options: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\ShowLogonOptions = 0"
            })
    } catch {
        Write-CheckResult -CheckName "Username Display on Switch" `
            -Status "Error checking settings" `
            -Secure $false `
            -Details $_.Exception.Message `
            -Recommendation "Verify access to user display settings in registry"
    }

    # BitLocker check with both admin and non-admin methods
    try {
        $vulnerabilities = @()
        $details = @()
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Non-admin method using Shell.Application
        try {
            $shell = New-Object -ComObject Shell.Application
            $systemDrive = $shell.NameSpace($env:SystemDrive).Self
            $bitlockerStatus = $systemDrive.ExtendedProperty('System.Volume.BitLockerProtection')
            
            $details += "Standard User Check Results:"
            $details += "- System Drive: $($env:SystemDrive)"
            $details += "- Protection Status: $(switch($bitlockerStatus) {
                0 {"Not Protected"}
                1 {"Protected"}
                default {"Unknown ($bitlockerStatus)"}
            })"
            
            if ($bitlockerStatus -ne 1) {
                $vulnerabilities += "System drive is not BitLocker protected"
            }
        }
        catch {
            $details += "Failed to check BitLocker status using standard method: $($_.Exception.Message)"
        }

        # Admin method if available
        if ($isAdmin) {
            try {
                $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop
                $details += "`nAdmin Check Results:"
                foreach ($volume in $bitlockerVolumes) {
                    $details += "Drive $($volume.MountPoint):"
                    $details += "- Protection Status: $($volume.ProtectionStatus)"
                    $details += "- Encryption Method: $($volume.EncryptionMethod)"
                    $details += "- Encryption Percentage: $($volume.EncryptionPercentage)%"
                    $details += "- Lock Status: $($volume.LockStatus)"
                    
                    if ($volume.MountPoint -eq $env:SystemDrive -and $volume.ProtectionStatus -ne "On") {
                        $vulnerabilities += "System drive ($($volume.MountPoint)) is not fully protected"
                    }
                }
            }
            catch {
                $details += "`nFailed to get BitLocker status with admin privileges: $($_.Exception.Message)"
            }
        }

        # Check registry for BitLocker policies
        $bitlockerPolicies = @(
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
                Name = "EnableBDEWithNoTPM"
                Description = "BitLocker without TPM allowed"
            },
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
                Name = "UseAdvancedStartup"
                Description = "Advanced startup required"
            },
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
                Name = "MinimumPIN"
                Description = "Minimum PIN length"
            }
        )

        $details += "`nBitLocker Policy Settings:"
        foreach ($policy in $bitlockerPolicies) {
            try {
                $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                if ($value) {
                    $details += "- $($policy.Description): $($value.$($policy.Name))"
                }
            }
            catch {
                continue
            }
        }

        $isSecure = $vulnerabilities.Count -eq 0 -and ($bitlockerStatus -eq 1 -or ($isAdmin -and $bitlockerVolumes.ProtectionStatus -contains "On"))

        Write-CheckResult -CheckName "BitLocker" `
            -Status "Status checked" `
            -Secure $isSecure `
            -Details ($details -join "`n") `
            -Recommendation $(if(-not $isSecure) {
                "BitLocker Recommendations:`n" +
                "- Enable BitLocker on system drive`n" +
                "- Use TPM + PIN for better security`n" +
                "- Enable advanced startup`n" +
                "- Use strong encryption method (AES-256)`n" +
                "- Consider encrypting all fixed drives`n" +
                "`nCurrent issues:`n- " + ($vulnerabilities -join "`n- ")
            })
    }
    catch {
        Write-CheckResult -CheckName "BitLocker" `
            -Status "Error checking status" `
            -Secure $false `
            -Details "Error: $($_.Exception.Message)" `
            -Recommendation "Unable to check BitLocker status. Verify BitLocker is installed."
    }

    # Enhanced credential storage check
    try {
        $storedCreds = cmdkey /list
        $credDetails = $storedCreds | Where-Object { $_ -match 'Target:' } | ForEach-Object { $_.Trim() }
        $credCount = $credDetails.Count
        
        Write-CheckResult -CheckName "Stored Credentials" `
            -Status "Checked stored credentials" `
            -Secure ($credCount -eq 0) `
            -Details "Found $credCount stored credentials`n$($credDetails -join "`n")" `
            -Recommendation "Review and remove unnecessary stored credentials:`n" +
            "Command: cmdkey /list`n" +
            "Command to delete: cmdkey /delete:targetname`n" +
            "Registry path to clear all: HKCU:\Software\Microsoft\Windows\CurrentVersion\Credentials\*"
    } catch {
        Write-CheckResult -CheckName "Stored Credentials" `
            -Status "Error checking credentials" `
            -Secure $false `
            -Recommendation "Verify access to credential manager"
    }

    # Windows Firewall Status
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        $allEnabled = $true
        $details = foreach ($profile in $firewallProfiles) {
            if (-not $profile.Enabled) { $allEnabled = $false }
            "$($profile.Name): $($profile.Enabled)"
        }
        
        Write-CheckResult -CheckName "Windows Firewall" `
            -Status "Profiles checked" `
            -Secure $allEnabled `
            -Details ($details -join ", ") `
            -Recommendation "Required configuration:`n" +
            "- Enable Domain profile: HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall = 1`n" +
            "- Enable Private profile: HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall = 1`n" +
            "- Enable Public profile: HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall = 1"
    } catch {
        Write-Host "  [!] Error checking Windows Firewall status" -ForegroundColor Red
    }

    # USB Storage and Removable Media Checks
    try {
        $vulnerabilities = @()
        $details = @()
        
        # Check USB Storage Policy
        $usbPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\Windows\RemovableStorageDevices" `
            -ErrorAction SilentlyContinue
        $details += "USB Storage Policy:"
        $details += "- Global Block: $($usbPolicy.Deny_All -eq 1)"

        # Check BitLocker Policy for Removable Drives
        $bitlockerPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
            -ErrorAction SilentlyContinue
        $details += "`nBitLocker Requirements:"
        $details += "- Deny Write Access Without BitLocker: $($bitlockerPolicy.RDVDenyWriteAccess -eq 1)"
        $details += "- Enforce Drive Encryption: $($bitlockerPolicy.RDVEncryptionRequired -eq 1)"

        # Check Device Installation Restrictions
        $deviceInstall = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" `
            -ErrorAction SilentlyContinue
        $details += "`nDevice Installation Controls:"
        $details += "- Device Installation Restrictions: $($deviceInstall.DenyRemovableDevices -eq 1)"

        # Check Write Protection
        $writeProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" `
            -ErrorAction SilentlyContinue
        $details += "`nWrite Protection:"
        $details += "- Write Protection Enabled: $($writeProtection.WriteProtect -eq 1)"

        # Check WPD (Windows Portable Devices) Policies
        $wpdPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}" `
            -ErrorAction SilentlyContinue
        $details += "`nWPD Device Control:"
        $details += "- WPD Devices Blocked: $($wpdPolicy.Deny_All -eq 1)"

        # Check for connected USB storage devices
        $usbDevices = Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq "USB" }
        $details += "`nConnected USB Storage Devices:"
        if ($usbDevices) {
            foreach ($device in $usbDevices) {
                $details += "- $($device.Caption) ($($device.Size/1GB) GB)"
            }
            $vulnerabilities += "Active USB storage devices detected"
        } else {
            $details += "- None detected"
        }

        # Build security assessment
        if (-not $usbPolicy.Deny_All -eq 1) {
            $vulnerabilities += "USB storage devices are not globally blocked"
        }
        if (-not $bitlockerPolicy.RDVDenyWriteAccess -eq 1) {
            $vulnerabilities += "BitLocker is not required for write access"
        }
        if (-not $deviceInstall.DenyRemovableDevices -eq 1) {
            $vulnerabilities += "Device installation restrictions not enabled"
        }
        if (-not $writeProtection.WriteProtect -eq 1) {
            $vulnerabilities += "Write protection is not enabled"
        }

        # Generate recommendations based on findings
        $recommendations = @(
            "Required Registry Configurations:",
            "1. Global USB Storage Restrictions:",
            "   HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\Windows\RemovableStorageDevices\Deny_All = 1",
            "",
            "2. BitLocker for Removable Drives:",
            "   HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVDenyWriteAccess = 1",
            "   HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVEncryptionRequired = 1",
            "",
            "3. Device Installation Restrictions:",
            "   HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyRemovableDevices = 1",
            "   HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses = 1",
            "   HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClassesRetroactive = 1",
            "",
            "4. Write Protection:",
            "   HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect = 1",
            "",
            "5. WPD Device Control:",
            "   HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\Deny_All = 1",
            "",
            "Group Policy Configurations:",
            "- Computer Configuration\Administrative Templates\System\Removable Storage Access",
            "- Computer Configuration\Administrative Templates\System\Device Installation\Device Installation Restrictions",
            "",
            "Additional Security Measures:",
            "- Configure device audit logging: auditpol /set /subcategory:'Removable Storage' /success:enable /failure:enable",
            "- Monitor USB events in Event Viewer: Microsoft-Windows-USB/Operational"
        )

        $isSecure = $vulnerabilities.Count -eq 0

        Write-CheckResult -CheckName "USB Storage Security" `
            -Status "Configuration checked" `
            -Secure $isSecure `
            -Details ($details -join "`n") `
            -Recommendation $(if(-not $isSecure) {
                "Current Vulnerabilities:`n- " + ($vulnerabilities -join "`n- ") + 
                "`n`n" + ($recommendations -join "`n")
            })

    } catch {
        Write-CheckResult -CheckName "USB Storage Security" `
            -Status "Error checking settings" `
            -Secure $false `
            -Details "Error: $($_.Exception.Message)" `
            -Recommendation "Verify access to USB storage policies and BitLocker configuration"
    }

    # Power and Screen Settings Check
try {
    $vulnerabilities = @()
    $details = @()

    # Get current power scheme - updated parsing for Windows 11
    $powerScheme = powercfg /getactivescheme
    if ($powerScheme -match "Power Scheme GUID: ([a-fA-F0-9-]+)(?:\s+\((.+)\))?") {
        $schemeGuid = $matches[1].Trim()
        $schemeName = if ($matches.Count -gt 2 -and $matches[2]) { $matches[2].Trim() } else { "Unnamed Scheme" }
    } else {
        throw "Could not parse power scheme from: $powerScheme"
    }
    
    # Check if user can modify power scheme
    $canModifyPower = $true
    try {
        $testCmd = powercfg /change monitor-timeout-ac 120 2>&1
        if ($testCmd -match "Access denied") {
            $canModifyPower = $false
        }
        # Restore original setting from active scheme
        $currentSetting = powercfg /query $schemeGuid SUB_VIDEO VIDEOIDLE 2>&1
        if ($currentSetting -match "Access denied") {
            $canModifyPower = $false
        }
    } catch {
        $canModifyPower = $false
    }

    if ($canModifyPower) {
        $vulnerabilities += "Users can modify power settings"
    }
    
    # Get current timeout values with improved parsing for Windows 11
    try {
        $videoSettings = powercfg /query $schemeGuid SUB_VIDEO VIDEOIDLE | Out-String
        $sleepSettings = powercfg /query $schemeGuid SUB_SLEEP STANDBYIDLE | Out-String

        # Helper function to extract values with better Windows 11 compatibility
        function Extract-PowerValue {
            param($output, $pattern)
            if ($output -match $pattern) {
                try {
                    $hexValue = $matches[1]
                    if ($hexValue -eq "0") { return 0 }
                    return [math]::Round([Convert]::ToInt32($hexValue, 16) / 60)
                } catch {
                    return "Not configured"
                }
            } else {
                return "Not configured"
            }
        }

        # Parse AC values - Updated for Windows 11
        $screenACValue = Extract-PowerValue -output $videoSettings -pattern "(?:Current AC Power Setting Index|AC Power Setting Index):\s*(?:0x)?([0-9a-fA-F]+)"
        
        # Parse DC values - Updated for Windows 11
        $screenDCValue = Extract-PowerValue -output $videoSettings -pattern "(?:Current DC Power Setting Index|DC Power Setting Index):\s*(?:0x)?([0-9a-fA-F]+)"
        
        # Parse Sleep AC values - Updated for Windows 11
        $sleepACValue = Extract-PowerValue -output $sleepSettings -pattern "(?:Current AC Power Setting Index|AC Power Setting Index):\s*(?:0x)?([0-9a-fA-F]+)"
        
        # Parse Sleep DC values - Updated for Windows 11
        $sleepDCValue = Extract-PowerValue -output $sleepSettings -pattern "(?:Current DC Power Setting Index|DC Power Setting Index):\s*(?:0x)?([0-9a-fA-F]+)"

        # Alternative method if the above fails
        if ($screenACValue -eq "Not configured" -or $screenDCValue -eq "Not configured") {
            Write-Verbose "Using alternative method to get screen timeout settings"
            $acTimeout = powercfg /query $schemeGuid SUB_VIDEO VIDEOIDLE /AC 2>$null
            $dcTimeout = powercfg /query $schemeGuid SUB_VIDEO VIDEOIDLE /DC 2>$null
            
            if ($acTimeout -match "Power Setting Value: 0x([0-9a-fA-F]+)") {
                $screenACValue = [math]::Round([Convert]::ToInt32($matches[1], 16) / 60)
            }
            if ($dcTimeout -match "Power Setting Value: 0x([0-9a-fA-F]+)") {
                $screenDCValue = [math]::Round([Convert]::ToInt32($matches[1], 16) / 60)
            }
        }
    } catch {
        throw "Failed to parse power settings: $($_.Exception.Message)"
    }
    
    $details += "Active Power Scheme: $schemeName"
    $details += "User Can Modify Settings: $canModifyPower"
    $details += "`nScreen Settings:"
    $details += "- On Battery: Turn off after $screenDCValue minutes"
    $details += "- Plugged in: Turn off after $screenACValue minutes"
    $details += "`nSleep Settings:"
    $details += "- On Battery: PC sleeps after $sleepDCValue minutes"
    $details += "- Plugged in: PC sleeps after $sleepACValue minutes"
    
    # Security checks with improved type checking
    if ($screenDCValue -ne "Not configured") {
        if (($screenDCValue -is [int] -or $screenDCValue -is [double]) -and $screenDCValue -gt 4) {
            $vulnerabilities += "Screen timeout on battery is too long (Current: $screenDCValue min, Recommended: ≤ 4 min)"
        }
    }
    if ($screenACValue -ne "Not configured") {
        if (($screenACValue -is [int] -or $screenACValue -is [double]) -and $screenACValue -gt 120) {
            $vulnerabilities += "Screen timeout when plugged in is too long (Current: $screenACValue min, Recommended: ≤ 120 min)"
        }
    }
    if ($sleepDCValue -ne "Not configured") {
        if (($sleepDCValue -is [int] -or $sleepDCValue -is [double]) -and $sleepDCValue -gt 4) {
            $vulnerabilities += "Sleep timeout on battery is too long (Current: $sleepDCValue min, Recommended: ≤ 4 min)"
        }
    }
    if ($sleepACValue -ne "Not configured") {
        if (($sleepACValue -is [int] -or $sleepACValue -is [double]) -and $sleepACValue -gt 120) {
            $vulnerabilities += "Sleep timeout when plugged in is too long (Current: $sleepACValue min, Recommended: ≤ 120 min)"
        }
    }

    $isSecure = $vulnerabilities.Count -eq 0 -and (-not $canModifyPower)
    
    Write-CheckResult -CheckName "Power & Screen Settings" `
        -Status "Settings checked" `
        -Secure $isSecure `
        -Details ($details -join "`n") `
        -Recommendation $(if(-not $isSecure) {
            $recommendations = @(
                "Required configurations:",
                "On battery (powercfg commands):",
                "- Screen: powercfg /setdcvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 240",
                "- Sleep: powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 240",
                "",
                "When plugged in:",
                "- Screen: powercfg /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 7200",
                "- Sleep: powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 7200",
                "",
                "Lock settings via Registry:",
                "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\* = 1"
            )
            $recommendations -join "`n"
        })
}
catch {
    Write-CheckResult -CheckName "Power & Screen Settings" `
        -Status "Error checking settings" `
        -Secure $false `
        -Details "Error: $($_.Exception.Message)" `
        -Recommendation "Verify access to power settings"
}

    # AutoLogon Check
    try {
        $autoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon" `
            -Name AutoAdminLogon -ErrorAction SilentlyContinue
        
        $isSecure = -not ($autoLogon.AutoAdminLogon -eq 1)
        
        Write-CheckResult -CheckName "AutoLogon" `
            -Status "Settings checked" `
            -Secure $isSecure `
            -Details "AutoLogon Enabled: $($autoLogon.AutoAdminLogon -eq 1)" `
            -Recommendation "Required configuration:`n" +
            "Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\AutoAdminLogon = 0`n" +
            "Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn = 1"
    } catch {
        Write-Host "  [!] Error checking AutoLogon settings" -ForegroundColor Red
    }

    # Network Selection UI Check
    try {
        $networkUI = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NetworkProvider" `
            -Name "HideNetworkSelectionUI" -ErrorAction SilentlyContinue
        
        $isHidden = $networkUI.HideNetworkSelectionUI -eq 1
        
        Write-CheckResult -CheckName "Network Selection UI" `
            -Status "Settings checked" `
            -Secure $isHidden `
            -Details "Network Selection UI Hidden: $isHidden" `
            -Recommendation "Required configuration:`n" +
            "Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NetworkProvider\HideNetworkSelectionUI = 1"
    } catch {
        Write-CheckResult -CheckName "Network Selection UI" `
            -Status "Error checking settings" `
            -Secure $false `
            -Details "Unable to access network UI settings" `
            -Recommendation "Configure network UI visibility through Group Policy"
    }

    # Screen Lock Timeout Check
    try {
        $screenSaver = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" `
            -Name ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeout -ErrorAction SilentlyContinue
        
        $timeoutMinutes = [math]::Round($screenSaver.ScreenSaveTimeout / 60, 1)
        $isSecure = $screenSaver.ScreenSaveActive -eq 1 -and 
                    $screenSaver.ScreenSaverIsSecure -eq 1 -and 
                    $timeoutMinutes -le 15  # 15 minutes or less is considered secure
        
        Write-CheckResult -CheckName "Screen Lock" `
            -Status "Settings checked" `
            -Secure $isSecure `
            -Details "Screen Saver: $($screenSaver.ScreenSaveActive -eq 1)`nPassword Protected: $($screenSaver.ScreenSaverIsSecure -eq 1)`nTimeout: $timeoutMinutes minutes" `
            -Recommendation "Enable screen saver with password protection and timeout ≤ 15 minutes"
    } catch {
        Write-CheckResult -CheckName "Screen Lock" `
            -Status "Error checking settings" `
            -Secure $false `
            -Recommendation "Configure screen lock settings through Security Policy"
    }

    # RDP Settings Check
    try {
        $rdpSettings = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        $userRdpSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
        
        $rdpEnabled = $rdpSettings.fDenyTSConnections -eq 0
        $userCanConfig = $userRdpSettings.fDenyTSConnections -eq $null
        
        Write-CheckResult -CheckName "RDP" `
            -Status "Settings checked" `
            -Secure (-not $userCanConfig) `
            -Details "RDP Enabled: $rdpEnabled`nUser Can Configure: $userCanConfig" `
            -Recommendation "Required configuration:`n" +
            "- Disable RDP: HKLM:\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 1`n" +
            "- Control via policy: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections = 1`n" +
            "- Require Network Level Authentication: HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1"
    } catch {
        Write-CheckResult -CheckName "RDP" `
            -Status "Error checking settings" `
            -Secure $false `
            -Recommendation "Verify RDP configuration through Group Policy"
    }

    # Proxy Configuration Check
    try {
        $proxySettings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $proxyEnabled = $proxySettings.ProxyEnable -eq 1
        $proxyServer = $proxySettings.ProxyServer
        $proxyOverride = $proxySettings.ProxyOverride
        
        Write-CheckResult -CheckName "Proxy" `
            -Status "Settings checked" `
            -Secure $proxyEnabled `
            -Details "Proxy Enabled: $proxyEnabled$(if($proxyServer){"`nProxy Server: $proxyServer"})`nExceptions: $proxyOverride" `
            -Recommendation "Recommended proxy configuration:`n" +
            "- Enable proxy: HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable = 1`n" +
            "- Set proxy server: HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer = 'server:port'`n" +
            "- Configure exceptions: HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyOverride = 'local;*.local'"
    } catch {
        Write-CheckResult -CheckName "Proxy" `
            -Status "Error checking settings" `
            -Secure $false `
            -Recommendation "Verify proxy configuration"
    }

    # Administrative Rights Check
    try {
        # Check using both methods for better accuracy
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Get detailed group information using whoami
        $whoamiGroups = whoami /groups
        # Include both English and French SIDs and names
        $elevatedGroups = $whoamiGroups | Select-String -Pattern "S-1-5-32-544|S-1-5-32-550|S-1-5-32-549|S-1-16-12288" -Context 0,0
        $isElevated = $elevatedGroups.Count -gt 0
        
        # Parse important security groups (both English and French)
        $adminGroup = $whoamiGroups | Select-String "BUILTIN\\(Administrators|Administrateurs)" -Context 0,0
        $powerUsersGroup = $whoamiGroups | Select-String "BUILTIN\\(Power Users|Utilisateurs avec pouvoir)" -Context 0,0
        $highMandatoryLevel = $whoamiGroups | Select-String "Mandatory Level\\High|Niveau obligatoire\\Élevé" -Context 0,0
        
        # Check current username
        $currentUser = $env:USERNAME
        $isAdminUser = $currentUser -match "^(Administrator|Administrateur)$"
        
        $securityDetails = @(
            "Current Elevation Status:",
            "- Is Administrator (API Check): $isAdmin",
            "- Is Elevated (whoami): $isElevated",
            "- Username Check: $(if ($isAdminUser) { 'Using admin account' } else { 'Standard account name' })",
            "",
            "Important Group Memberships:",
            $(if ($adminGroup) { "- Member of Administrators/Administrateurs group" }),
            $(if ($powerUsersGroup) { "- Member of Power Users/Utilisateurs avec pouvoir group" }),
            $(if ($highMandatoryLevel) { "- Running with High/Élevé Mandatory Level" }),
            "",
            "All Security Groups:",
            $($whoamiGroups | Where-Object { $_ -match "GROUP|LABEL|GROUPE|ÉTIQUETTE" } | ForEach-Object { "- $_" })
        ) | Where-Object { $_ -ne $null }
        
        # Consider all admin conditions
        $isSecure = -not ($isAdmin -or $isElevated -or $isAdminUser)
        
        $recommendations = @(
            "Security recommendations:",
            "- Use a standard user account for daily tasks",
            $(if ($isAdminUser) { 
                "- Avoid using Administrator account`n" +
                "  Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken = 1"
            }),
            $(if ($adminGroup) { 
                "- Remove from Administrators group if not required`n" +
                "  Command: Remove-LocalGroupMember -Group 'Administrators' -Member '$currentUser'"
            }),
            $(if ($powerUsersGroup) { 
                "- Remove from Power Users group if not required`n" +
                "  Command: Remove-LocalGroupMember -Group 'Power Users' -Member '$currentUser'"
            }),
            $(if ($highMandatoryLevel) { 
                "- Run with lower privileges when possible`n" +
                "  Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization = 1"
            })
        ) | Where-Object { $_ -ne $null }
        
        Write-CheckResult -CheckName "Admin Rights" `
            -Status "Rights checked" `
            -Secure $isSecure `
            -Details ($securityDetails -join "`n") `
            -Recommendation $(if(-not $isSecure) { $recommendations -join "`n" })
    } catch {
        Write-CheckResult -CheckName "Admin Rights" `
            -Status "Error checking rights" `
            -Secure $false `
            -Details "Error: $($_.Exception.Message)" `
            -Recommendation "Verify user rights and permissions using 'whoami /groups'"
    }

    # Cached Logons Check
    try {
        $cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
            -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
        
        $count = if ($cachedLogons.CachedLogonsCount) { $cachedLogons.CachedLogonsCount } else { "Not configured" }
        $isSecure = $count -le 1
        
        Write-CheckResult -CheckName "Cached Logons" `
            -Status "Settings checked" `
            -Secure $isSecure `
            -Details "Cached Logons Count: $count" `
            -Recommendation $(if(-not $isSecure){"Reduce cached logons count to 1 or 0 for better security"})
    } catch {
        Write-CheckResult -CheckName "Cached Logons" `
            -Status "Error checking settings" `
            -Secure $false `
            -Recommendation "Configure cached logons through Security Policy"
    }

    Write-Host "`nAssessment completed at $(Get-Date)" -ForegroundColor Cyan
}

# Main execution
try {
    # Create output directory if it doesn't exist
    $outputDir = ".\SecurityReports"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    # Start transcript
    $date = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $computerName = $env:COMPUTERNAME
    $outputFile = Join-Path $outputDir "WorkstationSecurity_${computerName}_${date}.txt"
    Start-Transcript -Path $outputFile

    # Run security check
    Check-SecuritySettings

    # Stop transcript
    Stop-Transcript
}
catch {
    Write-Host "Error running security check: $_" -ForegroundColor Red
    if ($Error[0].InvocationInfo.MyCommand.Name -eq "Start-Transcript") {
        Stop-Transcript
    }
}
    
