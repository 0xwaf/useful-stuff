# EXEC/check_email_security.ps1

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
    # Always show recommendations, with different color based on status
    if ($Recommendation) {
        $recColor = if ($Secure) { "Green" } else { "Magenta" }
        Write-Host "  Configuration Analysis:" -ForegroundColor $recColor
        foreach ($line in $Recommendation.Split("`n")) {
            # Check if this is a detected issue line or contains warnings/errors
            if ($line -match "Detected Issues:") {
                Write-Host "    $line" -ForegroundColor Red
            }
            elseif ($line -match "\s*- (CRITICAL|WARNING|ERROR|NOTICE):") {
                Write-Host "    $line" -ForegroundColor Red
            }
            elseif ($line.TrimStart().StartsWith("- ") -and $line -match "(CRITICAL|WARNING|ERROR|NOTICE)") {
                Write-Host "    $line" -ForegroundColor Red
            }
            else {
                Write-Host "    $line" -ForegroundColor $recColor
            }
        }
    }
}

function Check-SPFRecord {
    param ([string]$Domain)
    
    try {
        $spfRecord = Resolve-DnsName -Name $Domain -Type TXT | Where-Object { $_.Strings -match "^v=spf1" }
        
        if (-not $spfRecord) {
            Write-CheckResult -CheckName "SPF" `
                -Status "No SPF record found" `
                -Secure $false `
                -Recommendation "Create an SPF record to specify authorized mail servers"
            return
        }

        $spfText = $spfRecord.Strings
        $vulnerabilities = @()
        
        # Count DNS lookups
        $includeCount = ($spfText | Select-String -Pattern "include:" -AllMatches).Matches.Count
        $redirectCount = ($spfText | Select-String -Pattern "redirect=" -AllMatches).Matches.Count
        $aCount = ($spfText | Select-String -Pattern "\sa[:\s]" -AllMatches).Matches.Count
        $mxCount = ($spfText | Select-String -Pattern "\smx[:\s]" -AllMatches).Matches.Count
        $totalLookups = $includeCount + $redirectCount + $aCount + $mxCount

        if ($totalLookups -gt 10) {
            $vulnerabilities += "CRITICAL: Record exceeds 10 DNS lookup limit ($totalLookups lookups found)"
        }
        
        # Check record length
        if ($spfText.Length -gt 450) {  # Warning at 450 bytes to provide buffer
            $vulnerabilities += "WARNING: Record length ($($spfText.Length) bytes) approaching 512-byte limit"
        }

        # Check for termination
        if ($spfText -match "\+all$") {
            $vulnerabilities += "CRITICAL: Uses '+all' which allows all servers to send mail (very permissive)"
        }
        elseif ($spfText -match "~all$") {
            $vulnerabilities += "WARNING: Uses '~all' (soft fail) instead of '-all' (hard fail)"
        }
        elseif (-not ($spfText -match "-all$")) {
            $vulnerabilities += "ERROR: Missing terminating '-all'"
        }
        
        $isSecure = $vulnerabilities.Count -eq 0 -and $spfText -match "-all$"
        
        $recommendation = "Current Configuration Analysis:`n"
        $recommendation += "- Record: $spfText`n"
        $recommendation += "- DNS Lookups Found:`n"
        $recommendation += "  * Include statements: $includeCount`n"
        $recommendation += "  * Redirect statements: $redirectCount`n"
        $recommendation += "  * A records: $aCount`n"
        $recommendation += "  * MX records: $mxCount`n"
        $recommendation += "  * Total lookups: $totalLookups/10`n"
        $recommendation += "- Record Length: $($spfText.Length)/512 bytes`n"
        $recommendation += "- Policy Setting: " + $(
            if ($spfText -match "\+all$") { 
                "+all (Allows all senders - Most permissive, effectively disables SPF protection)"
            }
            elseif ($spfText -match "~all$") { 
                "~all (Soft fail - Unauthorized emails are marked as suspicious but delivered. Recommended during testing/transition)"
            }
            elseif ($spfText -match "-all$") { 
                "-all (Hard fail - Unauthorized emails are rejected. Strongest protection, recommended for production)"
            }
            elseif ($spfText -match "\?all$") {
                "?all (Neutral - No policy enforced, treats unauthorized senders as neutral. Not recommended)"
            }
            else { 
                "No policy specified (Default behavior varies by receiving server)"
            }
        )

        # Add explanation section for policy implications
        $recommendation += "`n- Policy Implications:`n"
        $recommendation += "  * Hard Fail (-all):`n"
        $recommendation += "    - Unauthorized emails are rejected`n"
        $recommendation += "    - Provides strongest protection`n"
        $recommendation += "    - May block legitimate emails if SPF record is incomplete`n"
        $recommendation += "    - Recommended when all legitimate sending sources are identified`n"

        $recommendation += "  * Soft Fail (~all):`n"
        $recommendation += "    - Unauthorized emails are marked as suspicious`n"
        $recommendation += "    - Emails still delivered to recipient`n"
        $recommendation += "    - Useful during SPF implementation and testing`n"
        $recommendation += "    - Allows time to identify missing legitimate sources`n"

        # Add mechanism explanation if present
        if ($spfText -match "include:|ip4:|ip6:|a:|mx:") {
            $recommendation += "`n- Mechanism Details:`n"
            if ($spfText -match "include:") {
                $recommendation += "  * include: - References another domain's SPF record`n"
            }
            if ($spfText -match "ip4:") {
                $recommendation += "  * ip4: - Authorizes specific IPv4 addresses/ranges`n"
            }
            if ($spfText -match "ip6:") {
                $recommendation += "  * ip6: - Authorizes specific IPv6 addresses/ranges`n"
            }
            if ($spfText -match "a:") {
                $recommendation += "  * a: - Authorizes domain's A record IPs`n"
            }
            if ($spfText -match "mx:") {
                $recommendation += "  * mx: - Authorizes domain's MX record IPs`n"
            }
        }

        if ($vulnerabilities) {
            $recommendation += "`n`nDetected Issues:`n    - " + ($vulnerabilities -join "`n    - ")
        }

        $recommendation += "`n`nExample SPF Record:
v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:spf.protection.outlook.com -all"

        Write-CheckResult -CheckName "SPF" `
            -Status "Record found" `
            -Secure $isSecure `
            -Details "Record: $spfText" `
            -Recommendation $recommendation
    }
    catch {
        Write-Host "Error checking SPF: $_" -ForegroundColor Red
    }
}

function Check-DMARCRecord {
    param ([string]$Domain)
    
    try {
        $dmarcRecord = $null
        try {
            $dmarcRecord = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -ErrorAction Stop | 
                Where-Object { $_.Strings -match "^v=DMARC1" }
        }
        catch {
            Write-CheckResult -CheckName "DMARC" `
                -Status "Error resolving DMARC record" `
                -Secure $false `
                -Details "DNS resolution failed" `
                -Recommendation "Verify DNS configuration and network connectivity"
            return
        }
        
        if (-not $dmarcRecord) {
            Write-CheckResult -CheckName "DMARC" `
                -Status "No DMARC record found" `
                -Secure $false `
                -Recommendation "Create a DMARC record to specify email authentication policies"
            return
        }

        $dmarcText = $dmarcRecord.Strings[0]
        $vulnerabilities = @()
        
        # Policy checks
        if ($dmarcText -match "p=none") {
            $vulnerabilities += "WARNING: Policy set to 'none' (monitoring only, no enforcement)"
        }
        elseif ($dmarcText -match "p=quarantine") {
            Write-Host "  Note: Using quarantine policy - suspicious emails will be marked as spam" -ForegroundColor Yellow
        }
        elseif (-not ($dmarcText -match "p=(quarantine|reject)")) {
            $vulnerabilities += "ERROR: Invalid or missing policy (p) tag"
        }
        
        # Reporting checks
        if (-not ($dmarcText -match "rua=mailto:")) {
            $vulnerabilities += "WARNING: No valid aggregate reporting email configured"
        }
        if (-not ($dmarcText -match "ruf=mailto:")) {
            $vulnerabilities += "NOTICE: No forensic reporting email configured"
        }
        
        # Percentage check
        if ($dmarcText -match "pct=(\d+)") {
            $pct = [int]$matches[1]
            if ($pct -lt 100) {
                $vulnerabilities += "WARNING: Partial implementation (pct=$pct) - only processing $pct% of messages"
            }
        }
        
        # Subdomain policy check
        if ($dmarcText -match "sp=none") {
            $vulnerabilities += "WARNING: Subdomain policy set to 'none' (no enforcement for subdomains)"
        }
        
        $isSecure = $vulnerabilities.Count -eq 0 -and 
                    $dmarcText -match "p=(quarantine|reject)" -and 
                    $dmarcText -match "rua=mailto:"
        
        $recommendation = "Current Configuration Analysis:`n"
        $recommendation += "- Record: $dmarcText`n"
        $recommendation += "- Policy Configuration:`n"
        if ($dmarcText -match "p=(\w+)") {
            $policy = switch($matches[1]) {
                "none" { "Monitor only (no action taken)" }
                "quarantine" { "Send suspicious emails to spam" }
                "reject" { "Reject suspicious emails" }
                default { "Unknown" }
            }
            $recommendation += "  * Main Policy: $($matches[1]) - $policy`n"
        }
        if ($dmarcText -match "sp=(\w+)") {
            $subPolicy = switch($matches[1]) {
                "none" { "Monitor only for subdomains" }
                "quarantine" { "Send suspicious subdomain emails to spam" }
                "reject" { "Reject suspicious subdomain emails" }
                default { "Unknown" }
            }
            $recommendation += "  * Subdomain Policy: $($matches[1]) - $subPolicy`n"
        }
        if ($dmarcText -match "pct=(\d+)") {
            $recommendation += "  * Enforcement Percentage: $($matches[1])%`n"
        }
        if ($dmarcText -match "adkim=(\w+)") {
            $dkimAlignment = switch($matches[1]) {
                "s" { "Strict (requires exact domain match)" }
                "r" { "Relaxed (allows subdomains)" }
                default { "Unknown" }
            }
            $recommendation += "  * DKIM Alignment: $($matches[1]) - $dkimAlignment`n"
        }
        if ($dmarcText -match "aspf=(\w+)") {
            $spfAlignment = switch($matches[1]) {
                "s" { "Strict (requires exact domain match)" }
                "r" { "Relaxed (allows subdomains)" }
                default { "Unknown" }
            }
            $recommendation += "  * SPF Alignment: $($matches[1]) - $spfAlignment`n"
        }
        if ($dmarcText -match "fo=([0-1ds]+)") {
            $foValues = $matches[1].ToCharArray()
            $recommendation += "  * Failure Options: $($matches[1]) - "
            $foExplanations = @()
            foreach ($value in $foValues) {
                $explanation = switch ($value) {
                    "0" { "Generate reports only if all mechanisms (SPF and DKIM) fail" }
                    "1" { "Generate reports if any mechanism (SPF or DKIM) fails" }
                    "d" { "Generate reports if DKIM fails, regardless of SPF" }
                    "s" { "Generate reports if SPF fails, regardless of DKIM" }
                    default { "Unknown option" }
                }
                $foExplanations += $explanation
            }
            $recommendation += "(" + ($foExplanations -join " AND ") + ")`n"
        }
        if ($dmarcText -match "ri=(\d+)") {
            $recommendation += "  * Report Interval: $($matches[1]) seconds`n"
        }
        $recommendation += "- Reporting Configuration:`n"
        if ($dmarcText -match "rua=mailto:([^;]+)") {
            $recommendation += "  * Aggregate Reports: $($matches[1])`n"
        }
        if ($dmarcText -match "ruf=mailto:([^;]+)") {
            $recommendation += "  * Forensic Reports: $($matches[1])`n"
        }
        if ($dmarcText -match "rf=(\w+)") {
            $recommendation += "  * Report Format: $($matches[1])`n"
        }

        if ($vulnerabilities) {
            $recommendation += "`n`nDetected Issues:`n    - " + ($vulnerabilities -join "`n    - ")
        }

        $recommendation += "`n`nExample DMARC Record:
v=DMARC1; p=reject; rua=mailto:dmarc@domain.com; ruf=mailto:forensic@domain.com; pct=100; adkim=s; aspf=s"

        Write-CheckResult -CheckName "DMARC" `
            -Status "Record found" `
            -Secure $isSecure `
            -Details "Record: $dmarcText" `
            -Recommendation $recommendation
    }
    catch {
        Write-Host "Error checking DMARC: $_" -ForegroundColor Red
    }
}

function Check-DKIMRecord {
    param ([string]$Domain)
    
    try {
        $selectors = @("default", "google", "selector1", "selector2", "k1", "mail")
        $dkimFound = $false
        
        foreach ($selector in $selectors) {
            try {
                $dkimRecord = Resolve-DnsName -Name "${selector}._domainkey.$Domain" -Type TXT -ErrorAction Stop |
                    Where-Object { $_.Strings -match "v=DKIM1" }
                
                if ($dkimRecord -and $dkimRecord.Strings) {
                    $dkimFound = $true
                    $dkimText = $dkimRecord.Strings[0]
                    $vulnerabilities = @()
                    
                    if ($dkimText -match "p=([A-Za-z0-9+/=]+)") {
                        $publicKey = $matches[1]
                        # Calculate RSA key length in bits
                        $keyBits = [math]::Floor(($publicKey.Length * 6) / 8) * 8  # Convert base64 length to bits
                        
                        if ([string]::IsNullOrEmpty($publicKey)) {
                            $vulnerabilities += "ERROR: Empty public key"
                        }
                        elseif ($keyBits -lt 2048) {
                            $vulnerabilities += "WARNING: Weak key length ($keyBits bits) - Minimum recommended is 2048 bits"
                        }
                        
                        $recommendation += "- Public Key Length: $keyBits bits " + $(
                            switch ($keyBits) {
                                {$_ -lt 1024} { "(CRITICAL: Very weak)" }
                                {$_ -lt 2048} { "(WARNING: Weak)" }
                                {$_ -eq 2048} { "(Good)" }
                                {$_ -gt 2048} { "(Strong)" }
                                default { "(Unknown)" }
                            }
                        ) + "`n"
                    }
                    else {
                        $vulnerabilities += "ERROR: Missing or invalid public key"
                    }
                    
                    if ($dkimText -match "t=y") {
                        $vulnerabilities += "WARNING: Testing mode enabled"
                    }
                    
                    $isSecure = $vulnerabilities.Count -eq 0
                    
                    $recommendation = "Current Configuration Analysis:`n"
                    $recommendation += "- Selector: $selector`n"
                    $recommendation += "- Record: $dkimText`n"
                    if ($dkimText -match "k=(\w+)") {
                        $recommendation += "- Key Type: $($matches[1])`n"
                    }
                    if ($dkimText -match "p=([A-Za-z0-9+/=]+)") {
                        $recommendation += "- Public Key: Present (Length: $($matches[1].Length) characters)`n"
                    }
                    if ($dkimText -match "t=y") {
                        $recommendation += "- Testing Mode: Enabled`n"
                    } else {
                        $recommendation += "- Testing Mode: Disabled`n"
                    }
                    if ($dkimText -match "s=([^;]+)") {
                        $recommendation += "- Service Type: $($matches[1])`n"
                    }

                    if ($vulnerabilities) {
                        $recommendation += "`n`nDetected Issues:`n    - " + ($vulnerabilities -join "`n    - ")
                    }

                    $recommendation += "`n`nExample DKIM Record:
selector._domainkey.domain.com IN TXT 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4...'"
                    
                    Write-CheckResult -CheckName "DKIM ($selector)" `
                        -Status "Record found" `
                        -Secure $isSecure `
                        -Details "Record: $dkimText" `
                        -Recommendation $recommendation
                }
            }
            catch {
                continue
            }
        }
        
        if (-not $dkimFound) {
            Write-CheckResult -CheckName "DKIM" `
                -Status "No DKIM records found with common selectors" `
                -Secure $false `
                -Recommendation "Configure DKIM with appropriate selectors for your email service"
        }
    }
    catch {
        Write-Host "Error checking DKIM: $_" -ForegroundColor Red
    }
}

function Check-EmailSecurity {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    Write-Host @"
    Email Security Assessment Tool v1.1
    Domain: $Domain
    Started: $(Get-Date)
"@ -ForegroundColor Cyan

    # Only run the core email authentication checks
    Check-SPFRecord -Domain $Domain
    Check-DMARCRecord -Domain $Domain
    Check-DKIMRecord -Domain $Domain

    Write-Host "`nAssessment completed at $(Get-Date)" -ForegroundColor Cyan
}

# Main execution
try {
    $domain = Read-Host "Enter domain to check"
    
    $outputDir = ".\SecurityReports"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    $date = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $outputFile = Join-Path $outputDir "EmailSecurity_${domain}_${date}.txt"
    Start-Transcript -Path $outputFile

    Check-EmailSecurity -Domain $domain

    Stop-Transcript
}
catch {
    Write-Host "Error running security check: $_" -ForegroundColor Red
    if ($Error[0].InvocationInfo.MyCommand.Name -eq "Start-Transcript") {
        Stop-Transcript
    }
}
