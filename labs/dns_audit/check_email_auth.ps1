<#
.SYNOPSIS
    Script kiem tra cau hinh xac thuc Email (MX, SPF de quy, DKIM Selector, DMARC) qua DNS.
    Phu trach: Thanh vien 3 - Nguyen Le Huu Dien (23120233) - Auth & Simulation Engineer.

.EXAMPLE
    .\check_email_auth.ps1 -SelfTest
    .\check_email_auth.ps1
    .\check_email_auth.ps1 -Domains "gmail.com","vietcombank.com.vn" -ExportMarkdown ".\live_audit_output.md"
#>

[CmdletBinding()]
param(
    [string[]]$Domains = @(
        "microsoft.com",
        "cloudflare.com",
        "vietcombank.com.vn",
        "uit.edu.vn",
        "github.com",
        "gmail.com",
        "vnexpress.net",
        "hust.edu.vn",
        "hcmus.edu.vn",
        "neverssl.com"
    ),
    [hashtable]$DkimSelectors = @{
        "vietcombank.com.vn" = @("selector1")
        "uit.edu.vn"         = @("google")
        "gmail.com"          = @("20230601")
    },
    [string]$ExportMarkdown = "",
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-TxtStrings {
    param([string]$DnsName)

    $records = @(Resolve-DnsName -Name $DnsName -Type TXT -ErrorAction Stop)
    $out = @()
    foreach ($rec in $records) {
        if ($null -eq $rec) { continue }
        $typeProp = $rec.PSObject.Properties["Type"]
        if ($typeProp -and ("$($typeProp.Value)" -notin @("TXT", "16"))) { continue }

        if ($rec.PSObject.Properties["Strings"] -and $rec.Strings) {
            $out += ($rec.Strings -join "")
        }
        elseif ($rec.PSObject.Properties["Text"] -and $rec.Text) {
            $out += ($rec.Text -join "")
        }
    }
    return $out
}

function Get-SpfRecordFromLookup {
    param(
        [string]$Domain,
        [scriptblock]$TxtLookupScript
    )
    if (-not $TxtLookupScript -or [string]::IsNullOrWhiteSpace($Domain)) {
        return ""
    }
    try {
        $list = @(& $TxtLookupScript $Domain)
        $match = @($list | Where-Object { $_ -match "^v=spf1(\s|$)" }) | Select-Object -First 1
        if ($match) { return [string]$match }
    }
    catch {
        return ""
    }
    return ""
}

function Resolve-SpfRecursive {
    param(
        [string]$SpfText,
        [string]$CurrentDomain = "",
        [scriptblock]$TxtLookupScript = $null,
        [System.Collections.Generic.HashSet[string]]$Visited = $null,
        [int]$Depth = 0,
        [int]$MaxDepth = 10
    )

    if ($null -eq $Visited) {
        $Visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        if (-not [string]::IsNullOrWhiteSpace($CurrentDomain)) {
            [void]$Visited.Add($CurrentDomain)
        }
    }

    $tokens = @($SpfText.Trim() -split "\s+")
    $topLookups = 0
    $recursiveLookups = 0
    $mechAll = "NONE"
    $redirectTarget = ""
    $redirectEffectiveAll = "NONE"
    $includedDomains = New-Object System.Collections.Generic.List[string]

    foreach ($tok in $tokens) {
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        $lower = $tok.ToLowerInvariant()

        if ($lower -match "^[\+\-\~\?]?all$") {
            $mechAll = if ($lower -eq "all") { "+all" } else { $lower }
            continue
        }

        $clean = $lower.TrimStart('+', '-', '~', '?')
        if ($clean -match "^(include:|a$|a:|a/|mx$|mx:|mx/|ptr$|ptr:|exists:|redirect=)") {
            $topLookups++
            $recursiveLookups++

            if ($TxtLookupScript -and ($Depth -lt $MaxDepth)) {
                if ($clean -match "^include:(.+)$") {
                    $incDom = $Matches[1].Trim()
                    if ($incDom -and (-not $Visited.Contains($incDom))) {
                        [void]$Visited.Add($incDom)
                        [void]$includedDomains.Add($incDom)
                        $childSpf = Get-SpfRecordFromLookup -Domain $incDom -TxtLookupScript $TxtLookupScript
                        if (-not [string]::IsNullOrWhiteSpace($childSpf)) {
                            $childRes = Resolve-SpfRecursive -SpfText $childSpf -CurrentDomain $incDom -TxtLookupScript $TxtLookupScript -Visited $Visited -Depth ($Depth + 1) -MaxDepth $MaxDepth
                            $recursiveLookups += $childRes.RecursiveLookupCount
                        }
                    }
                }
                elseif ($clean -match "^redirect=(.+)$") {
                    $redirectTarget = $Matches[1].Trim()
                    if ($redirectTarget -and (-not $Visited.Contains($redirectTarget))) {
                        [void]$Visited.Add($redirectTarget)
                        $redirSpf = Get-SpfRecordFromLookup -Domain $redirectTarget -TxtLookupScript $TxtLookupScript
                        if (-not [string]::IsNullOrWhiteSpace($redirSpf)) {
                            $redirRes = Resolve-SpfRecursive -SpfText $redirSpf -CurrentDomain $redirectTarget -TxtLookupScript $TxtLookupScript -Visited $Visited -Depth ($Depth + 1) -MaxDepth $MaxDepth
                            $recursiveLookups += $redirRes.RecursiveLookupCount
                            $redirectEffectiveAll = $redirRes.EffectiveAll
                        }
                    }
                }
            }
            elseif ($clean -match "^redirect=(.+)$") {
                $redirectTarget = $Matches[1].Trim()
            }
        }
    }

    $effectiveAll = if ($mechAll -ne "NONE") { $mechAll } else { $redirectEffectiveAll }

    return [PSCustomObject]@{
        MechanismAll         = $mechAll
        EffectiveAll         = $effectiveAll
        RedirectTarget       = $redirectTarget
        TopLookupCount       = $topLookups
        RecursiveLookupCount = $recursiveLookups
        IncludedDomains      = @($includedDomains)
    }
}

function Evaluate-SpfRecord {
    param(
        [string]$SpfText,
        [string]$Domain = "",
        [scriptblock]$TxtLookupScript = $null
    )

    if ([string]::IsNullOrWhiteSpace($SpfText)) {
        return [PSCustomObject]@{
            Present              = $false
            Record               = ""
            MechanismAll         = "NONE"
            EffectiveAll         = "NONE"
            RedirectTarget       = ""
            DnsLookupCount       = 0
            RecursiveLookupCount = 0
            LookupLimitExceeded  = $false
            Summary              = "Khong co ban ghi SPF"
        }
    }

    $res = Resolve-SpfRecursive -SpfText $SpfText -CurrentDomain $Domain -TxtLookupScript $TxtLookupScript
    $exceeded = ($res.RecursiveLookupCount -gt 10)

    if ($res.RedirectTarget) {
        $summary = "Co SPF (redirect=$($res.RedirectTarget) -> $($res.EffectiveAll), $($res.RecursiveLookupCount) DNS lookups)"
    }
    elseif ($TxtLookupScript -and ($res.RecursiveLookupCount -ne $res.TopLookupCount)) {
        $summary = "Co SPF ($($res.EffectiveAll), $($res.TopLookupCount) top / $($res.RecursiveLookupCount) recursive lookups)"
    }
    else {
        $summary = "Co SPF ($($res.EffectiveAll), $($res.RecursiveLookupCount) DNS lookups)"
    }

    if ($exceeded) {
        $summary += " [VUOT GIOI HAN 10]"
    }

    return [PSCustomObject]@{
        Present              = $true
        Record               = $SpfText.Trim()
        MechanismAll         = $res.MechanismAll
        EffectiveAll         = $res.EffectiveAll
        RedirectTarget       = $res.RedirectTarget
        DnsLookupCount       = $res.TopLookupCount
        RecursiveLookupCount = $res.RecursiveLookupCount
        LookupLimitExceeded  = $exceeded
        Summary              = $summary
    }
}

function Evaluate-DmarcRecord {
    param([string]$DmarcText)

    if ([string]::IsNullOrWhiteSpace($DmarcText)) {
        return [PSCustomObject]@{
            Present         = $false
            Record          = ""
            Policy          = "NONE"
            SubdomainPolicy = ""
            Pct             = "100"
            Rua             = ""
            Summary         = "Khong co ban ghi DMARC"
        }
    }

    $policy = "unknown"
    $sp = ""
    $pct = "100"
    $rua = ""

    if ($DmarcText -match "(?:^|;\s*)p=([a-zA-Z]+)") {
        $policy = $Matches[1].ToLowerInvariant()
    }
    if ($DmarcText -match "(?:^|;\s*)sp=([a-zA-Z]+)") {
        $sp = $Matches[1].ToLowerInvariant()
    }
    if ($DmarcText -match "(?:^|;\s*)pct=(\d+)") {
        $pct = $Matches[1]
    }
    if ($DmarcText -match "(?:^|;\s*)rua=([^;]+)") {
        $rua = $Matches[1].Trim()
    }

    $summary = "p=$policy"
    if ($sp) { $summary += "; sp=$sp" }
    if ($pct -ne "100") { $summary += "; pct=$pct" }
    if ($rua) { $summary += "; co RUA" }

    return [PSCustomObject]@{
        Present         = $true
        Record          = $DmarcText.Trim()
        Policy          = $policy
        SubdomainPolicy = $sp
        Pct             = $pct
        Rua             = $rua
        Summary         = $summary
    }
}

function Evaluate-DkimRecord {
    param(
        [string]$Selector,
        [string]$Domain,
        [string[]]$TxtRecords = @(),
        [string]$CnameTarget = ""
    )

    $fqdn = "$Selector._domainkey.$Domain"
    $dkimTxt = @($TxtRecords | Where-Object { $_ -match "v=DKIM1|p=|k=" }) | Select-Object -First 1
    if (-not $dkimTxt -and $TxtRecords.Count -gt 0) {
        $dkimTxt = $TxtRecords[0]
    }

    if ([string]::IsNullOrWhiteSpace($dkimTxt)) {
        $status = if ($CnameTarget) { "CNAME -> $CnameTarget (khong co TXT)" } else { "Khong tim thay" }
        return [PSCustomObject]@{
            Selector    = $Selector
            Fqdn        = $fqdn
            Present     = $false
            Status      = $status
            KeyType     = ""
            PublicKey   = ""
            IsRevoked   = $false
            CnameTarget = $CnameTarget
            Record      = ""
        }
    }

    $keyType = "rsa"
    if ($dkimTxt -match "(?:^|;\s*)k=([a-zA-Z0-9-]+)") {
        $keyType = $Matches[1].ToLowerInvariant()
    }

    $pubKey = ""
    $hasPTag = $false
    if ($dkimTxt -match "(?:^|;\s*)p=([^;\s]*)") {
        $hasPTag = $true
        $pubKey = $Matches[1].Trim()
    }

    $isRevoked = ($hasPTag -and [string]::IsNullOrWhiteSpace($pubKey))
    if ($isRevoked) {
        $status = "Da thu hoi (p= rong, RFC 6376)"
    }
    elseif ($pubKey) {
        $preview = $pubKey.Substring(0, [Math]::Min(18, $pubKey.Length))
        if ($CnameTarget) {
            $status = "Hop le qua CNAME ($CnameTarget); k=$keyType; p=$preview..."
        }
        else {
            $status = "Hop le (TXT); k=$keyType; p=$preview..."
        }
    }
    else {
        $status = "Co ban ghi nhung thieu the p="
    }

    return [PSCustomObject]@{
        Selector    = $Selector
        Fqdn        = $fqdn
        Present     = $true
        Status      = $status
        KeyType     = $keyType
        PublicKey   = $pubKey
        IsRevoked   = $isRevoked
        CnameTarget = $CnameTarget
        Record      = $dkimTxt.Trim()
    }
}

function Get-DkimInfo {
    param(
        [string]$Selector,
        [string]$Domain
    )

    $fqdn = "$Selector._domainkey.$Domain"
    try {
        $records = @(Resolve-DnsName -Name $fqdn -Type TXT -ErrorAction Stop)
        $cname = ""
        $txts = @()
        foreach ($rec in $records) {
            if ($null -eq $rec) { continue }
            $typeStr = if ($rec.PSObject.Properties["Type"]) { "$($rec.Type)" } else { "" }
            if ($typeStr -in @("CNAME", "5") -and $rec.PSObject.Properties["NameHost"] -and $rec.NameHost) {
                $cname = [string]$rec.NameHost
            }
            elseif ($typeStr -in @("TXT", "16")) {
                if ($rec.PSObject.Properties["Strings"] -and $rec.Strings) {
                    $txts += ($rec.Strings -join "")
                }
                elseif ($rec.PSObject.Properties["Text"] -and $rec.Text) {
                    $txts += ($rec.Text -join "")
                }
            }
        }
        return Evaluate-DkimRecord -Selector $Selector -Domain $Domain -TxtRecords $txts -CnameTarget $cname
    }
    catch {
        return Evaluate-DkimRecord -Selector $Selector -Domain $Domain -TxtRecords @() -CnameTarget ""
    }
}

function Get-SecurityRating {
    param(
        $SpfEval,
        $DmarcEval
    )

    $effAll = if ($SpfEval.PSObject.Properties["EffectiveAll"] -and ($SpfEval.EffectiveAll -ne "NONE")) {
        $SpfEval.EffectiveAll
    }
    else {
        $SpfEval.MechanismAll
    }

    if (-not $SpfEval.Present -and -not $DmarcEval.Present) {
        return "Yeu / Chua cau hinh"
    }
    if ($effAll -in @("+all", "all")) {
        return "Yeu / Chua cau hinh (+all nguy hiem)"
    }
    if ($DmarcEval.Present -and $DmarcEval.Policy -eq "reject" -and $SpfEval.Present -and ($effAll -in @("-all", "~all"))) {
        return "Manh"
    }
    if (($DmarcEval.Present -and $DmarcEval.Policy -in @("quarantine", "reject")) -or ($SpfEval.Present -and ($effAll -in @("-all", "~all")))) {
        return "Trung binh"
    }
    return "Yeu / Chua cau hinh"
}

function Invoke-SelfTest {
    Write-Host "=== Running Offline SelfTest for SPF / DKIM / DMARC Evaluators ===" -ForegroundColor Cyan

    $mockTxtMap = @{
        "_spf.google.com"    = @("v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all")
        "_netblocks.google.com"  = @("v=spf1 ip4:35.190.247.0/24 ~all")
        "_netblocks2.google.com" = @("v=spf1 ip6:2001:4860:4000::/36 ~all")
        "_netblocks3.google.com" = @("v=spf1 ip4:172.217.0.0/19 ~all")
        "l1.ex" = @("v=spf1 include:l2.ex include:l3.ex -all")
        "l2.ex" = @("v=spf1 include:l4.ex include:l5.ex include:l6.ex -all")
        "l3.ex" = @("v=spf1 include:l7.ex include:l8.ex include:l9.ex -all")
        "l4.ex" = @("v=spf1 include:l10.ex include:l11.ex -all")
        "l5.ex" = @("v=spf1 ip4:198.51.100.1 -all")
        "l6.ex" = @("v=spf1 ip4:198.51.100.2 -all")
        "l7.ex" = @("v=spf1 ip4:198.51.100.3 -all")
        "l8.ex" = @("v=spf1 ip4:198.51.100.4 -all")
        "l9.ex" = @("v=spf1 ip4:198.51.100.5 -all")
        "l10.ex" = @("v=spf1 ip4:198.51.100.6 -all")
        "l11.ex" = @("v=spf1 ip4:198.51.100.7 -all")
    }
    $mockLookup = {
        param([string]$Dom)
        if ($mockTxtMap.ContainsKey($Dom)) { return $mockTxtMap[$Dom] }
        return @()
    }

    $cases = @(
        @{
            Name           = "Strong domain (-all + p=reject)"
            Spf            = "v=spf1 include:_spf.google.com ip4:198.51.100.0/24 -all"
            Dmarc          = "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@corp.example"
            ExpectedRating = "Manh"
            ExpectedLookup = 1
        },
        @{
            Name           = "Medium domain (~all + p=quarantine)"
            Spf            = "v=spf1 mx include:mail.example ~all"
            Dmarc          = "v=DMARC1; p=quarantine; rua=mailto:rep@example"
            ExpectedRating = "Trung binh"
            ExpectedLookup = 2
        },
        @{
            Name           = "Weak monitoring only (?all + p=none)"
            Spf            = "v=spf1 a ?all"
            Dmarc          = "v=DMARC1; p=none"
            ExpectedRating = "Yeu / Chua cau hinh"
            ExpectedLookup = 1
        },
        @{
            Name           = "Dangerous +all SPF"
            Spf            = "v=spf1 +all"
            Dmarc          = "v=DMARC1; p=reject"
            ExpectedRating = "Yeu / Chua cau hinh (+all nguy hiem)"
            ExpectedLookup = 0
        },
        @{
            Name           = "Missing SPF and DMARC"
            Spf            = ""
            Dmarc          = ""
            ExpectedRating = "Yeu / Chua cau hinh"
            ExpectedLookup = 0
        },
        @{
            Name           = "SPF Lookup Limit Exceeded (>10 includes)"
            Spf            = "v=spf1 include:a.ex include:b.ex include:c.ex include:d.ex include:e.ex include:f.ex include:g.ex include:h.ex include:i.ex include:j.ex include:k.ex -all"
            Dmarc          = "v=DMARC1; p=reject"
            ExpectedRating = "Manh"
            ExpectedLookup = 11
            ExpectExceeded = $true
        },
        @{
            Name           = "SPF redirect= inherits effective ~all (like gmail.com)"
            Domain         = "gmail.com"
            Spf            = "v=spf1 redirect=_spf.google.com"
            Dmarc          = "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com"
            Lookup         = $mockLookup
            ExpectedRating = "Trung binh"
            ExpectedLookup = 4
            ExpectedEffAll = "~all"
        },
        @{
            Name           = "Nested SPF include tree exceeds 10 recursive lookups"
            Domain         = "nested.example"
            Spf            = "v=spf1 include:l1.ex -all"
            Dmarc          = "v=DMARC1; p=reject"
            Lookup         = $mockLookup
            ExpectedRating = "Manh"
            ExpectedLookup = 11
            ExpectExceeded = $true
        }
    )

    $passed = 0
    $failed = 0

    foreach ($c in $cases) {
        $domArg = if ($c.ContainsKey("Domain")) { $c.Domain } else { "" }
        $lkpArg = if ($c.ContainsKey("Lookup")) { $c.Lookup } else { $null }
        $spfEval = Evaluate-SpfRecord -SpfText $c.Spf -Domain $domArg -TxtLookupScript $lkpArg
        $dmarcEval = Evaluate-DmarcRecord -DmarcText $c.Dmarc
        $rating = Get-SecurityRating -SpfEval $spfEval -DmarcEval $dmarcEval

        $ok = ($rating -eq $c.ExpectedRating) -and ($spfEval.RecursiveLookupCount -eq $c.ExpectedLookup)
        if ($c.ContainsKey("ExpectExceeded")) {
            $ok = $ok -and ($spfEval.LookupLimitExceeded -eq $c.ExpectExceeded)
        }
        if ($c.ContainsKey("ExpectedEffAll")) {
            $ok = $ok -and ($spfEval.EffectiveAll -eq $c.ExpectedEffAll)
        }

        if ($ok) {
            $passed++
            Write-Host "[PASS] $($c.Name) -> Rating='$rating', Lookups=$($spfEval.RecursiveLookupCount), EffAll=$($spfEval.EffectiveAll)" -ForegroundColor Green
        }
        else {
            $failed++
            Write-Host "[FAIL] $($c.Name) -> Got Rating='$rating' (exp '$($c.ExpectedRating)'), Lookups=$($spfEval.RecursiveLookupCount) (exp $($c.ExpectedLookup)), EffAll=$($spfEval.EffectiveAll)" -ForegroundColor Red
        }
    }

    # Test 9: DKIM Active CNAME-delegated vs Revoked empty p=
    $dkimActive = Evaluate-DkimRecord -Selector "selector1" -Domain "vietcombank.com.vn" `
        -TxtRecords @("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZ5ktL;") `
        -CnameTarget "selector1-vietcombank-com-vn._domainkey.vcb365.onmicrosoft.com"
    $dkimRevoked = Evaluate-DkimRecord -Selector "20230601" -Domain "gmail.com" `
        -TxtRecords @("v=DKIM1; k=rsa; p=")
    $dkimOk = $dkimActive.Present -and (-not $dkimActive.IsRevoked) -and $dkimActive.CnameTarget -and $dkimRevoked.Present -and $dkimRevoked.IsRevoked
    if ($dkimOk) {
        $passed++
        Write-Host "[PASS] DKIM Evaluator distinguishes CNAME-delegated active key vs revoked empty p=" -ForegroundColor Green
    }
    else {
        $failed++
        Write-Host "[FAIL] DKIM Evaluator failed active/revoked distinction" -ForegroundColor Red
    }

    $totalCases = $cases.Count + 1
    Write-Host "`nSelfTest Summary: $passed/$totalCases passed." -ForegroundColor Cyan
    if ($failed -gt 0) { exit 1 } else { exit 0 }
}

if ($SelfTest) {
    Invoke-SelfTest
}

if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Write-Error "Lenh Resolve-DnsName khong kha dung tren he thong nay. Hay chay tren Windows PowerShell hoac dung nslookup thu cong."
    exit 1
}

Write-Host "=== DNS Email Authentication Audit (MX / SPF Recursive / DKIM / DMARC) ===" -ForegroundColor Cyan
Write-Host "Thoi gian khao sat: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')`n" -ForegroundColor DarkGray

$liveLookupScript = {
    param([string]$Dom)
    return Get-TxtStrings -DnsName $Dom
}

$results = @()
$dkimResults = @()

foreach ($domain in $Domains) {
    $mxSummary = "Khong co MX / Loi DNS"
    $spfRaw = ""
    $dmarcRaw = ""
    $note = ""

    try {
        $mxRecords = @(Resolve-DnsName -Name $domain -Type MX -ErrorAction Stop | Where-Object { "$($_.Type)" -eq "MX" } | Sort-Object Preference)
        if ($mxRecords.Count -gt 0) {
            $topMx = @($mxRecords | Select-Object -First 2 | ForEach-Object { "$($_.NameExchange) ($($_.Preference))" })
            $mxSummary = ($topMx -join "; ")
        }
        else {
            $mxSummary = "Khong co ban ghi MX"
        }
    }
    catch {
        $note = "Khong co ban ghi MX hoac loi truy van"
    }

    try {
        $txtList = @(Get-TxtStrings -DnsName $domain)
        $spfMatches = @($txtList | Where-Object { $_ -match "^v=spf1(\s|$)" })
        if ($spfMatches.Count -gt 0) {
            $spfRaw = $spfMatches[0]
            if ($spfMatches.Count -gt 1) {
                $note += " [Canh bao: Nhieu hon 1 ban ghi SPF]"
            }
        }
    }
    catch {
        if (-not $note) { $note = "Loi truy van TXT/SPF" }
    }

    try {
        $dmarcList = @(Get-TxtStrings -DnsName "_dmarc.$domain")
        $dmarcMatches = @($dmarcList | Where-Object { $_ -match "^v=DMARC1(\s|;|$)" })
        if ($dmarcMatches.Count -gt 0) {
            $dmarcRaw = $dmarcMatches[0]
        }
    }
    catch {
        # Khong co _dmarc hoac loi mang
    }

    $spfEval = Evaluate-SpfRecord -SpfText $spfRaw -Domain $domain -TxtLookupScript $liveLookupScript
    $dmarcEval = Evaluate-DmarcRecord -DmarcText $dmarcRaw
    $rating = Get-SecurityRating -SpfEval $spfEval -DmarcEval $dmarcEval

    $dkimSummary = "-"
    if ($DkimSelectors.ContainsKey($domain)) {
        $selInfos = @()
        foreach ($sel in @($DkimSelectors[$domain])) {
            $dkimInfo = Get-DkimInfo -Selector $sel -Domain $domain
            $dkimResults += $dkimInfo
            $selInfos += "${sel}: $($dkimInfo.Status)"
        }
        $dkimSummary = $selInfos -join "; "
    }

    $row = [PSCustomObject]@{
        Domain       = $domain
        MX           = $mxSummary
        SPF          = $spfEval.Summary
        DMARC        = $dmarcEval.Summary
        DKIM         = $dkimSummary
        Rating       = $rating
        SpfRaw       = $spfEval.Record
        DmarcRaw     = $dmarcEval.Record
        SpfLookups   = $spfEval.RecursiveLookupCount
        Note         = $note.Trim()
    }
    $results += $row
}

$results | Format-Table Domain, MX, SPF, DMARC, Rating -AutoSize

if ($dkimResults.Count -gt 0) {
    Write-Host "`n=== Kiem tra DKIM Selector Mau ===" -ForegroundColor Cyan
    $dkimResults | Format-Table Fqdn, Status -AutoSize
}

if (-not [string]::IsNullOrWhiteSpace($ExportMarkdown)) {
    $mdLines = @(
        "# Ket qua Khao sat Tu dong (check_email_auth.ps1)",
        "",
        "Thoi gian chay: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
        "",
        "| Domain | MX | SPF | DMARC | Danh gia |",
        "| :--- | :--- | :--- | :--- | :--- |"
    )
    foreach ($r in $results) {
        $mdLines += "| ``$($r.Domain)`` | $($r.MX) | $($r.SPF) | $($r.DMARC) | **$($r.Rating)** |"
    }
    $mdLines += ""
    $mdLines += "## Ban ghi tho (Raw Records)"
    $mdLines += ""
    foreach ($r in $results) {
        $mdLines += "- **$($r.Domain)**:"
        $mdLines += "  - SPF ($($r.SpfLookups) recursive lookups): ``$($r.SpfRaw)``"
        $mdLines += "  - DMARC: ``$($r.DmarcRaw)``"
    }
    if ($dkimResults.Count -gt 0) {
        $mdLines += ""
        $mdLines += "## Ket qua DKIM Selector"
        $mdLines += ""
        foreach ($d in $dkimResults) {
            $mdLines += "- **$($d.Fqdn)**: $($d.Status) | ``$($d.Record)``"
        }
    }
    $mdLines | Set-Content -Path $ExportMarkdown -Encoding UTF8
    Write-Host "`nDa xuat bao cao Markdown tai: $ExportMarkdown" -ForegroundColor Green
}
