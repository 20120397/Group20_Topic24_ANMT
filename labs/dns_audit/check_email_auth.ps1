<#
.SYNOPSIS
    Script kiểm tra cấu hình xác thực Email (MX, SPF, DMARC) qua DNS.
    Sinh viên thực hiện: Nguyễn Lê Hữu Điền (23120233).

.EXAMPLE
    .\check_email_auth.ps1 -SelfTest
    .\check_email_auth.ps1
    .\check_email_auth.ps1 -Domains "gmail.com","vietcombank.com.vn" -ExportMarkdown ".\live_results.md"

.NOTES
    # TODO (TV3): Co the bo sung them ten mien truong hoc, ngan hang hoac co quan Viet Nam vao tham so -Domains khi chay thu nghiem thuc te tren may co Internet.
#>

[CmdletBinding()]
param(
    [string[]]$Domains = @(
        "gmail.com",
        "microsoft.com",
        "github.com",
        "vietcombank.com.vn",
        "vnexpress.net",
        "hust.edu.vn",
        "uit.edu.vn",
        "cloudflare.com"
    ),
    [string]$ExportMarkdown = "",
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Evaluate-SpfRecord {
    param([string]$SpfText)

    if ([string]::IsNullOrWhiteSpace($SpfText)) {
        return [PSCustomObject]@{
            Present             = $false
            Record              = ""
            MechanismAll        = "NONE"
            DnsLookupCount      = 0
            LookupLimitExceeded = $false
            Summary             = "Khong co ban ghi SPF"
        }
    }

    $tokens = $SpfText.Trim() -split "\s+"
    $lookupCount = 0
    $allMech = "NONE"

    foreach ($tok in $tokens) {
        $lower = $tok.ToLowerInvariant()
        if ($lower -match "^[\+\-\~\?]?all$") {
            $allMech = $lower
            continue
        }
        $clean = $lower.TrimStart('+', '-', '~', '?')
        if ($clean -match "^(include:|a$|a:|a/|mx$|mx:|mx/|ptr$|ptr:|exists:|redirect=)") {
            $lookupCount++
        }
    }

    $exceeded = ($lookupCount -gt 10)
    $summary = "Co SPF ($allMech, $lookupCount DNS lookups)"
    if ($exceeded) {
        $summary += " [VUOT GIOI HAN 10]"
    }

    return [PSCustomObject]@{
        Present             = $true
        Record              = $SpfText.Trim()
        MechanismAll        = $allMech
        DnsLookupCount      = $lookupCount
        LookupLimitExceeded = $exceeded
        Summary             = $summary
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

function Get-SecurityRating {
    param(
        $SpfEval,
        $DmarcEval
    )

    if (-not $SpfEval.Present -and -not $DmarcEval.Present) {
        return "Yeu / Chua cau hinh"
    }
    if ($SpfEval.MechanismAll -eq "+all") {
        return "Yeu / Chua cau hinh (+all nguy hiem)"
    }
    if ($DmarcEval.Present -and $DmarcEval.Policy -eq "reject" -and $SpfEval.Present -and ($SpfEval.MechanismAll -in @("-all", "~all"))) {
        return "Manh"
    }
    if (($DmarcEval.Present -and $DmarcEval.Policy -in @("quarantine", "reject")) -or ($SpfEval.Present -and $SpfEval.MechanismAll -in @("-all", "~all"))) {
        return "Trung binh"
    }
    return "Yeu / Chua cau hinh"
}

function Get-TxtStrings {
    param([string]$DnsName)
    $records = Resolve-DnsName -Name $DnsName -Type TXT -ErrorAction Stop
    $out = @()
    foreach ($rec in $records) {
        if ($rec.PSObject.Properties["Strings"] -and $rec.Strings) {
            $out += ($rec.Strings -join "")
        }
        elseif ($rec.PSObject.Properties["Text"] -and $rec.Text) {
            $out += ($rec.Text -join "")
        }
    }
    return $out
}

function Invoke-SelfTest {
    Write-Host "=== Running Offline SelfTest for SPF / DMARC Evaluators ===" -ForegroundColor Cyan

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
        }
    )

    $passed = 0
    $failed = 0

    foreach ($c in $cases) {
        $spfEval = Evaluate-SpfRecord -SpfText $c.Spf
        $dmarcEval = Evaluate-DmarcRecord -DmarcText $c.Dmarc
        $rating = Get-SecurityRating -SpfEval $spfEval -DmarcEval $dmarcEval

        $ok = ($rating -eq $c.ExpectedRating) -and ($spfEval.DnsLookupCount -eq $c.ExpectedLookup)
        if ($c.ContainsKey("ExpectExceeded")) {
            $ok = $ok -and ($spfEval.LookupLimitExceeded -eq $c.ExpectExceeded)
        }

        if ($ok) {
            $passed++
            Write-Host "[PASS] $($c.Name) -> Rating='$rating', Lookups=$($spfEval.DnsLookupCount)" -ForegroundColor Green
        }
        else {
            $failed++
            Write-Host "[FAIL] $($c.Name) -> Got Rating='$rating' (exp '$($c.ExpectedRating)'), Lookups=$($spfEval.DnsLookupCount) (exp $($c.ExpectedLookup))" -ForegroundColor Red
        }
    }

    Write-Host "`nSelfTest Summary: $passed/$($cases.Count) passed." -ForegroundColor Cyan
    if ($failed -gt 0) { exit 1 } else { exit 0 }
}

if ($SelfTest) {
    Invoke-SelfTest
}

if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Write-Error "Lenh Resolve-DnsName khong kha dung tren he thong nay. Hay chay tren Windows PowerShell hoac dung nslookup thu cong."
    exit 1
}

Write-Host "=== DNS Email Authentication Audit (MX / SPF / DMARC) ===" -ForegroundColor Cyan
$results = @()

foreach ($domain in $Domains) {
    $mxSummary = "Khong co MX / Loi DNS"
    $spfRaw = ""
    $dmarcRaw = ""
    $note = ""

    try {
        $mxRecords = Resolve-DnsName -Name $domain -Type MX -ErrorAction Stop | Where-Object { $_.Type -eq "MX" } | Sort-Object Preference
        if ($mxRecords) {
            $topMx = $mxRecords | Select-Object -First 2 | ForEach-Object { "$($_.NameExchange) ($($_.Preference))" }
            $mxSummary = ($topMx -join "; ")
        }
        else {
            $mxSummary = "Khong co ban ghi MX"
        }
    }
    catch {
        $note = "Loi truy van MX (kiem tra mang/DNS)"
    }

    try {
        $txtList = Get-TxtStrings -DnsName $domain
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
        $dmarcList = Get-TxtStrings -DnsName "_dmarc.$domain"
        $dmarcMatches = @($dmarcList | Where-Object { $_ -match "^v=DMARC1(\s|;|$)" })
        if ($dmarcMatches.Count -gt 0) {
            $dmarcRaw = $dmarcMatches[0]
        }
    }
    catch {
        # Khong co _dmarc hoac loi mang
    }

    $spfEval = Evaluate-SpfRecord -SpfText $spfRaw
    $dmarcEval = Evaluate-DmarcRecord -DmarcText $dmarcRaw
    $rating = Get-SecurityRating -SpfEval $spfEval -DmarcEval $dmarcEval

    $row = [PSCustomObject]@{
        Domain       = $domain
        MX           = $mxSummary
        SPF          = $spfEval.Summary
        DMARC        = $dmarcEval.Summary
        Rating       = $rating
        SpfRaw       = $spfEval.Record
        DmarcRaw     = $dmarcEval.Record
        Note         = $note.Trim()
    }
    $results += $row
}

$results | Format-Table Domain, MX, SPF, DMARC, Rating -AutoSize

if (-not [string]::IsNullOrWhiteSpace($ExportMarkdown)) {
    $mdLines = @(
        "# Ket qua Khao sat Tu dong (check_email_auth.ps1)",
        "",
        "| Domain | MX | SPF | DMARC | Danh gia |",
        "| :--- | :--- | :--- | :--- | :--- |"
    )
    foreach ($r in $results) {
        $mdLines += "| ``$($r.Domain)`` | $($r.MX) | $($r.SPF) | $($r.DMARC) | **$($r.Rating)** |"
    }
    $mdLines | Set-Content -Path $ExportMarkdown -Encoding UTF8
    Write-Host "`nDa xuat bao cao Markdown tai: $ExportMarkdown" -ForegroundColor Green
}
