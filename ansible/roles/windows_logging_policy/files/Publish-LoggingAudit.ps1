Set-StrictMode -Version 2.0

$script:LoggingAuditHeader = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
$script:LoggingAuditTuple = '[{f3ccc681-b74c-4060-9f26-cd84525dca2a}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
$script:LoggingAuditCse = 'f3ccc681-b74c-4060-9f26-cd84525dca2a'
$script:LoggingAuditSupportedGuids = @{}
foreach ($supportedGuid in @(
    '{0cce9213-69ae-11d9-bed3-505054503030}', '{0cce9212-69ae-11d9-bed3-505054503030}',
    '{0cce9211-69ae-11d9-bed3-505054503030}', '{0cce9210-69ae-11d9-bed3-505054503030}',
    '{0cce9214-69ae-11d9-bed3-505054503030}', '{0cce9243-69ae-11d9-bed3-505054503030}',
    '{0cce921c-69ae-11d9-bed3-505054503030}', '{0cce921b-69ae-11d9-bed3-505054503030}',
    '{0cce921a-69ae-11d9-bed3-505054503030}', '{0cce9219-69ae-11d9-bed3-505054503030}',
    '{0cce9218-69ae-11d9-bed3-505054503030}', '{0cce9217-69ae-11d9-bed3-505054503030}',
    '{0cce9216-69ae-11d9-bed3-505054503030}', '{0cce9215-69ae-11d9-bed3-505054503030}',
    '{0cce9223-69ae-11d9-bed3-505054503030}', '{0cce9244-69ae-11d9-bed3-505054503030}',
    '{0cce9227-69ae-11d9-bed3-505054503030}', '{0cce9226-69ae-11d9-bed3-505054503030}',
    '{0cce9225-69ae-11d9-bed3-505054503030}', '{0cce9224-69ae-11d9-bed3-505054503030}',
    '{0cce9222-69ae-11d9-bed3-505054503030}', '{0cce9221-69ae-11d9-bed3-505054503030}',
    '{0cce9220-69ae-11d9-bed3-505054503030}', '{0cce921f-69ae-11d9-bed3-505054503030}',
    '{0cce921e-69ae-11d9-bed3-505054503030}', '{0cce921d-69ae-11d9-bed3-505054503030}',
    '{0cce9229-69ae-11d9-bed3-505054503030}', '{0cce922a-69ae-11d9-bed3-505054503030}',
    '{0cce9228-69ae-11d9-bed3-505054503030}', '{0cce922d-69ae-11d9-bed3-505054503030}',
    '{0cce922c-69ae-11d9-bed3-505054503030}', '{0cce922b-69ae-11d9-bed3-505054503030}',
    '{0cce922e-69ae-11d9-bed3-505054503030}', '{0cce9232-69ae-11d9-bed3-505054503030}',
    '{0cce9234-69ae-11d9-bed3-505054503030}', '{0cce9233-69ae-11d9-bed3-505054503030}',
    '{0cce922f-69ae-11d9-bed3-505054503030}', '{0cce9231-69ae-11d9-bed3-505054503030}',
    '{0cce9230-69ae-11d9-bed3-505054503030}', '{0cce923a-69ae-11d9-bed3-505054503030}',
    '{0cce9239-69ae-11d9-bed3-505054503030}', '{0cce9238-69ae-11d9-bed3-505054503030}',
    '{0cce9237-69ae-11d9-bed3-505054503030}', '{0cce9236-69ae-11d9-bed3-505054503030}',
    '{0cce9235-69ae-11d9-bed3-505054503030}', '{0cce923e-69ae-11d9-bed3-505054503030}',
    '{0cce923b-69ae-11d9-bed3-505054503030}', '{0cce923d-69ae-11d9-bed3-505054503030}',
    '{0cce923c-69ae-11d9-bed3-505054503030}', '{0cce9241-69ae-11d9-bed3-505054503030}',
    '{0cce9240-69ae-11d9-bed3-505054503030}', '{0cce923f-69ae-11d9-bed3-505054503030}',
    '{0cce9242-69ae-11d9-bed3-505054503030}', '{0cce9245-69ae-11d9-bed3-505054503030}',
    '{0cce9246-69ae-11d9-bed3-505054503030}', '{0cce9247-69ae-11d9-bed3-505054503030}',
    '{0cce9248-69ae-11d9-bed3-505054503030}', '{0cce9249-69ae-11d9-bed3-505054503030}'
)) {
    $script:LoggingAuditSupportedGuids[$supportedGuid] = $true
}

function Get-LoggingAuditHash {
    param([byte[]] $Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-LoggingAuditCanonicalGuid {
    param([string] $Value, [string] $Label)
    Assert-LoggingPolicyCondition ($Value -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') "$Label is not a brace-delimited GUID"
    $guid = [guid]::Parse($Value.Trim('{}'))
    return '{' + $guid.ToString('D').ToLowerInvariant() + '}'
}

function Assert-LoggingAuditSupportedGuid {
    param([string] $Guid)
    $canonical = Get-LoggingAuditCanonicalGuid $Guid 'Audit subcategory GUID'
    Assert-LoggingPolicyCondition ($script:LoggingAuditSupportedGuids.ContainsKey($canonical)) "Audit subcategory GUID is not in the reviewed MS-GPAC table: $Guid"
    return $canonical
}

function Get-LoggingAuditCanonicalSid {
    param([string] $Value)
    try {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($Value)
        return $sid.Value
    }
    catch {
        throw "Per-user audit Policy Target is not a valid standard SID: $($_.Exception.Message)"
    }
}

function Split-LoggingAuditRow {
    param([string] $Line)
    $field = '(?:"[\x20-\x21\x23-\x7E]*"|[^,]*)'
    $match = [regex]::Match($Line, "^(?<a>$field),(?<b>$field),(?<c>$field),(?<d>$field),(?<e>$field),(?<f>$field),(?<g>$field)$")
    Assert-LoggingPolicyCondition $match.Success 'Audit CSV row must contain exactly seven protocol fields'
    $raw = @($match.Groups['a'].Value, $match.Groups['b'].Value, $match.Groups['c'].Value,
        $match.Groups['d'].Value, $match.Groups['e'].Value, $match.Groups['f'].Value, $match.Groups['g'].Value)
    $values = @()
    foreach ($value in $raw) {
        if ($value.StartsWith('"')) {
            Assert-LoggingPolicyCondition ($value.EndsWith('"') -and $value.Length -ge 2) 'Malformed quoted audit field'
            $values += $value.Substring(1, $value.Length - 2)
        }
        else {
            Assert-LoggingPolicyCondition ($value -notmatch '"') 'Quotes are allowed only as a complete audit field'
            $values += $value
        }
    }
    return @{ raw = $raw; values = $values }
}

function Assert-LoggingAuditString {
    param([string] $Raw, [string] $Value, [bool] $AllowSpaces, [string] $Label)
    if ($Raw.StartsWith('"')) {
        Assert-LoggingPolicyCondition ($Raw -match '^"[\x20-\x21\x23-\x7E]*"$') "$Label has invalid quoted characters"
        return
    }
    $pattern = if ($AllowSpaces) { '^[A-Za-z0-9/\-:; ]*$' } else { '^[A-Za-z0-9/\-:;]*$' }
    Assert-LoggingPolicyCondition ($Value -match $pattern) "$Label has characters outside the MS-GPAC grammar"
}

function ConvertFrom-LoggingAuditLine {
    param([string] $Line)
    $split = Split-LoggingAuditRow $Line
    $raw = $split.raw
    $field = $split.values
    Assert-LoggingAuditString $raw[0] $field[0] $false 'Audit Machine Name'
    foreach ($index in @(1, 3, 4, 5, 6)) {
        Assert-LoggingPolicyCondition (-not $raw[$index].StartsWith('"')) "Audit field $index cannot be quoted"
    }

    if ($field[1] -eq 'System') {
        Assert-LoggingAuditString $raw[2] $field[2] $true 'Audit Subcategory'
        $guid = Assert-LoggingAuditSupportedGuid $field[3]
        Assert-LoggingPolicyCondition (@('Success', 'Failure', 'Success and Failure', 'No Auditing', 'Not Specified') -contains $field[4]) 'Invalid system audit inclusion text'
        Assert-LoggingPolicyCondition ($field[5] -eq '') 'System audit exclusion field must be empty'
        Assert-LoggingPolicyCondition ($field[6] -match '^[0-4]$') 'Invalid system audit setting value'
        return @{ class = 0; key = "system`n$guid"; guid = $guid; setting = [int] $field[6]; raw = $Line }
    }
    if ($field[1] -ne '') {
        $sid = Get-LoggingAuditCanonicalSid $field[1]
        Assert-LoggingAuditString $raw[2] $field[2] $true 'Per-user audit Subcategory'
        $guid = Assert-LoggingAuditSupportedGuid $field[3]
        foreach ($index in @(4, 5)) {
            Assert-LoggingPolicyCondition (@('', 'Success', 'Failure', 'Success and Failure', 'No Auditing', 'Not Specified') -contains $field[$index]) 'Invalid per-user audit display setting'
        }
        Assert-LoggingPolicyCondition ($field[6] -match '^(?:0|16|[1-9]|1[0-5])$') 'Invalid per-user audit setting value'
        return @{ class = 0; key = "user`n$sid`n$guid"; guid = $guid; setting = [int] $field[6]; raw = $Line }
    }
    if ($field[1] -eq '' -and $field[2] -match '^Option:(CrashOnAuditFail|FullPrivilegeAuditing|AuditBaseObjects|AuditBaseDirectories)$') {
        Assert-LoggingPolicyCondition (-not $raw[2].StartsWith('"')) 'Audit-option type cannot be quoted'
        Assert-LoggingPolicyCondition ($field[3] -eq '' -and $field[5] -eq '') 'Audit-option reserved fields must be empty'
        Assert-LoggingPolicyCondition (@('Enabled', 'Disabled') -contains $field[4]) 'Invalid audit-option text'
        Assert-LoggingPolicyCondition ($field[6] -match '^[01]$') 'Invalid audit-option value'
        return @{ class = 1; key = "option`n$($field[2].ToLowerInvariant())"; guid = $null; setting = [int] $field[6]; raw = $Line }
    }
    if ($field[1] -eq '' -and @('FileGlobalSacl', 'RegistryGlobalSacl') -contains $field[2]) {
        Assert-LoggingPolicyCondition (-not $raw[2].StartsWith('"')) 'Global-SACL type cannot be quoted'
        Assert-LoggingPolicyCondition ($field[3] -eq '' -and $field[4] -eq '' -and $field[5] -eq '') 'Global-SACL reserved fields must be empty'
        try {
            $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($field[6])
            Assert-LoggingPolicyCondition ($null -ne $descriptor.SystemAcl) 'Global-SACL row must contain an SDDL SACL'
        }
        catch {
            throw "Invalid global-SACL SDDL: $($_.Exception.Message)"
        }
        return @{ class = 2; key = "sacl`n$($field[2].ToLowerInvariant())"; guid = $null; setting = $field[6]; raw = $Line }
    }
    throw 'Audit CSV row does not match a supported MS-GPAC row class'
}

function ConvertFrom-LoggingAuditText {
    param([string] $Text, [bool] $RequireCrLf)
    Assert-LoggingPolicyCondition (-not [string]::IsNullOrEmpty($Text)) 'Audit CSV is empty'
    if ($RequireCrLf) {
        Assert-LoggingPolicyCondition $Text.EndsWith("`r`n") 'Audit CSV must end with CRLF'
        $withoutCrLf = $Text.Replace("`r`n", '')
        Assert-LoggingPolicyCondition ($withoutCrLf -notmatch "[`r`n]") 'Audit CSV contains a bare CR or LF'
        $lines = @($Text.Substring(0, $Text.Length - 2).Split(@("`r`n"), [System.StringSplitOptions]::None))
    }
    else {
        $normalized = $Text.Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd("`n")
        $lines = @($normalized.Split(@("`n"), [System.StringSplitOptions]::None))
    }
    Assert-LoggingPolicyCondition ($lines.Count -ge 1 -and $lines[0] -ceq $script:LoggingAuditHeader) 'Audit CSV header is not exact'
    $rows = @()
    $seen = @{}
    $lastClass = 0
    for ($index = 1; $index -lt $lines.Count; $index++) {
        Assert-LoggingPolicyCondition ($lines[$index].Length -gt 0) 'Audit CSV contains an empty physical row'
        $row = ConvertFrom-LoggingAuditLine $lines[$index]
        Assert-LoggingPolicyCondition ($row.class -ge $lastClass) 'Audit CSV row classes are out of protocol order'
        $lastClass = $row.class
        Assert-LoggingPolicyCondition (-not $seen.ContainsKey($row.key)) "Audit CSV contains duplicate semantic key '$($row.key)'"
        $seen[$row.key] = $true
        $rows += ,$row
    }
    return $rows
}

function ConvertTo-LoggingAuditBytes {
    param([object] $Rows)
    $lines = @($script:LoggingAuditHeader)
    foreach ($row in @($Rows)) {
        $lines += [string] $row.raw
    }
    $text = [string]::Join("`r`n", $lines) + "`r`n"
    $bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($text)
    return ,$bytes
}

function Read-LoggingAuditPayload {
    param([string] $Path)
    if (-not [System.IO.File]::Exists($Path)) {
        return @{ exists = $false; bytes = $null; hash = $null; rows = @() }
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    Assert-LoggingPolicyCondition (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) 'Audit CSV must not contain a UTF-8 BOM'
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    catch {
        throw "Audit CSV is not strict UTF-8: $($_.Exception.Message)"
    }
    $rows = @(ConvertFrom-LoggingAuditText $text $true)
    return @{ exists = $true; bytes = $bytes; hash = Get-LoggingAuditHash $bytes; rows = $rows }
}

function Get-LoggingAuditLdapConnection {
    param([string] $Server)
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($Server)
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $connection.SessionOptions.ProtocolVersion = 3
    $connection.Bind()
    return $connection
}

function Get-LoggingAuditAttributeString {
    param([System.DirectoryServices.Protocols.SearchResultEntry] $Entry, [string] $Name, [bool] $AllowAbsent)
    if (-not $Entry.Attributes.Contains($Name) -or $Entry.Attributes[$Name].Count -eq 0) {
        Assert-LoggingPolicyCondition $AllowAbsent "LDAP attribute '$Name' is absent"
        return ''
    }
    Assert-LoggingPolicyCondition ($Entry.Attributes[$Name].Count -eq 1) "LDAP attribute '$Name' is multi-valued"
    $values = @($Entry.Attributes[$Name].GetValues([string]))
    Assert-LoggingPolicyCondition ($values.Count -eq 1) "LDAP attribute '$Name' cannot be decoded as one string"
    return [string] $values[0]
}

function Get-LoggingAuditDirectoryState {
    param([hashtable] $Context)
    $connection = Get-LoggingAuditLdapConnection $Context.dc
    try {
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $Context.gpo_dn, '(objectClass=groupPolicyContainer)',
            [System.DirectoryServices.Protocols.SearchScope]::Base,
            @('versionNumber', 'gPCMachineExtensionNames', 'gPCFileSysPath'))
        $response = [System.DirectoryServices.Protocols.SearchResponse] $connection.SendRequest($request)
        Assert-LoggingPolicyCondition ($response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) 'LDAP GPO read failed'
        Assert-LoggingPolicyCondition ($response.Entries.Count -eq 1) 'LDAP GPO read did not return exactly one entry'
        $entry = $response.Entries[0]
        $versionText = Get-LoggingAuditAttributeString $entry 'versionNumber' $false
        $version = [uint32] 0
        Assert-LoggingPolicyCondition ([uint32]::TryParse($versionText, [ref] $version)) 'LDAP versionNumber is not an unsigned 32-bit integer'
        $extensions = Get-LoggingAuditAttributeString $entry 'gPCMachineExtensionNames' $true
        $fileSysPath = Get-LoggingAuditAttributeString $entry 'gPCFileSysPath' $false
        $expected = "\\$($Context.domain_dns)\SYSVOL\$($Context.domain_dns)\Policies\{" + ([guid] $Context.gpo_guid).ToString('D') + '}\'
        $normalize = { param($value) ([string] $value).Replace('/', '\').TrimEnd('\') }
        Assert-LoggingPolicyCondition ([string]::Equals((& $normalize $fileSysPath), (& $normalize $expected), [System.StringComparison]::OrdinalIgnoreCase)) 'gPCFileSysPath does not match the target-domain GPO identity'
        return @{ version = $version; extensions = $extensions }
    }
    finally {
        $connection.Dispose()
    }
}

function ConvertFrom-LoggingAuditExtensions {
    param([string] $Value)
    if ([string]::IsNullOrEmpty($Value)) {
        return @()
    }
    $pairs = @()
    $seen = @{}
    $pattern = '\[\{(?<cse>[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}\{(?<tool>[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}\]'
    while ($Value.Length -gt 0) {
        $match = [regex]::Match($Value, $pattern, [System.Text.RegularExpressions.RegexOptions]::None, [timespan]::FromSeconds(1))
        Assert-LoggingPolicyCondition ($match.Success -and $match.Index -eq 0) 'Malformed gPCMachineExtensionNames tuple sequence'
        $raw = $match.Value
        $cse = $match.Groups['cse'].Value.ToLowerInvariant()
        Assert-LoggingPolicyCondition (-not $seen.ContainsKey($cse)) "Duplicate CSE GUID in gPCMachineExtensionNames: $cse"
        $seen[$cse] = $true
        $pairs += ,@{ cse = $cse; raw = $raw }
        $Value = $Value.Substring($match.Length)
    }
    $previous = ''
    foreach ($pair in $pairs) {
        Assert-LoggingPolicyCondition ($previous -eq '' -or [string]::Compare($previous, $pair.cse, $true) -lt 0) 'gPCMachineExtensionNames CSE tuples are not sorted'
        $previous = $pair.cse
    }
    return $pairs
}

function Get-LoggingAuditIntendedExtensions {
    param([string] $Current, [bool] $AuditDataRemains)
    $pairs = @(ConvertFrom-LoggingAuditExtensions $Current)
    $result = @($pairs | Where-Object { $_.cse -ne $script:LoggingAuditCse })
    $existingAudit = @($pairs | Where-Object { $_.cse -eq $script:LoggingAuditCse })
    if ($existingAudit.Count -eq 1) {
        Assert-LoggingPolicyCondition ([string]::Equals($existingAudit[0].raw, $script:LoggingAuditTuple, [System.StringComparison]::OrdinalIgnoreCase)) 'Audit CSE is registered with an unexpected tool GUID'
    }
    if ($AuditDataRemains) {
        $result += ,@{ cse = $script:LoggingAuditCse; raw = $script:LoggingAuditTuple }
    }
    $sorted = @($result | Sort-Object -Property cse)
    return [string]::Join('', @($sorted | ForEach-Object { $_.raw }))
}

function Read-LoggingAuditGptVersion {
    param([string] $Path)
    Assert-LoggingPolicyCondition ([System.IO.File]::Exists($Path)) "GPT.INI is missing: $Path"
    $text = [System.IO.File]::ReadAllText($Path)
    $lines = @($text.Replace("`r`n", "`n").Replace("`r", "`n").Split("`n"))
    $inGeneral = $false
    $versions = @()
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match '^\s*\[(?<section>[^]]+)\]\s*$') {
            $inGeneral = $Matches.section -ieq 'General'
        }
        elseif ($inGeneral -and $lines[$index] -match '^\s*Version\s*=\s*(?<version>\d+)\s*$') {
            $versions += ,@{ index = $index; value = $Matches.version }
        }
    }
    Assert-LoggingPolicyCondition ($versions.Count -eq 1) 'GPT.INI must contain one Version in [General]'
    $version = [uint32] 0
    Assert-LoggingPolicyCondition ([uint32]::TryParse([string] $versions[0].value, [ref] $version)) 'GPT.INI Version is outside uint32 range'
    return @{ version = $version; text = $text; line_index = [int] $versions[0].index }
}

function Get-LoggingAuditSnapshot {
    param([hashtable] $Context)
    $auditPath = [System.IO.Path]::Combine($Context.gpt_path, 'Machine\Microsoft\Windows NT\Audit\audit.csv')
    $gptPath = [System.IO.Path]::Combine($Context.gpt_path, 'GPT.INI')
    $directory = Get-LoggingAuditDirectoryState $Context
    $gpt = Read-LoggingAuditGptVersion $gptPath
    Assert-LoggingPolicyCondition ($directory.version -eq $gpt.version) 'AD and GPT versions disagree before audit publication'
    $null = ConvertFrom-LoggingAuditExtensions $directory.extensions
    return @{
        audit_path = $auditPath
        gpt_path = $gptPath
        payload = Read-LoggingAuditPayload $auditPath
        ad_version = [uint32] $directory.version
        gpt_version = [uint32] $gpt.version
        extensions = [string] $directory.extensions
        gpt_text = [string] $gpt.text
        gpt_version_line = [int] $gpt.line_index
    }
}

function Test-LoggingAuditGuidInList {
    param([string] $Guid, [object] $Values)
    foreach ($value in @($Values)) {
        if ([string]::Equals($Guid.Trim('{}'), ([string] $value).Trim('{}'), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Merge-LoggingAuditRows {
    param([object] $Existing, [object] $Desired, [object] $PriorOwned)
    $desiredByGuid = @{}
    foreach ($row in @($Desired)) {
        Assert-LoggingPolicyCondition ($row.class -eq 0 -and $row.key.StartsWith("system`n")) 'The role-authored audit template may contain only system-subcategory rows'
        $desiredByGuid[$row.guid] = $row
    }
    $subcategory = @()
    $options = @()
    $sacls = @()
    $seenDesiredCollision = @{}
    foreach ($row in @($Existing)) {
        if ($row.class -eq 0 -and $row.key.StartsWith("system`n") -and $desiredByGuid.ContainsKey($row.guid)) {
            if (-not (Test-LoggingAuditGuidInList $row.guid $PriorOwned)) {
                throw "Desired audit GUID already exists outside committed ownership: $($row.guid)"
            }
            $desiredRow = $desiredByGuid[$row.guid]
            if ($row.setting -eq $desiredRow.setting) {
                $subcategory += ,$row
            }
            else {
                $subcategory += ,$desiredRow
            }
            $seenDesiredCollision[$row.guid] = $true
            continue
        }
        if ($row.class -eq 0 -and $row.key.StartsWith("system`n") -and (Test-LoggingAuditGuidInList $row.guid $PriorOwned)) {
            continue
        }
        if ($row.class -eq 0) { $subcategory += ,$row }
        elseif ($row.class -eq 1) { $options += ,$row }
        else { $sacls += ,$row }
    }
    foreach ($row in @($Desired)) {
        if (-not $seenDesiredCollision.ContainsKey($row.guid)) {
            $subcategory += ,$row
        }
    }
    return @($subcategory + $options + $sacls)
}

function Get-LoggingAuditNextVersion {
    param([uint32] $Version)
    $user = ($Version -shr 16) -band 0xffff
    $machine = ($Version -band 0xffff) + 1
    if ($machine -gt 0xffff) { $machine = 1 }
    return [uint32] (($user -shl 16) -bor $machine)
}

function Write-LoggingAuditBackup {
    param([hashtable] $Context, [hashtable] $Snapshot)
    if (-not $Snapshot.payload.exists) {
        return $null
    }
    $directory = [System.IO.Path]::GetDirectoryName([string] $Context.state_path)
    $name = "audit-$($Context.gpo_guid)-$($Snapshot.payload.hash).csv"
    $path = [System.IO.Path]::Combine($directory, $name)
    if ([System.IO.File]::Exists($path)) {
        Assert-LoggingPolicyCondition ((Get-LoggingAuditHash ([System.IO.File]::ReadAllBytes($path))) -eq $Snapshot.payload.hash) 'Protected audit backup path has unexpected content'
        return $path
    }
    $acl = New-LoggingPolicyAcl $false
    Start-LoggingPolicyMutation $Context.progress 'logging' 'create_audit_backup' $path
    $stream = [System.IO.FileStream]::new($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Snapshot.payload.bytes, 0, $Snapshot.payload.bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    Assert-LoggingPolicyProtectedAcl $path
    Complete-LoggingPolicyMutation $Context.progress
    return $path
}

function Start-LoggingAuditPending {
    param(
        [hashtable] $Context, [hashtable] $State, [string] $Operation,
        [object] $TargetGuids, [object] $IntendedGuids, [hashtable] $Snapshot,
        [uint32] $IntendedVersion, [string] $IntendedExtensions,
        [object] $DesiredHash, [bool] $DesiredDeletion, [object] $BackupPath
    )
    $record = $State.policies.logging
    $record.pending = @{
        operation = $Operation
        target = @{
            policy_id = 'logging'; target_name = [string] $Context.policy_name
            gpo_guid = [string] $Context.gpo_guid; audit_guids = @($TargetGuids)
        }
        prior_ownership = @{ audit_guids = @($record.audit_guids) }
        intended_ownership = @{ audit_guids = @($IntendedGuids) }
        audit = @{
            dc = [string] $Context.dc
            prior_ad_version = [uint32] $Snapshot.ad_version
            intended_ad_version = $IntendedVersion
            prior_gpt_version = [uint32] $Snapshot.gpt_version
            intended_gpt_version = $IntendedVersion
            prior_machine_extensions = [string] $Snapshot.extensions
            intended_machine_extensions = $IntendedExtensions
            prior_hash = $Snapshot.payload.hash
            prior_backup_path = $BackupPath
            desired_hash = $DesiredHash
            desired_deletion = $DesiredDeletion
        }
    }
    Write-LoggingPolicyState $Context $State
}

function Assert-LoggingAuditSnapshotMatchesPrior {
    param([hashtable] $Current, [hashtable] $Prior)
    Assert-LoggingPolicyCondition ($Current.ad_version -eq $Prior.ad_version -and $Current.gpt_version -eq $Prior.gpt_version) 'Audit versions changed concurrently after pending persistence'
    Assert-LoggingPolicyCondition ([string]::Equals($Current.extensions, $Prior.extensions, [System.StringComparison]::Ordinal)) 'Audit extension registration changed concurrently after pending persistence'
    Assert-LoggingPolicyCondition ([string]::Equals([string] $Current.payload.hash, [string] $Prior.payload.hash, [System.StringComparison]::OrdinalIgnoreCase)) 'Audit payload changed concurrently after pending persistence'
}

function Write-LoggingAuditPayload {
    param([string] $Path, [byte[]] $Bytes, [bool] $Delete)
    if ($Delete) {
        if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Delete($Path) }
        return
    }
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    $null = [System.IO.Directory]::CreateDirectory($directory)
    $temporary = [System.IO.Path]::Combine($directory, ('.audit-' + [System.IO.Path]::GetRandomFileName()))
    try {
        $stream = [System.IO.FileStream]::new($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if ([System.IO.File]::Exists($Path)) {
            [System.IO.File]::Replace($temporary, $Path, $null)
        }
        else {
            [System.IO.File]::Move($temporary, $Path)
        }
    }
    finally {
        if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) }
    }
}

function Set-LoggingAuditLdapState {
    param([hashtable] $Context, [uint32] $Version, [string] $Extensions)
    $connection = Get-LoggingAuditLdapConnection $Context.dc
    try {
        $request = [System.DirectoryServices.Protocols.ModifyRequest]::new($Context.gpo_dn)
        $versionChange = [System.DirectoryServices.Protocols.DirectoryAttributeModification]::new()
        $versionChange.Name = 'versionNumber'
        $versionChange.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        $null = $versionChange.Add($Version.ToString([System.Globalization.CultureInfo]::InvariantCulture))
        $null = $request.Modifications.Add($versionChange)
        $extensionChange = [System.DirectoryServices.Protocols.DirectoryAttributeModification]::new()
        $extensionChange.Name = 'gPCMachineExtensionNames'
        $extensionChange.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        if (-not [string]::IsNullOrEmpty($Extensions)) { $null = $extensionChange.Add($Extensions) }
        $null = $request.Modifications.Add($extensionChange)
        $response = [System.DirectoryServices.Protocols.ModifyResponse] $connection.SendRequest($request)
        Assert-LoggingPolicyCondition ($response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) 'Combined LDAP audit extension/version replacement failed'
    }
    finally { $connection.Dispose() }
}

function Set-LoggingAuditGptVersion {
    param([hashtable] $Snapshot, [uint32] $Version)
    $current = Read-LoggingAuditGptVersion $Snapshot.gpt_path
    Assert-LoggingPolicyCondition ($current.version -eq $Snapshot.gpt_version) 'GPT.INI changed before version publication'
    $lines = @($current.text.Replace("`r`n", "`n").Replace("`r", "`n").Split("`n"))
    $lines[$current.line_index] = "Version=$Version"
    $text = [string]::Join("`r`n", $lines)
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $temporary = $Snapshot.gpt_path + '.ludus-' + [System.IO.Path]::GetRandomFileName()
    try {
        $stream = [System.IO.FileStream]::new($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $bytes = $encoding.GetBytes($text)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        [System.IO.File]::Replace($temporary, $Snapshot.gpt_path, $null)
    }
    finally {
        if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) }
    }
}

function Assert-LoggingAuditPayloadReadback {
    param([string] $Path, [object] $DesiredHash, [bool] $DesiredDeletion)
    $payload = Read-LoggingAuditPayload $Path
    if ($DesiredDeletion) {
        Assert-LoggingPolicyCondition (-not $payload.exists) 'Audit CSV deletion readback failed before version publication'
    }
    else {
        Assert-LoggingPolicyCondition (
            [string]::Equals([string] $payload.hash, [string] $DesiredHash, [System.StringComparison]::OrdinalIgnoreCase)
        ) 'Audit CSV hash readback failed before version publication'
    }
}

function Assert-LoggingAuditReadback {
    param([hashtable] $Context, [object] $DesiredHash, [bool] $DesiredDeletion, [uint32] $Version, [string] $Extensions)
    $current = Get-LoggingAuditSnapshot $Context
    if ($DesiredDeletion) {
        Assert-LoggingPolicyCondition (-not $current.payload.exists) 'Audit CSV deletion readback failed'
    }
    else {
        Assert-LoggingPolicyCondition ([string]::Equals([string] $current.payload.hash, [string] $DesiredHash, [System.StringComparison]::OrdinalIgnoreCase)) 'Audit CSV hash readback failed'
    }
    Assert-LoggingPolicyCondition ($current.ad_version -eq $Version -and $current.gpt_version -eq $Version) 'Audit version readback failed'
    Assert-LoggingPolicyCondition ([string]::Equals($current.extensions, $Extensions, [System.StringComparison]::Ordinal)) 'Audit extension readback failed'
}

function Complete-LoggingAuditPending {
    param([hashtable] $Context, [hashtable] $State)
    $record = $State.policies.logging
    $record.audit_guids = @($record.pending.intended_ownership.audit_guids)
    $record.pending = $null
    Write-LoggingPolicyState $Context $State
}

function Publish-LoggingAudit {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [hashtable] $Context,
        [hashtable] $State,
        [string] $DesiredCsv,
        [bool] $PlanOnly
    )

    Assert-LoggingPolicyCondition ($Context.writer_held -eq $true) 'Publish-LoggingAudit requires the caller-held writer lock'
    if (-not $Context.Contains('progress')) { $Context.progress = New-LoggingPolicyProgress }
    Set-LoggingPolicyProgressScope $Context.progress 'logging' 'audit_preflight' $Context.state_path
    Assert-LoggingPolicyCondition ($State.policies.Contains('logging')) 'Publish-LoggingAudit requires verified logging GPO ownership'
    $record = $State.policies.logging
    Assert-LoggingPolicyCondition ($null -eq $record.pending) 'Unresolved pending state blocks audit publication'
    Assert-LoggingPolicyCondition ([string] $record.gpo_guid -eq [string] $Context.gpo_guid) 'Logging state GUID does not match publisher Context'

    $desiredRows = @(ConvertFrom-LoggingAuditText $DesiredCsv $false)
    $desiredGuids = @($desiredRows | ForEach-Object { $_.guid.Trim('{}') })
    $snapshot = Get-LoggingAuditSnapshot $Context
    $null = @(Merge-LoggingAuditRows $snapshot.payload.rows $desiredRows $record.audit_guids)
    $removed = @($record.audit_guids | Where-Object { -not (Test-LoggingAuditGuidInList ([string] $_) $desiredGuids) })
    $added = @($desiredGuids | Where-Object { -not (Test-LoggingAuditGuidInList ([string] $_) $record.audit_guids) })
    $transitions = @()
    if ($removed.Count -gt 0) {
        $intermediateGuids = @($record.audit_guids | Where-Object { -not (Test-LoggingAuditGuidInList ([string] $_) $removed) })
        $intermediateRows = @($desiredRows | Where-Object { Test-LoggingAuditGuidInList $_.guid $intermediateGuids })
        $transitions += ,@{ operation = 'audit_delete'; target = $removed; guids = $intermediateGuids; rows = $intermediateRows }
    }
    if ($added.Count -gt 0 -or $removed.Count -eq 0) {
        $target = if ($desiredGuids.Count -gt 0) { $desiredGuids } else { @($record.audit_guids) }
        if ($target.Count -gt 0) {
            $transitions += ,@{ operation = 'audit_publish'; target = $target; guids = $desiredGuids; rows = $desiredRows }
        }
    }

    $changed = $false
    foreach ($transition in $transitions) {
        $mergedRows = @(Merge-LoggingAuditRows $snapshot.payload.rows $transition.rows $record.audit_guids)
        $desiredDeletion = $mergedRows.Count -eq 0
        $bytes = if ($desiredDeletion) { $null } else { ConvertTo-LoggingAuditBytes $mergedRows }
        $desiredHash = if ($desiredDeletion) { $null } else { Get-LoggingAuditHash $bytes }
        $extensions = Get-LoggingAuditIntendedExtensions $snapshot.extensions (-not $desiredDeletion)
        $payloadChanged = -not [string]::Equals([string] $snapshot.payload.hash, [string] $desiredHash, [System.StringComparison]::OrdinalIgnoreCase)
        $extensionChanged = -not [string]::Equals($snapshot.extensions, $extensions, [System.StringComparison]::Ordinal)
        $ownershipChanged = @($record.audit_guids).Count -ne @($transition.guids).Count -or
            @($record.audit_guids | Where-Object { -not (Test-LoggingAuditGuidInList ([string] $_) $transition.guids) }).Count -gt 0
        if (-not $payloadChanged -and -not $extensionChanged -and -not $ownershipChanged) {
            continue
        }
        $changed = $true
        if ($PlanOnly -or -not $PSCmdlet.ShouldProcess($Context.gpo_guid, $transition.operation)) {
            continue
        }

        $authoritativeChanged = $payloadChanged -or $extensionChanged
        $intendedVersion = if ($authoritativeChanged) { Get-LoggingAuditNextVersion $snapshot.ad_version } else { [uint32] $snapshot.ad_version }
        $backupPath = Write-LoggingAuditBackup $Context $snapshot
        Start-LoggingPolicyMutation $Context.progress 'logging' "persist_$($transition.operation)" $Context.state_path
        Start-LoggingAuditPending $Context $State $transition.operation $transition.target $transition.guids $snapshot $intendedVersion $extensions $desiredHash $desiredDeletion $backupPath
        Complete-LoggingPolicyMutation $Context.progress
        Set-LoggingPolicyProgressScope $Context.progress 'logging' 'audit_concurrency_readback' $Context.state_path
        $recheck = Get-LoggingAuditSnapshot $Context
        Assert-LoggingAuditSnapshotMatchesPrior $recheck $snapshot
        if ($authoritativeChanged) {
            if ($payloadChanged) {
                Start-LoggingPolicyMutation $Context.progress 'logging' 'audit_payload' $snapshot.audit_path
                Write-LoggingAuditPayload $snapshot.audit_path $bytes $desiredDeletion
                Assert-LoggingAuditPayloadReadback $snapshot.audit_path $desiredHash $desiredDeletion
                Complete-LoggingPolicyMutation $Context.progress
            }
            else { Assert-LoggingAuditPayloadReadback $snapshot.audit_path $desiredHash $desiredDeletion }
            Start-LoggingPolicyMutation $Context.progress 'logging' 'audit_ldap' $Context.gpo_dn
            Set-LoggingAuditLdapState $Context $intendedVersion $extensions
            Complete-LoggingPolicyMutation $Context.progress
            Start-LoggingPolicyMutation $Context.progress 'logging' 'audit_gpt_version' $snapshot.gpt_path
            Set-LoggingAuditGptVersion $snapshot $intendedVersion
            Complete-LoggingPolicyMutation $Context.progress
        }
        Set-LoggingPolicyProgressScope $Context.progress 'logging' 'audit_final_readback' $Context.state_path
        Assert-LoggingAuditReadback $Context $desiredHash $desiredDeletion $intendedVersion $extensions
        Start-LoggingPolicyMutation $Context.progress 'logging' 'commit_audit_state' $Context.state_path
        Complete-LoggingAuditPending $Context $State
        Complete-LoggingPolicyMutation $Context.progress
        $snapshot = Get-LoggingAuditSnapshot $Context
    }
    return @{ changed = $changed; state = $State }
}
