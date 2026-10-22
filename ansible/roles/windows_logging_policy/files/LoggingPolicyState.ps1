Set-StrictMode -Version 2.0

class LudusLoggingPolicyWriterHandle : System.IDisposable {
    hidden [System.Threading.Mutex] $Mutex
    hidden [bool] $OwnsMutex

    LudusLoggingPolicyWriterHandle([System.Threading.Mutex] $mutex, [bool] $ownsMutex) {
        $this.Mutex = $mutex
        $this.OwnsMutex = $ownsMutex
    }

    [void] Dispose() {
        if ($null -eq $this.Mutex) {
            return
        }
        try {
            if ($this.OwnsMutex) {
                $this.Mutex.ReleaseMutex()
                $this.OwnsMutex = $false
            }
        }
        finally {
            $this.Mutex.Dispose()
            $this.Mutex = $null
        }
    }
}

function Assert-LoggingPolicyCondition {
    param(
        [bool] $Condition,
        [string] $Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-LoggingPolicyExactKeys {
    param(
        [System.Collections.IDictionary] $Value,
        [string[]] $Keys,
        [string] $Label
    )
    Assert-LoggingPolicyCondition ($null -ne $Value) "$Label must be a mapping"
    $actual = @($Value.Keys | ForEach-Object { [string] $_ })
    Assert-LoggingPolicyCondition ($actual.Count -eq $Keys.Count) "$Label has unsupported or missing keys"
    foreach ($key in $Keys) {
        Assert-LoggingPolicyCondition ($Value.Contains($key)) "$Label is missing '$key'"
    }
}

function Assert-LoggingPolicyString {
    param(
        [object] $Value,
        [string] $Label,
        [bool] $AllowEmpty = $false
    )
    Assert-LoggingPolicyCondition ($Value -is [string]) "$Label must be a string"
    if (-not $AllowEmpty) {
        Assert-LoggingPolicyCondition (-not [string]::IsNullOrWhiteSpace([string] $Value)) "$Label must not be empty"
    }
}

function Assert-LoggingPolicyBoolean {
    param([object] $Value, [string] $Label)
    Assert-LoggingPolicyCondition ($Value -is [bool]) "$Label must be a boolean"
}

function Assert-LoggingPolicyInteger {
    param(
        [object] $Value,
        [string] $Label,
        [int64] $Minimum,
        [int64] $Maximum
    )
    $isInteger = $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]
    Assert-LoggingPolicyCondition $isInteger "$Label must be an integer"
    $number = [int64] $Value
    Assert-LoggingPolicyCondition ($number -ge $Minimum -and $number -le $Maximum) "$Label is outside the supported range"
}

function Assert-LoggingPolicyList {
    param([object] $Value, [string] $Label)
    $isList = $Value -is [System.Collections.IList] -and $Value -isnot [string]
    Assert-LoggingPolicyCondition $isList "$Label must be a list"
}

function Get-LoggingPolicyGuidString {
    param([object] $Value, [string] $Label)
    Assert-LoggingPolicyString $Value $Label
    $guid = [guid]::Empty
    Assert-LoggingPolicyCondition ([guid]::TryParse(([string] $Value).Trim('{}'), [ref] $guid)) "$Label must be a GUID"
    return $guid.ToString('D').ToLowerInvariant()
}

function Assert-LoggingPolicyConfiguration {
    param([hashtable] $Configuration)

    $keys = @(
        'domain', 'server', 'owner_id', 'management_host', 'state_dir',
        'logging_enabled', 'enrollment_enabled', 'defender_disable_policy_enabled',
        'names', 'links', 'audit_subcategories', 'powershell', 'enrollment', 'defender',
        'execution_inventory_host', 'desired_audit_csv'
    )
    Assert-LoggingPolicyExactKeys $Configuration $keys 'Configuration'
    foreach ($name in @('domain', 'server', 'desired_audit_csv')) {
        Assert-LoggingPolicyString $Configuration[$name] "Configuration.$name" $true
    }
    foreach ($name in @('owner_id', 'management_host', 'state_dir', 'execution_inventory_host')) {
        Assert-LoggingPolicyString $Configuration[$name] "Configuration.$name"
    }
    Assert-LoggingPolicyCondition (
        [string] $Configuration.owner_id -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ) 'Configuration.owner_id contains unsupported marker characters'
    Assert-LoggingPolicyCondition (
        [string]::Equals([string] $Configuration.management_host, [string] $Configuration.execution_inventory_host,
            [System.StringComparison]::OrdinalIgnoreCase)
    ) 'The executing inventory host is not the designated management host'

    foreach ($name in @('logging_enabled', 'enrollment_enabled', 'defender_disable_policy_enabled')) {
        Assert-LoggingPolicyBoolean $Configuration[$name] "Configuration.$name"
    }

    $policyIds = @('logging', 'enrollment', 'defender')
    Assert-LoggingPolicyCondition ($Configuration.names -is [System.Collections.IDictionary]) 'Configuration.names must be a mapping'
    Assert-LoggingPolicyExactKeys $Configuration.names $policyIds 'Configuration.names'
    $seenNames = @{}
    foreach ($policyId in $policyIds) {
        $policyName = $Configuration.names[$policyId]
        Assert-LoggingPolicyString $policyName "Configuration.names.$policyId"
        $normalizedName = ([string] $policyName).Trim().ToLowerInvariant()
        Assert-LoggingPolicyCondition (-not $seenNames.ContainsKey($normalizedName)) 'Policy names must be unique'
        Assert-LoggingPolicyCondition (
            $normalizedName -ne 'default domain policy' -and
            $normalizedName -ne 'default domain controllers policy'
        ) "Configuration.names.$policyId must not name a built-in policy"
        $seenNames[$normalizedName] = $true
    }

    Assert-LoggingPolicyCondition ($Configuration.links -is [System.Collections.IDictionary]) 'Configuration.links must be a mapping'
    Assert-LoggingPolicyExactKeys $Configuration.links $policyIds 'Configuration.links'
    foreach ($policyId in $policyIds) {
        $links = $Configuration.links[$policyId]
        Assert-LoggingPolicyList $links "Configuration.links.$policyId"
        foreach ($link in $links) {
            Assert-LoggingPolicyCondition ($link -is [System.Collections.IDictionary]) "Configuration.links.$policyId item must be a mapping"
            $linkKeys = @($link.Keys | ForEach-Object { [string] $_ })
            $requiredLinkKeys = @('target', 'enabled', 'enforced')
            foreach ($key in $requiredLinkKeys) {
                Assert-LoggingPolicyCondition ($link.Contains($key)) "Configuration.links.$policyId item is missing '$key'"
            }
            Assert-LoggingPolicyCondition (
                $linkKeys.Count -eq 3 -or ($linkKeys.Count -eq 4 -and $link.Contains('order'))
            ) "Configuration.links.$policyId item has unsupported keys"
            Assert-LoggingPolicyString $link.target "Configuration.links.$policyId.target"
            Assert-LoggingPolicyBoolean $link.enabled "Configuration.links.$policyId.enabled"
            Assert-LoggingPolicyBoolean $link.enforced "Configuration.links.$policyId.enforced"
            if ($link.Contains('order')) {
                Assert-LoggingPolicyInteger $link.order "Configuration.links.$policyId.order" 1 ([int32]::MaxValue)
            }
        }
    }

    Assert-LoggingPolicyList $Configuration.audit_subcategories 'Configuration.audit_subcategories'
    $supportedAuditGuids = @{}
    foreach ($prefix in @(
        '0cce9242', '0cce9240', '0cce9236', '0cce9237', '0cce9235',
        '0cce923e', '0cce923b', '0cce923c', '0cce923d', '0cce9215',
        '0cce921c', '0cce921b', '0cce9221', '0cce9244', '0cce9227'
    )) {
        $supportedAuditGuids["$prefix-69ae-11d9-bed3-505054503030"] = $true
    }
    $seenAuditGuids = @{}
    foreach ($audit in $Configuration.audit_subcategories) {
        Assert-LoggingPolicyCondition ($audit -is [System.Collections.IDictionary]) 'Each audit_subcategories item must be a mapping'
        Assert-LoggingPolicyExactKeys $audit @('guid', 'success', 'failure') 'audit_subcategories item'
        $auditGuid = Get-LoggingPolicyGuidString $audit.guid 'audit_subcategories.guid'
        Assert-LoggingPolicyCondition ($supportedAuditGuids.ContainsKey($auditGuid)) "Unsupported audit subcategory GUID: $auditGuid"
        Assert-LoggingPolicyCondition (-not $seenAuditGuids.ContainsKey($auditGuid)) "Duplicate audit subcategory GUID: $auditGuid"
        Assert-LoggingPolicyBoolean $audit.success 'audit_subcategories.success'
        Assert-LoggingPolicyBoolean $audit.failure 'audit_subcategories.failure'
        $seenAuditGuids[$auditGuid] = $true
    }

    Assert-LoggingPolicyCondition ($Configuration.powershell -is [System.Collections.IDictionary]) 'Configuration.powershell must be a mapping'
    $powerShellKeys = @(
        'module_logging_enabled', 'module_names', 'script_block_logging_enabled',
        'script_block_invocation_logging_enabled', 'transcription_enabled',
        'transcription_invocation_header', 'transcription_directory'
    )
    Assert-LoggingPolicyExactKeys $Configuration.powershell $powerShellKeys 'Configuration.powershell'
    foreach ($name in $powerShellKeys | Where-Object { $_ -ne 'module_names' -and $_ -ne 'transcription_directory' }) {
        Assert-LoggingPolicyBoolean $Configuration.powershell[$name] "Configuration.powershell.$name"
    }
    Assert-LoggingPolicyList $Configuration.powershell.module_names 'Configuration.powershell.module_names'
    Assert-LoggingPolicyCondition ($Configuration.powershell.module_names.Count -gt 0) 'Configuration.powershell.module_names must not be empty'
    $seenModules = @{}
    foreach ($moduleName in $Configuration.powershell.module_names) {
        Assert-LoggingPolicyString $moduleName 'Configuration.powershell.module_names item'
        $normalizedModule = ([string] $moduleName).ToLowerInvariant()
        Assert-LoggingPolicyCondition (-not $seenModules.ContainsKey($normalizedModule)) "Duplicate module name: $moduleName"
        $seenModules[$normalizedModule] = $true
    }
    $transcriptionDirectory = [string] $Configuration.powershell.transcription_directory
    Assert-LoggingPolicyString $transcriptionDirectory 'Configuration.powershell.transcription_directory'
    $validTranscriptionPath = $transcriptionDirectory -match '^[A-Za-z]:\\' -or $transcriptionDirectory -match '^\\\\[^\\]+\\[^\\]+'
    Assert-LoggingPolicyCondition $validTranscriptionPath 'transcription_directory must be an absolute local or UNC path'

    Assert-LoggingPolicyCondition ($Configuration.enrollment -is [System.Collections.IDictionary]) 'Configuration.enrollment must be a mapping'
    Assert-LoggingPolicyExactKeys $Configuration.enrollment @(
        'renew_update_revoke', 'update_templates', 'offline_expiration_percent', 'offline_expiration_store'
    ) 'Configuration.enrollment'
    Assert-LoggingPolicyBoolean $Configuration.enrollment.renew_update_revoke 'Configuration.enrollment.renew_update_revoke'
    Assert-LoggingPolicyBoolean $Configuration.enrollment.update_templates 'Configuration.enrollment.update_templates'
    Assert-LoggingPolicyInteger $Configuration.enrollment.offline_expiration_percent 'Configuration.enrollment.offline_expiration_percent' 1 100
    Assert-LoggingPolicyString $Configuration.enrollment.offline_expiration_store 'Configuration.enrollment.offline_expiration_store'
    Assert-LoggingPolicyCondition (
        [string]::Equals([string] $Configuration.enrollment.offline_expiration_store, 'MY', [System.StringComparison]::OrdinalIgnoreCase)
    ) 'Only the verified MY enrollment store is supported in v1'
    if ($Configuration.enrollment_enabled) {
        Assert-LoggingPolicyCondition (
            $Configuration.enrollment.renew_update_revoke -and $Configuration.enrollment.update_templates
        ) 'Enabled enrollment supports only the verified v1 all-options bundle'
    }

    Assert-LoggingPolicyCondition ($Configuration.defender -is [System.Collections.IDictionary]) 'Configuration.defender must be a mapping'
    Assert-LoggingPolicyExactKeys $Configuration.defender @('disable_antispyware', 'disable_realtime_monitoring') 'Configuration.defender'
    Assert-LoggingPolicyBoolean $Configuration.defender.disable_antispyware 'Configuration.defender.disable_antispyware'
    Assert-LoggingPolicyBoolean $Configuration.defender.disable_realtime_monitoring 'Configuration.defender.disable_realtime_monitoring'
}

function Get-LoggingPolicyStateDirectory {
    param([string] $Path)
    Assert-LoggingPolicyCondition ($Path -match '^[A-Za-z]:\\') 'state_dir must be an absolute local drive path'
    Assert-LoggingPolicyCondition ($Path -notmatch '(^|\\)\.\.?($|\\)') 'state_dir must not contain relative path segments'
    Assert-LoggingPolicyCondition ($Path.Substring(2) -notmatch ':') 'state_dir must not contain an alternate data stream'
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
    Assert-LoggingPolicyCondition (-not [string]::Equals($fullPath, $root, [System.StringComparison]::OrdinalIgnoreCase)) 'state_dir must not be a drive root'
    return $fullPath
}

function Assert-LoggingPolicyNoReparsePath {
    param([string] $Path)
    $current = [System.IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([System.IO.File]::Exists($current) -or [System.IO.Directory]::Exists($current)) {
            $attributes = [System.IO.File]::GetAttributes($current)
            Assert-LoggingPolicyCondition (
                ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
            ) "Reparse points are not allowed in the owned state path: $current"
        }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) {
            break
        }
        $current = $parent.FullName
    }
}

function Get-LoggingPolicyAllowedSids {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $result = @{}
        foreach ($sid in @($identity.User.Value, 'S-1-5-18', 'S-1-5-32-544')) {
            $result[$sid] = $true
        }
        return $result
    }
    finally {
        $identity.Dispose()
    }
}

function New-LoggingPolicyAcl {
    param([bool] $Directory)
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($Directory) {
            $security = New-Object System.Security.AccessControl.DirectorySecurity
        }
        else {
            $security = New-Object System.Security.AccessControl.FileSecurity
        }
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner($identity.User)
        $allowed = Get-LoggingPolicyAllowedSids
        foreach ($sidValue in $allowed.Keys) {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($sidValue)
            if ($Directory) {
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
            }
            else {
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
            }
            $null = $security.AddAccessRule($rule)
        }
        return $security
    }
    finally {
        $identity.Dispose()
    }
}

function Assert-LoggingPolicyProtectedAcl {
    param([string] $Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    Assert-LoggingPolicyCondition $acl.AreAccessRulesProtected "State ACL inheritance is enabled: $Path"
    $allowed = Get-LoggingPolicyAllowedSids
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    Assert-LoggingPolicyCondition ($allowed.ContainsKey($owner)) "State owner is not an approved identity: $Path"
    $fullControl = [int64] [System.Security.AccessControl.FileSystemRights]::FullControl
    $found = @{}
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        Assert-LoggingPolicyCondition (-not $rule.IsInherited) "Inherited state ACL rule found: $Path"
        Assert-LoggingPolicyCondition ($allowed.ContainsKey($sid)) "Unapproved state ACL identity $sid on $Path"
        Assert-LoggingPolicyCondition (
            $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
        ) "Deny ACL entries are not accepted on protected state: $Path"
        $rights = [int64] $rule.FileSystemRights
        Assert-LoggingPolicyCondition (($rights -band $fullControl) -eq $fullControl) "Approved identity lacks FullControl on $Path"
        $found[$sid] = $true
    }
    foreach ($sid in $allowed.Keys) {
        Assert-LoggingPolicyCondition ($found.ContainsKey($sid)) "Required ACL identity $sid is absent from $Path"
    }
}

function ConvertTo-LoggingPolicyDictionary {
    param([object] $Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $map = @{}
        foreach ($key in $Value.Keys) {
            $map[[string] $key] = ConvertTo-LoggingPolicyDictionary $Value[$key]
        }
        return $map
    }
    if ($Value -is [pscustomobject]) {
        $map = @{}
        foreach ($property in $Value.PSObject.Properties) {
            $map[$property.Name] = ConvertTo-LoggingPolicyDictionary $property.Value
        }
        return $map
    }
    if ($Value -is [System.Collections.IList] -and $Value -isnot [string]) {
        $items = New-Object System.Collections.ArrayList
        foreach ($item in $Value) {
            $null = $items.Add((ConvertTo-LoggingPolicyDictionary $item))
        }
        return ,$items.ToArray()
    }
    return $Value
}

function Get-LoggingPolicyRegistryIdentity {
    param([System.Collections.IDictionary] $Identifier)
    return (([string] $Identifier.key).ToLowerInvariant() + "`n" + ([string] $Identifier.value_name).ToLowerInvariant())
}

function Assert-LoggingPolicyRegistryIdentifiers {
    param(
        [string] $PolicyId,
        [object] $Identifiers,
        [string] $Label
    )
    Assert-LoggingPolicyList $Identifiers $Label
    $allowed = @{
        logging = @{
            "hklm\system\currentcontrolset\control\lsa`nscenoapplylegacyauditpolicy" = 'DWord'
            "hklm\software\policies\microsoft\windows\powershell\modulelogging`nenablemodulelogging" = 'DWord'
            "hklm\software\policies\microsoft\windows\powershell\scriptblocklogging`nenablescriptblocklogging" = 'DWord'
            "hklm\software\policies\microsoft\windows\powershell\scriptblocklogging`nenablescriptblockinvocationlogging" = 'DWord'
            "hklm\software\policies\microsoft\windows\powershell\transcription`nenabletranscripting" = 'DWord'
            "hklm\software\policies\microsoft\windows\powershell\transcription`nenableinvocationheader" = 'DWord'
            "hklm\software\policies\microsoft\windows\powershell\transcription`noutputdirectory" = 'String'
        }
        enrollment = @{
            "hklm\software\policies\microsoft\cryptography\autoenrollment`naepolicy" = 'DWord'
            "hklm\software\policies\microsoft\cryptography\autoenrollment`nofflineexpirationpercent" = 'DWord'
            "hklm\software\policies\microsoft\cryptography\autoenrollment`nofflineexpirationstorenames" = 'String'
        }
        defender = @{
            "hklm\software\policies\microsoft\windows defender`ndisableantispyware" = 'DWord'
            "hklm\software\policies\microsoft\windows defender\real-time protection`ndisablerealtimemonitoring" = 'DWord'
        }
    }
    $moduleNamesKey = 'hklm\software\policies\microsoft\windows\powershell\modulelogging\modulenames'
    $seen = @{}
    foreach ($identifier in $Identifiers) {
        Assert-LoggingPolicyCondition ($identifier -is [System.Collections.IDictionary]) "$Label item must be a mapping"
        Assert-LoggingPolicyExactKeys $identifier @('key', 'value_name', 'type') "$Label item"
        foreach ($key in @('key', 'value_name', 'type')) {
            Assert-LoggingPolicyString $identifier[$key] "$Label $key"
        }
        $identity = Get-LoggingPolicyRegistryIdentity $identifier
        Assert-LoggingPolicyCondition (-not $seen.ContainsKey($identity)) "$Label contains a duplicate registry identifier"
        $normalizedKey = ([string] $identifier.key).ToLowerInvariant()
        if ($PolicyId -eq 'logging' -and $normalizedKey -eq $moduleNamesKey) {
            Assert-LoggingPolicyCondition ([string] $identifier.type -ceq 'String') "$Label module-name identifier must use String"
        }
        else {
            Assert-LoggingPolicyCondition ($allowed[$PolicyId].ContainsKey($identity)) "$Label contains a registry identifier not owned by policy '$PolicyId'"
            Assert-LoggingPolicyCondition ([string] $identifier.type -ceq [string] $allowed[$PolicyId][$identity]) "$Label registry identifier has the wrong type"
        }
        $seen[$identity] = $true
    }
}

function Assert-LoggingPolicyAuditIdentifiers {
    param(
        [string] $PolicyId,
        [object] $Identifiers,
        [string] $Label
    )
    Assert-LoggingPolicyList $Identifiers $Label
    $allowed = @{}
    foreach ($prefix in @(
        '0cce9242', '0cce9240', '0cce9236', '0cce9237', '0cce9235',
        '0cce923e', '0cce923b', '0cce923c', '0cce923d', '0cce9215',
        '0cce921c', '0cce921b', '0cce9221', '0cce9244', '0cce9227'
    )) {
        $allowed["$prefix-69ae-11d9-bed3-505054503030"] = $true
    }
    $seen = @{}
    foreach ($value in $Identifiers) {
        $guid = Get-LoggingPolicyGuidString $value "$Label GUID"
        Assert-LoggingPolicyCondition ($PolicyId -eq 'logging' -and $allowed.ContainsKey($guid)) "$Label contains an audit GUID not owned by policy '$PolicyId'"
        Assert-LoggingPolicyCondition (-not $seen.ContainsKey($guid)) "$Label contains a duplicate audit GUID"
        $seen[$guid] = $true
    }
}

function Assert-LoggingPolicyLinkIdentifiers {
    param([object] $Identifiers, [string] $Label)
    Assert-LoggingPolicyList $Identifiers $Label
    $seen = @{}
    foreach ($value in $Identifiers) {
        Assert-LoggingPolicyString $value "$Label target"
        $normalized = ([string] $value).ToLowerInvariant()
        Assert-LoggingPolicyCondition (-not $seen.ContainsKey($normalized)) "$Label contains a duplicate link target"
        $seen[$normalized] = $true
    }
}

function Test-LoggingPolicyRegistryContains {
    param([object] $Identifiers, [System.Collections.IDictionary] $Target)
    $targetIdentity = Get-LoggingPolicyRegistryIdentity $Target
    foreach ($identifier in $Identifiers) {
        if ((Get-LoggingPolicyRegistryIdentity $identifier) -eq $targetIdentity) {
            return $true
        }
    }
    return $false
}

function Test-LoggingPolicyStringListContains {
    param([object] $Values, [string] $Target)
    foreach ($value in $Values) {
        if ([string]::Equals([string] $value, $Target, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Assert-LoggingPolicyPending {
    param(
        [System.Collections.IDictionary] $Pending,
        [string] $PolicyId
    )
    foreach ($key in @('operation', 'target', 'prior_ownership', 'intended_ownership')) {
        Assert-LoggingPolicyCondition ($Pending.Contains($key)) "Pending record for $PolicyId is missing '$key'"
    }
    $operations = @(
        'create', 'registry_add', 'registry_update', 'registry_remove',
        'audit_publish', 'audit_delete', 'link_add', 'link_update', 'link_disable'
    )
    Assert-LoggingPolicyCondition ($Pending.operation -is [string] -and $operations -contains $Pending.operation) "Pending operation for $PolicyId is unsupported"
    Assert-LoggingPolicyCondition ($Pending.target -is [System.Collections.IDictionary]) "Pending target for $PolicyId must be a mapping"
    Assert-LoggingPolicyCondition ($Pending.target.Contains('policy_id')) "Pending target for $PolicyId is missing 'policy_id'"
    Assert-LoggingPolicyCondition ([string] $Pending.target.policy_id -eq $PolicyId) "Pending target policy ID does not match $PolicyId"
    foreach ($key in @('prior_ownership', 'intended_ownership')) {
        Assert-LoggingPolicyCondition ($Pending[$key] -is [System.Collections.IDictionary]) "Pending $key for $PolicyId must be a mapping"
    }

    switch ([string] $Pending.operation) {
        'create' {
            Assert-LoggingPolicyExactKeys $Pending @('operation', 'target', 'prior_ownership', 'intended_ownership') "Pending create for $PolicyId"
            Assert-LoggingPolicyExactKeys $Pending.target @('policy_id', 'target_name', 'gpo_guid') "Pending create target for $PolicyId"
            Assert-LoggingPolicyString $Pending.target.target_name "Pending create target name for $PolicyId"
            Assert-LoggingPolicyExactKeys $Pending.prior_ownership @('gpo_guid') "Pending create prior ownership for $PolicyId"
            Assert-LoggingPolicyExactKeys $Pending.intended_ownership @('gpo_guid') "Pending create intended ownership for $PolicyId"
            Assert-LoggingPolicyCondition ($null -eq $Pending.prior_ownership.gpo_guid) "Pending create prior GPO GUID for $PolicyId must be null"
            if ($null -ne $Pending.target.gpo_guid) {
                $targetGuid = Get-LoggingPolicyGuidString $Pending.target.gpo_guid "Pending create target GPO GUID for $PolicyId"
                $intendedGuid = Get-LoggingPolicyGuidString $Pending.intended_ownership.gpo_guid "Pending create intended GPO GUID for $PolicyId"
                Assert-LoggingPolicyCondition ($targetGuid -eq $intendedGuid) "Pending create target and intended GPO GUID differ for $PolicyId"
            }
            else {
                Assert-LoggingPolicyCondition ($null -eq $Pending.intended_ownership.gpo_guid) "Pending create intended GPO GUID for $PolicyId must be null before creation"
            }
        }
        { $_ -in @('registry_add', 'registry_update', 'registry_remove') } {
            Assert-LoggingPolicyExactKeys $Pending @('operation', 'target', 'prior_ownership', 'intended_ownership') "Pending registry operation for $PolicyId"
            Assert-LoggingPolicyExactKeys $Pending.target @('policy_id', 'target_name', 'gpo_guid', 'registry_identifier') "Pending registry target for $PolicyId"
            Assert-LoggingPolicyString $Pending.target.target_name "Pending registry target name for $PolicyId"
            $null = Get-LoggingPolicyGuidString $Pending.target.gpo_guid "Pending registry target GPO GUID for $PolicyId"
            Assert-LoggingPolicyRegistryIdentifiers $PolicyId @($Pending.target.registry_identifier) "Pending registry target for $PolicyId"
            foreach ($key in @('prior_ownership', 'intended_ownership')) {
                Assert-LoggingPolicyExactKeys $Pending[$key] @('registry') "Pending registry $key for $PolicyId"
                Assert-LoggingPolicyRegistryIdentifiers $PolicyId $Pending[$key].registry "Pending registry $key for $PolicyId"
            }
            $inPrior = Test-LoggingPolicyRegistryContains $Pending.prior_ownership.registry $Pending.target.registry_identifier
            $inIntended = Test-LoggingPolicyRegistryContains $Pending.intended_ownership.registry $Pending.target.registry_identifier
            $targetIdentity = Get-LoggingPolicyRegistryIdentity $Pending.target.registry_identifier
            foreach ($identifier in $Pending.prior_ownership.registry) {
                if ((Get-LoggingPolicyRegistryIdentity $identifier) -ne $targetIdentity) {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyRegistryContains $Pending.intended_ownership.registry $identifier) "Pending registry operation changes unrelated prior ownership for $PolicyId"
                }
            }
            foreach ($identifier in $Pending.intended_ownership.registry) {
                if ((Get-LoggingPolicyRegistryIdentity $identifier) -ne $targetIdentity) {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyRegistryContains $Pending.prior_ownership.registry $identifier) "Pending registry operation adds unrelated intended ownership for $PolicyId"
                }
            }
            if ($Pending.operation -eq 'registry_add') {
                Assert-LoggingPolicyCondition (-not $inPrior -and $inIntended) "Pending registry_add ownership transition is invalid for $PolicyId"
            }
            elseif ($Pending.operation -eq 'registry_update') {
                Assert-LoggingPolicyCondition ($inPrior -and $inIntended) "Pending registry_update ownership transition is invalid for $PolicyId"
            }
            else {
                Assert-LoggingPolicyCondition ($inPrior -and -not $inIntended) "Pending registry_remove ownership transition is invalid for $PolicyId"
            }
        }
        { $_ -in @('audit_publish', 'audit_delete') } {
            Assert-LoggingPolicyExactKeys $Pending @('operation', 'target', 'prior_ownership', 'intended_ownership', 'audit') "Pending audit operation for $PolicyId"
            Assert-LoggingPolicyExactKeys $Pending.target @('policy_id', 'target_name', 'gpo_guid', 'audit_guids') "Pending audit target for $PolicyId"
            Assert-LoggingPolicyString $Pending.target.target_name "Pending audit target name for $PolicyId"
            $null = Get-LoggingPolicyGuidString $Pending.target.gpo_guid "Pending audit target GPO GUID for $PolicyId"
            Assert-LoggingPolicyAuditIdentifiers $PolicyId $Pending.target.audit_guids "Pending audit target for $PolicyId"
            Assert-LoggingPolicyCondition ($Pending.target.audit_guids.Count -gt 0) "Pending audit target for $PolicyId must not be empty"
            foreach ($key in @('prior_ownership', 'intended_ownership')) {
                Assert-LoggingPolicyExactKeys $Pending[$key] @('audit_guids') "Pending audit $key for $PolicyId"
                Assert-LoggingPolicyAuditIdentifiers $PolicyId $Pending[$key].audit_guids "Pending audit $key for $PolicyId"
            }
            foreach ($guid in $Pending.target.audit_guids) {
                if ($Pending.operation -eq 'audit_publish') {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyStringListContains $Pending.intended_ownership.audit_guids $guid) "Pending audit_publish target is absent from intended ownership for $PolicyId"
                }
                else {
                    Assert-LoggingPolicyCondition (
                        (Test-LoggingPolicyStringListContains $Pending.prior_ownership.audit_guids $guid) -and
                        -not (Test-LoggingPolicyStringListContains $Pending.intended_ownership.audit_guids $guid)
                    ) "Pending audit_delete ownership transition is invalid for $PolicyId"
                }
            }
            foreach ($guid in $Pending.prior_ownership.audit_guids) {
                if (-not (Test-LoggingPolicyStringListContains $Pending.intended_ownership.audit_guids $guid)) {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyStringListContains $Pending.target.audit_guids $guid) "Pending audit operation removes unrelated ownership for $PolicyId"
                }
            }
            foreach ($guid in $Pending.intended_ownership.audit_guids) {
                if (-not (Test-LoggingPolicyStringListContains $Pending.prior_ownership.audit_guids $guid)) {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyStringListContains $Pending.target.audit_guids $guid) "Pending audit operation adds unrelated ownership for $PolicyId"
                }
            }
            Assert-LoggingPolicyCondition ($Pending.audit -is [System.Collections.IDictionary]) "Pending audit for $PolicyId must be a mapping"
        }
        { $_ -in @('link_add', 'link_update', 'link_disable') } {
            Assert-LoggingPolicyExactKeys $Pending @('operation', 'target', 'prior_ownership', 'intended_ownership') "Pending link operation for $PolicyId"
            Assert-LoggingPolicyExactKeys $Pending.target @('policy_id', 'target_name', 'gpo_guid', 'link_target') "Pending link target for $PolicyId"
            Assert-LoggingPolicyString $Pending.target.target_name "Pending link target name for $PolicyId"
            $null = Get-LoggingPolicyGuidString $Pending.target.gpo_guid "Pending link target GPO GUID for $PolicyId"
            Assert-LoggingPolicyString $Pending.target.link_target "Pending link target for $PolicyId"
            foreach ($key in @('prior_ownership', 'intended_ownership')) {
                Assert-LoggingPolicyExactKeys $Pending[$key] @('link_targets') "Pending link $key for $PolicyId"
                Assert-LoggingPolicyLinkIdentifiers $Pending[$key].link_targets "Pending link $key for $PolicyId"
            }
            $inPrior = Test-LoggingPolicyStringListContains $Pending.prior_ownership.link_targets $Pending.target.link_target
            $inIntended = Test-LoggingPolicyStringListContains $Pending.intended_ownership.link_targets $Pending.target.link_target
            foreach ($target in $Pending.prior_ownership.link_targets) {
                if (-not [string]::Equals([string] $target, [string] $Pending.target.link_target, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyStringListContains $Pending.intended_ownership.link_targets $target) "Pending link operation changes unrelated prior ownership for $PolicyId"
                }
            }
            foreach ($target in $Pending.intended_ownership.link_targets) {
                if (-not [string]::Equals([string] $target, [string] $Pending.target.link_target, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Assert-LoggingPolicyCondition (Test-LoggingPolicyStringListContains $Pending.prior_ownership.link_targets $target) "Pending link operation adds unrelated intended ownership for $PolicyId"
                }
            }
            if ($Pending.operation -eq 'link_add') {
                Assert-LoggingPolicyCondition (-not $inPrior -and $inIntended) "Pending link_add ownership transition is invalid for $PolicyId"
            }
            else {
                Assert-LoggingPolicyCondition ($inPrior -and $inIntended) "Pending link update/disable ownership transition is invalid for $PolicyId"
            }
        }
    }

    if ($Pending.Contains('audit')) {
        Assert-LoggingPolicyCondition ($Pending.audit -is [System.Collections.IDictionary]) "Pending audit for $PolicyId must be a mapping"
        Assert-LoggingPolicyExactKeys $Pending.audit @(
            'dc', 'prior_ad_version', 'intended_ad_version', 'prior_gpt_version',
            'intended_gpt_version', 'prior_machine_extensions', 'intended_machine_extensions',
            'prior_hash', 'prior_backup_path', 'desired_hash', 'desired_deletion'
        ) "Pending audit for $PolicyId"
        Assert-LoggingPolicyString $Pending.audit.dc "Pending audit DC for $PolicyId"
        foreach ($key in @('prior_ad_version', 'intended_ad_version', 'prior_gpt_version', 'intended_gpt_version')) {
            Assert-LoggingPolicyInteger $Pending.audit[$key] "Pending audit $key for $PolicyId" 0 ([uint32]::MaxValue)
        }
        foreach ($key in @('prior_machine_extensions', 'intended_machine_extensions')) {
            Assert-LoggingPolicyString $Pending.audit[$key] "Pending audit $key for $PolicyId" $true
        }
        foreach ($key in @('prior_hash', 'prior_backup_path', 'desired_hash')) {
            if ($null -ne $Pending.audit[$key]) {
                Assert-LoggingPolicyString $Pending.audit[$key] "Pending audit $key for $PolicyId"
            }
        }
        foreach ($key in @('prior_hash', 'desired_hash')) {
            if ($null -ne $Pending.audit[$key]) {
                Assert-LoggingPolicyCondition ([string] $Pending.audit[$key] -match '^[0-9A-Fa-f]{64}$') "Pending audit $key for $PolicyId must be a SHA-256 digest"
            }
        }
        Assert-LoggingPolicyBoolean $Pending.audit.desired_deletion "Pending audit desired_deletion for $PolicyId"
        $deletionMatchesHash = ($Pending.audit.desired_deletion -and $null -eq $Pending.audit.desired_hash) -or
            (-not $Pending.audit.desired_deletion -and $null -ne $Pending.audit.desired_hash)
        Assert-LoggingPolicyCondition $deletionMatchesHash "Pending audit desired_deletion must be true exactly when desired_hash is null for $PolicyId"
        if ($Pending.operation -eq 'audit_publish') {
            Assert-LoggingPolicyCondition (-not $Pending.audit.desired_deletion) "Pending audit_publish cannot request CSV deletion for $PolicyId"
        }
    }
}

function Assert-LoggingPolicyState {
    param(
        [System.Collections.IDictionary] $State,
        [bool] $AllowPending
    )
    Assert-LoggingPolicyExactKeys $State @('schema_version', 'owner_id', 'domain_guid', 'writer_host', 'policies') 'State'
    Assert-LoggingPolicyInteger $State.schema_version 'State.schema_version' 1 1
    foreach ($key in @('owner_id', 'domain_guid', 'writer_host')) {
        Assert-LoggingPolicyString $State[$key] "State.$key"
    }
    $null = Get-LoggingPolicyGuidString $State.domain_guid 'State.domain_guid'
    Assert-LoggingPolicyCondition ($State.policies -is [System.Collections.IDictionary]) 'State.policies must be a mapping'
    foreach ($policyIdValue in $State.policies.Keys) {
        $policyId = [string] $policyIdValue
        Assert-LoggingPolicyCondition (@('logging', 'enrollment', 'defender') -contains $policyId) "Unsupported state policy ID: $policyId"
        $record = $State.policies[$policyIdValue]
        Assert-LoggingPolicyCondition ($record -is [System.Collections.IDictionary]) "State policy $policyId must be a mapping"
        Assert-LoggingPolicyExactKeys $record @('gpo_guid', 'registry', 'audit_guids', 'link_targets', 'pending') "State policy $policyId"
        Assert-LoggingPolicyRegistryIdentifiers $policyId $record.registry "State policy $policyId registry"
        Assert-LoggingPolicyAuditIdentifiers $policyId $record.audit_guids "State policy $policyId audit_guids"
        Assert-LoggingPolicyLinkIdentifiers $record.link_targets "State policy $policyId link_targets"
        if ($null -ne $record.pending) {
            Assert-LoggingPolicyCondition ($record.pending -is [System.Collections.IDictionary]) "State policy $policyId pending must be a mapping or null"
            Assert-LoggingPolicyPending $record.pending $policyId
            if ($record.pending.operation -eq 'create') {
                Assert-LoggingPolicyCondition ($null -eq $record.gpo_guid) "State policy $policyId must keep committed GPO GUID null while create is pending"
            }
            else {
                $committedGuid = Get-LoggingPolicyGuidString $record.gpo_guid "State policy $policyId GPO GUID"
                $pendingGuid = Get-LoggingPolicyGuidString $record.pending.target.gpo_guid "Pending target GPO GUID for $policyId"
                Assert-LoggingPolicyCondition ($committedGuid -eq $pendingGuid) "Pending target GPO GUID does not match committed state for $policyId"
            }
            Assert-LoggingPolicyCondition $AllowPending "State policy $policyId has unresolved pending work"
        }
        if ($null -eq $record.gpo_guid) {
            Assert-LoggingPolicyCondition ($null -ne $record.pending -and $record.pending.operation -eq 'create') "State policy $policyId has no committed GPO GUID"
        }
        else {
            $null = Get-LoggingPolicyGuidString $record.gpo_guid "State policy $policyId GPO GUID"
        }
    }
}

function Read-LoggingPolicyState {
    param([string] $StatePath)
    $directory = [System.IO.Path]::GetDirectoryName($StatePath)
    Assert-LoggingPolicyNoReparsePath $directory
    if (-not [System.IO.Directory]::Exists($directory)) {
        return $null
    }
    Assert-LoggingPolicyProtectedAcl $directory
    if (-not [System.IO.File]::Exists($StatePath)) {
        return $null
    }
    Assert-LoggingPolicyNoReparsePath $StatePath
    Assert-LoggingPolicyProtectedAcl $StatePath
    try {
        $json = [System.IO.File]::ReadAllText($StatePath, [System.Text.UTF8Encoding]::new($false, $true))
        Assert-LoggingPolicyCondition (-not [string]::IsNullOrWhiteSpace($json)) 'State file is empty'
        $object = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        $state = ConvertTo-LoggingPolicyDictionary $object
        Assert-LoggingPolicyCondition ($state -is [System.Collections.IDictionary]) 'State JSON root must be a mapping'
        Assert-LoggingPolicyState $state $true
        return $state
    }
    catch {
        throw "Unable to load protected logging-policy state: $($_.Exception.Message)"
    }
}

function Get-LoggingPolicyMarker {
    param([string] $OwnerId, [string] $PolicyId)
    return "[LudusWindowsLoggingPolicy owner=$OwnerId;policy=$PolicyId]"
}

function Assert-LoggingPolicyLinkTargetInDomain {
    param(
        [string] $Target,
        [string] $DomainDn,
        [string] $Server,
        [bool] $AllowDomainRootAlias
    )
    if ($AllowDomainRootAlias -and [string]::Equals($Target, 'domain_root', [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    $insideDomain = [string]::Equals($Target, $DomainDn, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Target.EndsWith(",$DomainDn", [System.StringComparison]::OrdinalIgnoreCase)
    Assert-LoggingPolicyCondition $insideDomain "Link target is outside the selected domain: $Target"
    try {
        $targetObject = Get-ADObject -Identity $Target -Server $Server -Properties objectClass -ErrorAction Stop
    }
    catch {
        throw "Unable to resolve link target '$Target' on selected DC '$Server': $($_.Exception.Message)"
    }
    $classes = @($targetObject.ObjectClass)
    $leafClass = [string] $classes[$classes.Count - 1]
    Assert-LoggingPolicyCondition (
        $leafClass -eq 'organizationalUnit' -or $leafClass -eq 'domainDNS'
    ) "Link target must be the domain root or an organizational unit: $Target"
}

function Assert-LoggingPolicyLinksInDomain {
    param(
        [System.Collections.IDictionary] $Links,
        [string] $DomainDn,
        [string] $Server
    )
    foreach ($policyId in @('logging', 'enrollment', 'defender')) {
        foreach ($link in $Links[$policyId]) {
            Assert-LoggingPolicyLinkTargetInDomain ([string] $link.target) $DomainDn $Server $true
        }
    }
}

function Assert-LoggingPolicyStoredLinksInDomain {
    param(
        [System.Collections.IDictionary] $State,
        [string] $DomainDn,
        [string] $Server
    )
    if ($null -eq $State) {
        return
    }
    foreach ($policyId in $State.policies.Keys) {
        foreach ($target in $State.policies[$policyId].link_targets) {
            Assert-LoggingPolicyLinkTargetInDomain ([string] $target) $DomainDn $Server $false
        }
        $pending = $State.policies[$policyId].pending
        if ($null -ne $pending -and $pending.operation -like 'link_*') {
            Assert-LoggingPolicyLinkTargetInDomain ([string] $pending.target.link_target) $DomainDn $Server $false
            foreach ($snapshotName in @('prior_ownership', 'intended_ownership')) {
                foreach ($target in $pending[$snapshotName].link_targets) {
                    Assert-LoggingPolicyLinkTargetInDomain ([string] $target) $DomainDn $Server $false
                }
            }
        }
    }
}

function Assert-LoggingPolicyOwnershipView {
    param(
        [object[]] $Gpos,
        [System.Collections.IDictionary] $State,
        [hashtable] $Configuration
    )
    foreach ($policyId in @('logging', 'enrollment', 'defender')) {
        $name = [string] $Configuration.names[$policyId]
        $marker = Get-LoggingPolicyMarker $Configuration.owner_id $policyId
        $named = @($Gpos | Where-Object { [string]::Equals([string] $_.DisplayName, $name, [System.StringComparison]::OrdinalIgnoreCase) })
        $marked = @($Gpos | Where-Object { [string]::Equals([string] $_.Description, $marker, [System.StringComparison]::Ordinal) })
        Assert-LoggingPolicyCondition ($named.Count -le 1) "Policy name is ambiguous: $name"
        Assert-LoggingPolicyCondition ($marked.Count -le 1) "Ownership marker is ambiguous for policy: $policyId"

        $record = $null
        if ($null -ne $State -and $State.policies.Contains($policyId)) {
            $record = $State.policies[$policyId]
        }
        $enabledKey = if ($policyId -eq 'defender') { 'defender_disable_policy_enabled' } else { "${policyId}_enabled" }
        $enabled = [bool] $Configuration[$enabledKey]

        if ($null -ne $record -or $marked.Count -gt 0) {
            Assert-LoggingPolicyCondition ($null -ne $State -and $null -ne $record) "Marked policy '$policyId' has no matching protected state record"
            Assert-LoggingPolicyCondition ($marked.Count -eq 1) "State policy '$policyId' has no matching marked GPO"
            Assert-LoggingPolicyCondition ($named.Count -eq 1 -and $named[0].Id -eq $marked[0].Id) "Marked policy '$policyId' was renamed or replaced"
            $recordGuid = Get-LoggingPolicyGuidString $record.gpo_guid "State policy $policyId GPO GUID"
            $actualGuid = ([guid] $marked[0].Id).ToString('D').ToLowerInvariant()
            Assert-LoggingPolicyCondition ($recordGuid -eq $actualGuid) "Marked policy '$policyId' GUID does not match protected state"
        }
        elseif ($enabled -and $named.Count -gt 0) {
            throw "Enabled policy name '$name' already exists without this role's ownership marker"
        }
    }
}

function Assert-LoggingPolicyContextShape {
    param([hashtable] $Context)
    foreach ($key in @('domain_dns', 'domain_dn', 'domain_guid', 'dc', 'sysvol_root', 'state_path', 'writer_host', 'owner_id', 'state')) {
        Assert-LoggingPolicyCondition ($Context.ContainsKey($key)) "Context is missing '$key'"
    }
    foreach ($key in @('domain_dns', 'domain_dn', 'domain_guid', 'dc', 'sysvol_root', 'state_path', 'writer_host', 'owner_id')) {
        Assert-LoggingPolicyString $Context[$key] "Context.$key"
    }
    $null = Get-LoggingPolicyGuidString $Context.domain_guid 'Context.domain_guid'
    if ($null -ne $Context.state) {
        Assert-LoggingPolicyCondition ($Context.state -is [System.Collections.IDictionary]) 'Context.state must be a mapping or null'
    }
}

function Get-LoggingPolicyContext {
    param([hashtable] $Configuration)

    Assert-LoggingPolicyConfiguration $Configuration
    $stateDirectory = Get-LoggingPolicyStateDirectory $Configuration.state_dir
    Assert-LoggingPolicyNoReparsePath $stateDirectory

    foreach ($moduleName in @('GroupPolicy', 'ActiveDirectory')) {
        $available = @(Get-Module -ListAvailable -Name $moduleName -ErrorAction Stop)
        Assert-LoggingPolicyCondition ($available.Count -gt 0) "Required PowerShell module is unavailable: $moduleName"
        $null = Import-Module -Name $moduleName -ErrorAction Stop -PassThru
    }

    try {
        $joinedDomain = Get-ADDomain -Current LocalComputer -ErrorAction Stop
    }
    catch {
        throw "Unable to discover the joined domain in the current session: $($_.Exception.Message)"
    }
    $joinedGuid = ([guid] $joinedDomain.ObjectGUID).ToString('D').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace([string] $Configuration.domain)) {
        $requestedDomain = $joinedDomain
    }
    else {
        try {
            $requestedDomain = Get-ADDomain -Identity $Configuration.domain -Server $joinedDomain.PDCEmulator -ErrorAction Stop
        }
        catch {
            throw "Unable to resolve the explicit domain through the joined domain: $($_.Exception.Message)"
        }
        $requestedGuid = ([guid] $requestedDomain.ObjectGUID).ToString('D').ToLowerInvariant()
        Assert-LoggingPolicyCondition ($requestedGuid -eq $joinedGuid) 'The explicit domain does not match the joined-domain boundary'
    }

    $domainDns = ([string] $requestedDomain.DNSRoot).ToLowerInvariant()
    $domainDn = [string] $requestedDomain.DistinguishedName
    Assert-LoggingPolicyString $domainDns 'Discovered domain DNS name'
    Assert-LoggingPolicyString $domainDn 'Discovered domain distinguished name'
    $server = if ([string]::IsNullOrWhiteSpace([string] $Configuration.server)) {
        [string] $requestedDomain.PDCEmulator
    }
    else {
        [string] $Configuration.server
    }
    Assert-LoggingPolicyString $server 'Selected DC'

    try {
        $dcObject = Get-ADDomainController -Identity $server -Server $server -ErrorAction Stop
        $dc = ([string] $dcObject.HostName).ToLowerInvariant()
        Assert-LoggingPolicyString $dc 'Selected DC FQDN'
        Assert-LoggingPolicyCondition ($dc.Contains('.')) 'Selected DC must resolve to an FQDN'
        Assert-LoggingPolicyCondition (-not [bool] $dcObject.IsReadOnly) 'The selected DC is read-only'
        Assert-LoggingPolicyCondition (
            [string]::Equals([string] $dcObject.Domain, $domainDns, [System.StringComparison]::OrdinalIgnoreCase)
        ) 'The selected DC belongs to a different domain'
        $selectedDomain = Get-ADDomain -Identity $domainDns -Server $dc -ErrorAction Stop
        $selectedGuid = ([guid] $selectedDomain.ObjectGUID).ToString('D').ToLowerInvariant()
        Assert-LoggingPolicyCondition ($selectedGuid -eq $joinedGuid) 'The selected DC returned a different domain identity'
        $rootDse = Get-ADRootDSE -Server $dc -ErrorAction Stop
        Assert-LoggingPolicyCondition (
            [string]::Equals([string] $rootDse.DefaultNamingContext, $domainDn, [System.StringComparison]::OrdinalIgnoreCase)
        ) 'The selected DC default naming context does not match the target domain'
    }
    catch {
        throw "Selected writable-DC LDAP preflight failed for '$server': $($_.Exception.Message)"
    }

    $sysvolRoot = "\\$dc\SYSVOL\$domainDns"
    try {
        Assert-LoggingPolicyCondition ([System.IO.Directory]::Exists($sysvolRoot)) "Selected-DC SYSVOL path is unavailable: $sysvolRoot"
        $enumerator = [System.IO.Directory]::EnumerateFileSystemEntries($sysvolRoot).GetEnumerator()
        try {
            $null = $enumerator.MoveNext()
        }
        finally {
            if ($enumerator -is [System.IDisposable]) {
                $enumerator.Dispose()
            }
        }
    }
    catch {
        throw "Selected-DC SYSVOL preflight failed in the current session: $($_.Exception.Message)"
    }

    Assert-LoggingPolicyLinksInDomain $Configuration.links $domainDn $dc
    $statePath = [System.IO.Path]::Combine($stateDirectory, "state-$joinedGuid.json")
    $state = Read-LoggingPolicyState $statePath
    Assert-LoggingPolicyStoredLinksInDomain $state $domainDn $dc
    if ($null -ne $state) {
        Assert-LoggingPolicyCondition ([string] $state.owner_id -ceq [string] $Configuration.owner_id) 'Protected state owner does not match Configuration.owner_id'
        $stateDomainGuid = Get-LoggingPolicyGuidString $state.domain_guid 'State.domain_guid'
        Assert-LoggingPolicyCondition ($stateDomainGuid -eq $joinedGuid) 'Protected state belongs to a different domain'
        Assert-LoggingPolicyCondition (
            [string]::Equals([string] $state.writer_host, [string] $Configuration.management_host, [System.StringComparison]::OrdinalIgnoreCase)
        ) 'Protected state belongs to a different designated writer host'
        foreach ($policyId in $state.policies.Keys) {
            if ($null -ne $state.policies[$policyId].pending) {
                Assert-LoggingPolicyCondition (
                    [string]::Equals([string] $state.policies[$policyId].pending.target.target_name,
                        [string] $Configuration.names[$policyId], [System.StringComparison]::Ordinal)
                ) "Policy '$policyId' pending target name does not match configured identity"
                if ($state.policies[$policyId].pending.Contains('audit')) {
                    Assert-LoggingPolicyCondition (
                        [string]::Equals([string] $state.policies[$policyId].pending.audit.dc,
                            $dc, [System.StringComparison]::OrdinalIgnoreCase)
                    ) "Policy '$policyId' pending audit DC does not match the selected DC"
                }
            }
            Assert-LoggingPolicyCondition ($null -eq $state.policies[$policyId].pending) "Policy '$policyId' has unresolved pending state; explicit recovery is required"
        }
    }

    try {
        $gpos = @(Get-GPO -All -Domain $domainDns -Server $dc -ErrorAction Stop)
    }
    catch {
        throw "Unable to read GPO ownership through selected DC '$dc': $($_.Exception.Message)"
    }
    Assert-LoggingPolicyOwnershipView $gpos $state $Configuration

    [hashtable] $context = @{
        domain_dns = $domainDns
        domain_dn = $domainDn
        domain_guid = $joinedGuid
        dc = $dc
        sysvol_root = $sysvolRoot
        state_path = $statePath
        writer_host = [string] $Configuration.management_host
        owner_id = [string] $Configuration.owner_id
        state = $state
    }
    return $context
}

function Enter-LoggingPolicyWriter {
    param(
        [hashtable] $Context,
        [bool] $PlanOnly
    )
    Assert-LoggingPolicyContextShape $Context
    $domainGuid = Get-LoggingPolicyGuidString $Context.domain_guid 'Context.domain_guid'
    $mutexName = "Global\Ludus.WindowsLoggingPolicy.$domainGuid"
    $createdNew = $false
    $mutex = [System.Threading.Mutex]::new($false, $mutexName, [ref] $createdNew)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0, $false)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        $mode = if ($PlanOnly) { 'planning' } else { 'mutation' }
        Assert-LoggingPolicyCondition $acquired "Another per-domain writer holds the $mode lock"
        [System.IDisposable] $handle = [LudusLoggingPolicyWriterHandle]::new($mutex, $true)
        $mutex = $null
        return $handle
    }
    finally {
        if ($null -ne $mutex) {
            if ($acquired) {
                $mutex.ReleaseMutex()
            }
            $mutex.Dispose()
        }
    }
}

function Write-LoggingPolicyState {
    param(
        [hashtable] $Context,
        [hashtable] $State
    )
    Assert-LoggingPolicyContextShape $Context
    Assert-LoggingPolicyState $State $true
    $domainGuid = Get-LoggingPolicyGuidString $Context.domain_guid 'Context.domain_guid'
    $stateDomainGuid = Get-LoggingPolicyGuidString $State.domain_guid 'State.domain_guid'
    Assert-LoggingPolicyCondition ($stateDomainGuid -eq $domainGuid) 'State domain does not match Context'
    Assert-LoggingPolicyCondition ([string] $State.owner_id -ceq [string] $Context.owner_id) 'State owner does not match Context'
    Assert-LoggingPolicyCondition (
        [string]::Equals([string] $State.writer_host, [string] $Context.writer_host, [System.StringComparison]::OrdinalIgnoreCase)
    ) 'State writer does not match Context'
    Assert-LoggingPolicyStoredLinksInDomain $State $Context.domain_dn $Context.dc
    foreach ($policyId in $State.policies.Keys) {
        $pending = $State.policies[$policyId].pending
        if ($null -ne $pending -and $pending.Contains('audit')) {
            Assert-LoggingPolicyCondition (
                [string]::Equals([string] $pending.audit.dc, [string] $Context.dc,
                    [System.StringComparison]::OrdinalIgnoreCase)
            ) "Pending audit DC for $policyId does not match Context"
        }
    }

    $statePath = [System.IO.Path]::GetFullPath([string] $Context.state_path)
    $stateDirectory = [System.IO.Path]::GetDirectoryName($statePath)
    $expectedName = "state-$domainGuid.json"
    Assert-LoggingPolicyCondition (
        [string]::Equals([System.IO.Path]::GetFileName($statePath), $expectedName, [System.StringComparison]::OrdinalIgnoreCase)
    ) 'Context.state_path does not match the domain state filename'
    $null = Get-LoggingPolicyStateDirectory $stateDirectory
    Assert-LoggingPolicyNoReparsePath $stateDirectory

    $directoryAcl = New-LoggingPolicyAcl $true
    if (-not [System.IO.Directory]::Exists($stateDirectory)) {
        $null = [System.IO.Directory]::CreateDirectory($stateDirectory, $directoryAcl)
    }
    Set-Acl -LiteralPath $stateDirectory -AclObject $directoryAcl -ErrorAction Stop
    Assert-LoggingPolicyNoReparsePath $stateDirectory
    Assert-LoggingPolicyProtectedAcl $stateDirectory
    if ([System.IO.File]::Exists($statePath)) {
        Assert-LoggingPolicyNoReparsePath $statePath
        Assert-LoggingPolicyProtectedAcl $statePath
    }

    try {
        $json = ConvertTo-Json -InputObject $State -Depth 12 -Compress
    }
    catch {
        throw "Unable to serialize logging-policy state: $($_.Exception.Message)"
    }
    $serialized = $json + "`r`n"
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($serialized)
    $temporaryPath = [System.IO.Path]::Combine($stateDirectory, ('.state-' + [System.IO.Path]::GetRandomFileName()))
    $stream = $null
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        $fileAcl = New-LoggingPolicyAcl $false
        Set-Acl -LiteralPath $temporaryPath -AclObject $fileAcl -ErrorAction Stop
        Assert-LoggingPolicyNoReparsePath $temporaryPath
        Assert-LoggingPolicyProtectedAcl $temporaryPath
        if ([System.IO.File]::Exists($statePath)) {
            [System.IO.File]::Replace($temporaryPath, $statePath, $null, $true)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $statePath)
        }
        Assert-LoggingPolicyNoReparsePath $statePath
        Assert-LoggingPolicyProtectedAcl $statePath
        $readBack = [System.IO.File]::ReadAllText($statePath, $encoding)
        Assert-LoggingPolicyCondition ($readBack -ceq $serialized) 'State readback did not match the durable write'
    }
    catch {
        throw "Unable to persist protected logging-policy state: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}
