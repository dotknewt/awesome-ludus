Set-StrictMode -Version 2.0

function New-LoggingPolicyProgress {
    return @{
        changed = $false
        affected_policy = $null
        phase = 'preflight'
        state_path = $null
        current = $null
        completed = [System.Collections.ArrayList]::new()
        planned_changes = [System.Collections.ArrayList]::new()
        policies = [System.Collections.ArrayList]::new()
    }
}

function Set-LoggingPolicyProgressScope {
    param([hashtable] $Progress, [object] $PolicyId, [string] $Phase, [object] $StatePath)
    $Progress.affected_policy = $PolicyId
    $Progress.phase = $Phase
    if ($null -ne $StatePath) { $Progress.state_path = [string] $StatePath }
}

function Start-LoggingPolicyMutation {
    param([hashtable] $Progress, [object] $PolicyId, [string] $Phase, [string] $Target)
    Assert-LoggingPolicyCondition ($null -eq $Progress.current) 'Mutation progress already has an uncertain operation'
    Set-LoggingPolicyProgressScope $Progress $PolicyId $Phase $Progress.state_path
    $Progress.current = @{
        policy_id = $PolicyId
        phase = $Phase
        target = $Target
        outcome = 'uncertain'
    }
}

function Complete-LoggingPolicyMutation {
    param([hashtable] $Progress)
    Assert-LoggingPolicyCondition ($null -ne $Progress.current) 'Mutation progress has no operation to complete'
    $Progress.current.outcome = 'completed'
    $null = $Progress.completed.Add($Progress.current)
    $Progress.current = $null
    $Progress.changed = $true
}

function Write-LoggingPolicyTrackedState {
    param([hashtable] $Context, [object] $PolicyId, [string] $Phase)
    Start-LoggingPolicyMutation $Context.progress $PolicyId $Phase ([string] $Context.state_path)
    Write-LoggingPolicyState $Context $Context.state
    Complete-LoggingPolicyMutation $Context.progress
}

function Get-LoggingPolicyFailureResult {
    param([hashtable] $Progress, [object] $Failure)
    $uncertain = @()
    if ($null -ne $Progress.current) { $uncertain = @($Progress.current) }
    return @{
        changed = [bool] ($Progress.changed -or $uncertain.Count -gt 0)
        planned_changes = @($Progress.planned_changes)
        policies = @($Progress.policies)
        partial_failure = @{
            affected_policy = $Progress.affected_policy
            phase = [string] $Progress.phase
            state_path = $Progress.state_path
            completed = @($Progress.completed)
            uncertain = $uncertain
            message = [string] $Failure.Exception.Message
        }
    }
}

function New-LoggingPolicyStateDocument {
    param([hashtable] $Context)
    return @{
        schema_version = 1
        owner_id = [string] $Context.owner_id
        domain_guid = [string] $Context.domain_guid
        writer_host = [string] $Context.writer_host
        policies = @{}
    }
}

function New-LoggingPolicyRecord {
    return @{
        gpo_guid = $null
        registry = @()
        audit_guids = @()
        link_targets = @()
        pending = $null
    }
}

function Get-LoggingPolicyEnabled {
    param([string] $PolicyId, [hashtable] $Configuration)
    if ($PolicyId -eq 'defender') {
        return [bool] $Configuration.defender_disable_policy_enabled
    }
    return [bool] $Configuration["${PolicyId}_enabled"]
}

function Get-LoggingPolicyRecord {
    param([hashtable] $State, [string] $PolicyId)
    if ($null -ne $State -and $State.policies.Contains($PolicyId)) {
        return $State.policies[$PolicyId]
    }
    return $null
}

function Copy-LoggingPolicyRegistryIdentifiers {
    param([object] $Identifiers)
    $result = @()
    foreach ($identifier in @($Identifiers)) {
        $result += ,@{
            key = [string] $identifier.key
            value_name = [string] $identifier.value_name
            type = [string] $identifier.type
        }
    }
    return $result
}

function Test-LoggingPolicyRegistryIdentityEqual {
    param([System.Collections.IDictionary] $Left, [System.Collections.IDictionary] $Right)
    return [string]::Equals([string] $Left.key, [string] $Right.key, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string] $Left.value_name, [string] $Right.value_name, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-LoggingPolicyStringEqual {
    param([object] $Left, [object] $Right)
    return [string]::Equals([string] $Left, [string] $Right, [System.StringComparison]::OrdinalIgnoreCase)
}

function Add-LoggingPolicyPlan {
    param([System.Collections.ArrayList] $Plans, [string] $Action)
    $null = $Plans.Add($Action)
}

function Reconcile-LoggingPolicyObjects {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [hashtable] $Context,
        [hashtable] $Configuration,
        [bool] $PlanOnly,
        [System.Collections.ArrayList] $Plans
    )

    if ($null -eq $Context.state) {
        $Context.state = New-LoggingPolicyStateDocument $Context
    }
    foreach ($policyId in @('logging', 'enrollment', 'defender')) {
        Set-LoggingPolicyProgressScope $Context.progress $policyId 'gpo_reconciliation' $Context.state_path
        if (-not (Get-LoggingPolicyEnabled $policyId $Configuration)) {
            continue
        }
        if ($Context.state.policies.Contains($policyId)) {
            continue
        }

        $name = [string] $Configuration.names[$policyId]
        Add-LoggingPolicyPlan $Plans "create unlinked GPO '$name'"
        if ($PlanOnly -or -not $PSCmdlet.ShouldProcess($name, 'Create marked unlinked GPO')) {
            continue
        }

        $record = New-LoggingPolicyRecord
        $marker = Get-LoggingPolicyMarker $Configuration.owner_id $policyId
        $record.pending = @{
            operation = 'create'
            target = @{ policy_id = $policyId; target_name = $name; gpo_guid = $null }
            prior_ownership = @{ gpo_guid = $null }
            intended_ownership = @{ gpo_guid = $null }
        }
        $Context.state.policies[$policyId] = $record
        Write-LoggingPolicyTrackedState $Context $policyId 'persist_create_intent'

        Start-LoggingPolicyMutation $Context.progress $policyId 'create_gpo' $name
        $created = New-GPO -Name $name -Comment $marker -Domain $Context.domain_dns -Server $Context.dc -ErrorAction Stop
        $guid = ([guid] $created.Id).ToString('D').ToLowerInvariant()
        Complete-LoggingPolicyMutation $Context.progress
        $record.pending.target.gpo_guid = $guid
        $record.pending.intended_ownership.gpo_guid = $guid
        Write-LoggingPolicyTrackedState $Context $policyId 'persist_created_guid'

        Set-LoggingPolicyProgressScope $Context.progress $policyId 'verify_created_gpo' $Context.state_path
        $verified = Get-GPO -Guid $guid -Domain $Context.domain_dns -Server $Context.dc -ErrorAction Stop
        Assert-LoggingPolicyCondition ([string] $verified.Description -ceq $marker) "Created GPO marker readback failed for '$policyId'"
        Assert-LoggingPolicyCondition (
            [string]::Equals([string] $verified.DisplayName, $name, [System.StringComparison]::Ordinal)
        ) "Created GPO name readback failed for '$policyId'"

        $record.gpo_guid = $guid
        $record.pending = $null
        Write-LoggingPolicyTrackedState $Context $policyId 'commit_created_gpo'
    }
}

function New-LoggingRegistrySetting {
    param([string] $Key, [string] $ValueName, [string] $Type, [object] $Value, [bool] $Additive = $false)
    return @{
        identifier = @{ key = $Key; value_name = $ValueName; type = $Type }
        value = $Value
        additive = $Additive
    }
}

function Get-LoggingPolicyDesiredRegistry {
    param([string] $PolicyId, [hashtable] $Configuration)
    $settings = @()
    if (-not (Get-LoggingPolicyEnabled $PolicyId $Configuration)) {
        return $settings
    }

    if ($PolicyId -eq 'logging') {
        $settings += ,(New-LoggingRegistrySetting 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 'DWord' 1)
        if ($Configuration.powershell.module_logging_enabled) {
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 'DWord' 1)
            foreach ($moduleName in $Configuration.powershell.module_names) {
                $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' ([string] $moduleName) 'String' ([string] $moduleName) $true)
            }
        }
        if ($Configuration.powershell.script_block_logging_enabled) {
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 'DWord' 1)
        }
        if ($Configuration.powershell.script_block_invocation_logging_enabled) {
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockInvocationLogging' 'DWord' 1)
        }
        if ($Configuration.powershell.transcription_enabled) {
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 'DWord' 1)
            if ($Configuration.powershell.transcription_invocation_header) {
                $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableInvocationHeader' 'DWord' 1)
            }
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' 'String' ([string] $Configuration.powershell.transcription_directory))
        }
    }
    elseif ($PolicyId -eq 'enrollment') {
        Assert-LoggingPolicyCondition (
            $Configuration.enrollment.renew_update_revoke -and $Configuration.enrollment.update_templates
        ) 'Enabled enrollment supports only the verified v1 all-options bundle'
        $key = 'HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
        $settings += ,(New-LoggingRegistrySetting $key 'AEPolicy' 'DWord' 7)
        $settings += ,(New-LoggingRegistrySetting $key 'OfflineExpirationPercent' 'DWord' ([int] $Configuration.enrollment.offline_expiration_percent))
        $settings += ,(New-LoggingRegistrySetting $key 'OfflineExpirationStoreNames' 'String' 'MY')
    }
    else {
        if ($Configuration.defender.disable_antispyware) {
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 'DWord' 1)
        }
        if ($Configuration.defender.disable_realtime_monitoring) {
            $settings += ,(New-LoggingRegistrySetting 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 'DWord' 1)
        }
    }
    return $settings
}

function Get-LoggingPolicyRegistryValue {
    param([hashtable] $Context, [string] $Guid, [System.Collections.IDictionary] $Identifier)
    $errors = @()
    $values = @(Get-GPRegistryValue -Guid $Guid -Domain $Context.domain_dns -Server $Context.dc -Key $Identifier.key -ValueName $Identifier.value_name -ErrorAction SilentlyContinue -ErrorVariable +errors)
    if ($errors.Count -gt 0) {
        $notFound = @($errors | Where-Object {
            $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
            $_.FullyQualifiedErrorId -match 'NotFound|ArgumentException'
        })
        if ($notFound.Count -ne $errors.Count) {
            throw "Registry policy read failed for '$($Identifier.key)\$($Identifier.value_name)': $($errors[0].Exception.Message)"
        }
        return $null
    }
    Assert-LoggingPolicyCondition ($values.Count -le 1) "Registry policy read was ambiguous for '$($Identifier.key)\$($Identifier.value_name)'"
    if ($values.Count -eq 0) {
        return $null
    }
    return $values[0]
}

function Test-LoggingPolicyRegistryValue {
    param([object] $Actual, [System.Collections.IDictionary] $Setting)
    if ($null -eq $Actual) {
        return $false
    }
    $actualType = [string] $Actual.Type
    $typeMatches = [string]::Equals($actualType, [string] $Setting.identifier.type, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $typeMatches) {
        return $false
    }
    if ($Setting.identifier.type -eq 'DWord') {
        return [uint32] $Actual.Value -eq [uint32] $Setting.value
    }
    return [string] $Actual.Value -ceq [string] $Setting.value
}

function Set-LoggingPolicyRegistryPending {
    param(
        [hashtable] $Context,
        [string] $PolicyId,
        [string] $TargetName,
        [string] $Operation,
        [System.Collections.IDictionary] $Identifier,
        [object] $IntendedRegistry
    )
    $record = $Context.state.policies[$PolicyId]
    $record.pending = @{
        operation = $Operation
        target = @{
            policy_id = $PolicyId
            target_name = $TargetName
            gpo_guid = [string] $record.gpo_guid
            registry_identifier = @{
                key = [string] $Identifier.key
                value_name = [string] $Identifier.value_name
                type = [string] $Identifier.type
            }
        }
        prior_ownership = @{ registry = @(Copy-LoggingPolicyRegistryIdentifiers $record.registry) }
        intended_ownership = @{ registry = @(Copy-LoggingPolicyRegistryIdentifiers $IntendedRegistry) }
    }
    Write-LoggingPolicyTrackedState $Context $PolicyId "persist_$Operation"
}

function Reconcile-LoggingPolicyRegistry {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [hashtable] $Context,
        [hashtable] $Configuration,
        [bool] $PlanOnly,
        [System.Collections.ArrayList] $Plans
    )

    foreach ($policyId in @('logging', 'enrollment', 'defender')) {
        Set-LoggingPolicyProgressScope $Context.progress $policyId 'registry_reconciliation' $Context.state_path
        $record = Get-LoggingPolicyRecord $Context.state $policyId
        if ($null -eq $record -or $null -eq $record.gpo_guid) {
            continue
        }
        $desired = @(Get-LoggingPolicyDesiredRegistry $policyId $Configuration)

        foreach ($setting in $desired) {
            $owned = @($record.registry | Where-Object { Test-LoggingPolicyRegistryIdentityEqual $_ $setting.identifier }).Count -eq 1
            $actual = Get-LoggingPolicyRegistryValue $Context $record.gpo_guid $setting.identifier
            Assert-LoggingPolicyCondition ($owned -or $null -eq $actual) "Requested registry value '$($setting.identifier.key)\$($setting.identifier.value_name)' exists outside committed ownership"
            if ($owned -and (Test-LoggingPolicyRegistryValue $actual $setting)) {
                continue
            }
            $operation = if ($owned) { 'registry_update' } else { 'registry_add' }
            Add-LoggingPolicyPlan $Plans "$operation $policyId registry value $($setting.identifier.value_name)"
            if ($PlanOnly -or -not $PSCmdlet.ShouldProcess($setting.identifier.value_name, $operation)) {
                continue
            }
            $intended = @(Copy-LoggingPolicyRegistryIdentifiers $record.registry)
            if (-not $owned) {
                $intended += ,$setting.identifier
            }
            Set-LoggingPolicyRegistryPending $Context $policyId ([string] $Configuration.names[$policyId]) $operation $setting.identifier $intended
            Start-LoggingPolicyMutation $Context.progress $policyId $operation "$($setting.identifier.key)\$($setting.identifier.value_name)"
            if ($setting.additive) {
                $null = Set-GPRegistryValue -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Key $setting.identifier.key -ValueName $setting.identifier.value_name -Type $setting.identifier.type -Value $setting.value -Additive -ErrorAction Stop
            }
            else {
                $null = Set-GPRegistryValue -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Key $setting.identifier.key -ValueName $setting.identifier.value_name -Type $setting.identifier.type -Value $setting.value -ErrorAction Stop
            }
            $readback = Get-LoggingPolicyRegistryValue $Context $record.gpo_guid $setting.identifier
            Assert-LoggingPolicyCondition (Test-LoggingPolicyRegistryValue $readback $setting) "Registry readback failed for '$($setting.identifier.value_name)'"
            Complete-LoggingPolicyMutation $Context.progress
            $record.registry = $intended
            $record.pending = $null
            Write-LoggingPolicyTrackedState $Context $policyId "commit_$operation"
        }

        $desiredIdentifiers = @($desired | ForEach-Object { $_.identifier })
        foreach ($identifier in @(Copy-LoggingPolicyRegistryIdentifiers $record.registry)) {
            $stillDesired = @($desiredIdentifiers | Where-Object { Test-LoggingPolicyRegistryIdentityEqual $_ $identifier }).Count -eq 1
            if ($stillDesired) {
                continue
            }
            Add-LoggingPolicyPlan $Plans "registry_remove $policyId registry value $($identifier.value_name)"
            if ($PlanOnly -or -not $PSCmdlet.ShouldProcess($identifier.value_name, 'registry_remove')) {
                continue
            }
            $intended = @($record.registry | Where-Object { -not (Test-LoggingPolicyRegistryIdentityEqual $_ $identifier) })
            Set-LoggingPolicyRegistryPending $Context $policyId ([string] $Configuration.names[$policyId]) 'registry_remove' $identifier $intended
            $actual = Get-LoggingPolicyRegistryValue $Context $record.gpo_guid $identifier
            if ($null -ne $actual) {
                Start-LoggingPolicyMutation $Context.progress $policyId 'registry_remove' "$($identifier.key)\$($identifier.value_name)"
                $null = Remove-GPRegistryValue -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Key $identifier.key -ValueName $identifier.value_name -ErrorAction Stop
            }
            $readback = Get-LoggingPolicyRegistryValue $Context $record.gpo_guid $identifier
            Assert-LoggingPolicyCondition ($null -eq $readback) "Registry retirement readback failed for '$($identifier.value_name)'"
            if ($null -ne $actual) { Complete-LoggingPolicyMutation $Context.progress }
            $record.registry = $intended
            $record.pending = $null
            Write-LoggingPolicyTrackedState $Context $policyId 'commit_registry_remove'
        }
    }
}

function Resolve-LoggingPolicyLinkRequests {
    param([hashtable] $Context, [object] $Requests)
    $resolved = @()
    $seen = @{}
    foreach ($request in $Requests) {
        $target = if (Test-LoggingPolicyStringEqual $request.target 'domain_root') {
            [string] $Context.domain_dn
        }
        else {
            [string] $request.target
        }
        $identity = $target.ToLowerInvariant()
        Assert-LoggingPolicyCondition (-not $seen.ContainsKey($identity)) "Duplicate resolved link target: $target"
        $seen[$identity] = $true
        $item = @{ target = $target; enabled = [bool] $request.enabled; enforced = [bool] $request.enforced }
        if ($request.Contains('order')) {
            $item.order = [int] $request.order
        }
        $resolved += ,$item
    }
    return $resolved
}

function Get-LoggingPolicyLink {
    param([hashtable] $Context, [string] $Guid, [string] $Target)
    $inheritance = Get-GPInheritance -Target $Target -Domain $Context.domain_dns -Server $Context.dc -ErrorAction Stop
    $links = @($inheritance.GpoLinks | Where-Object {
        ([guid] $_.GpoId).ToString('D').Equals($Guid, [System.StringComparison]::OrdinalIgnoreCase)
    })
    Assert-LoggingPolicyCondition ($links.Count -le 1) "Direct link is ambiguous at '$Target'"
    if ($links.Count -eq 0) {
        return $null
    }
    return $links[0]
}

function Test-LoggingPolicyLinkMatches {
    param([object] $Actual, [System.Collections.IDictionary] $Desired)
    if ($null -eq $Actual) {
        return $false
    }
    $enabled = [string] $Actual.Enabled -match '^(True|Yes)$'
    $enforced = [string] $Actual.Enforced -match '^(True|Yes)$'
    if ($enabled -ne [bool] $Desired.enabled -or $enforced -ne [bool] $Desired.enforced) {
        return $false
    }
    if ($Desired.Contains('order') -and [int] $Actual.Order -ne [int] $Desired.order) {
        return $false
    }
    return $true
}

function Set-LoggingPolicyLinkPending {
    param([hashtable] $Context, [string] $PolicyId, [string] $TargetName, [string] $Operation, [string] $Target, [object] $Intended)
    $record = $Context.state.policies[$PolicyId]
    $record.pending = @{
        operation = $Operation
        target = @{
            policy_id = $PolicyId
            target_name = $TargetName
            gpo_guid = [string] $record.gpo_guid
            link_target = $Target
        }
        prior_ownership = @{ link_targets = @($record.link_targets) }
        intended_ownership = @{ link_targets = @($Intended) }
    }
    Write-LoggingPolicyTrackedState $Context $PolicyId "persist_$Operation"
}

function Reconcile-LoggingPolicyLinks {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [hashtable] $Context,
        [hashtable] $Configuration,
        [bool] $PlanOnly,
        [System.Collections.ArrayList] $Plans
    )

    foreach ($policyId in @('logging', 'enrollment', 'defender')) {
        Set-LoggingPolicyProgressScope $Context.progress $policyId 'link_reconciliation' $Context.state_path
        $record = Get-LoggingPolicyRecord $Context.state $policyId
        if ($null -eq $record -or $null -eq $record.gpo_guid) {
            continue
        }
        $requests = if (Get-LoggingPolicyEnabled $policyId $Configuration) {
            @(Resolve-LoggingPolicyLinkRequests $Context $Configuration.links[$policyId])
        }
        else {
            @()
        }

        foreach ($request in $requests) {
            $owned = @($record.link_targets | Where-Object { Test-LoggingPolicyStringEqual $_ $request.target }).Count -eq 1
            $actual = Get-LoggingPolicyLink $Context $record.gpo_guid $request.target
            if ($owned -and (Test-LoggingPolicyLinkMatches $actual $request)) {
                continue
            }
            $operation = if ($owned) { 'link_update' } else { 'link_add' }
            Assert-LoggingPolicyCondition ($owned -or $null -eq $actual) "Requested link at '$($request.target)' exists outside committed ownership"
            Add-LoggingPolicyPlan $Plans "$operation $policyId at $($request.target)"
            if ($PlanOnly -or -not $PSCmdlet.ShouldProcess($request.target, $operation)) {
                continue
            }
            $intended = @($record.link_targets)
            if (-not $owned) {
                $intended += $request.target
            }
            Set-LoggingPolicyLinkPending $Context $policyId ([string] $Configuration.names[$policyId]) $operation $request.target $intended
            $linkEnabled = if ($request.enabled) { 'Yes' } else { 'No' }
            $enforced = if ($request.enforced) { 'Yes' } else { 'No' }
            Start-LoggingPolicyMutation $Context.progress $policyId $operation $request.target
            if ($operation -eq 'link_add' -or $null -eq $actual) {
                if ($request.Contains('order')) {
                    $null = New-GPLink -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Target $request.target -LinkEnabled $linkEnabled -Enforced $enforced -Order $request.order -ErrorAction Stop
                }
                else {
                    $null = New-GPLink -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Target $request.target -LinkEnabled $linkEnabled -Enforced $enforced -ErrorAction Stop
                }
            }
            elseif ($request.Contains('order')) {
                $null = Set-GPLink -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Target $request.target -LinkEnabled $linkEnabled -Enforced $enforced -Order $request.order -ErrorAction Stop
            }
            else {
                $null = Set-GPLink -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Target $request.target -LinkEnabled $linkEnabled -Enforced $enforced -ErrorAction Stop
            }
            $readback = Get-LoggingPolicyLink $Context $record.gpo_guid $request.target
            Assert-LoggingPolicyCondition (Test-LoggingPolicyLinkMatches $readback $request) "Link readback failed at '$($request.target)'"
            Complete-LoggingPolicyMutation $Context.progress
            $record.link_targets = $intended
            $record.pending = $null
            Write-LoggingPolicyTrackedState $Context $policyId "commit_$operation"
        }

        foreach ($target in @($record.link_targets)) {
            $requested = @($requests | Where-Object { Test-LoggingPolicyStringEqual $_.target $target }).Count -eq 1
            if ($requested) {
                continue
            }
            $actual = Get-LoggingPolicyLink $Context $record.gpo_guid $target
            $alreadyDisabled = $null -eq $actual -or ([string] $actual.Enabled -notmatch '^(True|Yes)$')
            if ($alreadyDisabled) {
                continue
            }
            Add-LoggingPolicyPlan $Plans "link_disable $policyId at $target"
            if ($PlanOnly -or -not $PSCmdlet.ShouldProcess($target, 'link_disable')) {
                continue
            }
            Set-LoggingPolicyLinkPending $Context $policyId ([string] $Configuration.names[$policyId]) 'link_disable' $target @($record.link_targets)
            if ($null -ne $actual) {
                Start-LoggingPolicyMutation $Context.progress $policyId 'link_disable' $target
                $null = Set-GPLink -Guid $record.gpo_guid -Domain $Context.domain_dns -Server $Context.dc -Target $target -LinkEnabled No -ErrorAction Stop
            }
            $readback = Get-LoggingPolicyLink $Context $record.gpo_guid $target
            Assert-LoggingPolicyCondition ($null -eq $readback -or [string] $readback.Enabled -notmatch '^(True|Yes)$') "Link-disable readback failed at '$target'"
            if ($null -ne $actual) { Complete-LoggingPolicyMutation $Context.progress }
            $record.pending = $null
            Write-LoggingPolicyTrackedState $Context $policyId 'commit_link_disable'
        }
    }
}

function Invoke-LoggingPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [hashtable] $Configuration,
        [bool] $PlanOnly,
        [hashtable] $Progress = (New-LoggingPolicyProgress)
    )

    $plans = $Progress.planned_changes
    $policies = $Progress.policies
    $initialContext = Get-LoggingPolicyContext $Configuration
    Set-LoggingPolicyProgressScope $Progress $null 'acquire_writer' $initialContext.state_path
    $writer = Enter-LoggingPolicyWriter $initialContext $PlanOnly
    try {
        $context = Get-LoggingPolicyContext $Configuration
        $context.writer_held = $true
        $context.progress = $Progress
        Set-LoggingPolicyProgressScope $Progress $null 'reconcile' $context.state_path
        $mutationsAllowed = -not $PlanOnly -and $PSCmdlet.ShouldProcess($context.domain_dns, 'Reconcile role-owned logging policies')
        $effectivePlanOnly = -not $mutationsAllowed

        Reconcile-LoggingPolicyObjects $context $Configuration $effectivePlanOnly $plans
        Reconcile-LoggingPolicyRegistry $context $Configuration $effectivePlanOnly $plans

        $loggingRecord = Get-LoggingPolicyRecord $context.state 'logging'
        if ($null -ne $loggingRecord -and $null -ne $loggingRecord.gpo_guid) {
            # Publish-LoggingAudit owns both audit_publish and audit_delete transitions.
            $guidWithBraces = '{' + ([guid] $loggingRecord.gpo_guid).ToString('D').ToUpperInvariant() + '}'
            $context.gpo_guid = [string] $loggingRecord.gpo_guid
            $context.gpo_dn = "CN=$guidWithBraces,CN=Policies,CN=System,$($context.domain_dn)"
            $context.gpt_path = [System.IO.Path]::Combine($context.sysvol_root, "Policies\$guidWithBraces")
            $context.policy_name = [string] $Configuration.names.logging
            $auditCsv = if ($Configuration.logging_enabled) { [string] $Configuration.desired_audit_csv } else { 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value' }
            $auditResult = Publish-LoggingAudit -Context $context -State $context.state -DesiredCsv $auditCsv -PlanOnly $effectivePlanOnly
            $context.state = $auditResult.state
            if ($auditResult.changed) {
                Add-LoggingPolicyPlan $plans 'publish bounded logging advanced-audit policy'
            }
        }

        Reconcile-LoggingPolicyLinks $context $Configuration $effectivePlanOnly $plans
        foreach ($policyId in @('logging', 'enrollment', 'defender')) {
            $record = Get-LoggingPolicyRecord $context.state $policyId
            $summaryGuid = if ($null -ne $record) { $record.gpo_guid } else { $null }
            $null = $policies.Add(@{
                id = $policyId
                enabled = Get-LoggingPolicyEnabled $policyId $Configuration
                managed = $null -ne $record
                gpo_guid = $summaryGuid
            })
        }
        return @{
            changed = $plans.Count -gt 0
            planned_changes = @($plans)
            policies = @($policies)
        }
    }
    finally {
        $writer.Dispose()
    }
}
