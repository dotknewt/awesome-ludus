# Run on domain controller
$lowpriv = "OlaBruker"
$highpriv = "OlaAdmin"
## Create a new AD users $lowpriv and $highpriv
foreach ($user in "$lowpriv", "$highpriv") {
    try { Get-ADUser "${user}" }
    catch [Microsoft.PowerShell.Commands.ADIdentityNotFoundException] {
        New-ADUser -name ${user} -AccountPassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true
    }
}

# Creates 15 folders in C:\Shares, named Share[1-15] and creates an SMB share from each folder called Logs[1-15]
# Denies user $lowpriv access to the shares

foreach ($number in 1..15) {
    try { Get-Item "C:\Shares\Share$number" }
    catch [Microsoft.PowerShell.Commands.PathNotFound] { 
        New-Item "C:\Shares\Share$number" -ItemType Directory 
    }

    try { Get-SmbShare -Name "Logs$number" }
    catch [CimJobException] {
        New-SmbShare -Name "Logs$number" -Description "Test Share $number" -Path "C:\Shares\Share$number" -NoAccess ${lowpriv} -FullAccess 'Everyone'
    }
}

# Create a single share only accessible by $highpriv
try { Get-Item "C:\Shares\Share16" }
catch [Microsoft.PowerShell.Commands.PathNotFound] { 
    New-Item "C:\Shares\Share16"
}

try { Get-SmbShare -Name "Logs16" }
catch [CmdletizationQuery_NotFound_Name] {
    New-SmbShare -Name "Logs16" -Description "Only ${highpriv} HasAccess" -Path "C:\Shares\Share16" -NoAccess Administrator, ${lowpriv}, condef, localuser -FullAccess ${highpriv}
}
