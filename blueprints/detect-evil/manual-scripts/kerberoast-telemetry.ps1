# Generate telemetry similar to kerberoast attacks

New-ADOrganizationalUnit -Name "Kerberoast" -Path "DC=CONDEF,DC=local"

New-ADUser User1 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User1 -UserPrincipalName User1 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User1 -ServicePrincipalNames @{Add = 'HTTP/webserver', 'HTTP/CONDEF' }

New-ADUser User2 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User2 -UserPrincipalName User2 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User2 -ServicePrincipalNames @{Add = 'HTTP/webserver1', 'HTTP/CONDEF1' }

New-ADUser User3 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User3 -UserPrincipalName User3 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User3 -ServicePrincipalNames @{Add = 'HTTP/webserver2', 'HTTP/CONDEF2' }

New-ADUser User4 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User4 -UserPrincipalName User4 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User4 -ServicePrincipalNames @{Add = 'HTTP/webserver3', 'HTTP/CONDEF3' }

New-ADUser User5 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User5 -UserPrincipalName User5 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User5 -ServicePrincipalNames @{Add = 'HTTP/webserver4', 'HTTP/CONDEF4' }

New-ADUser User6 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User6 -UserPrincipalName User6 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User6 -ServicePrincipalNames @{Add = 'HTTP/webserver5', 'HTTP/CONDEF5' }

New-ADUser User7 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User7 -UserPrincipalName User7 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User7 -ServicePrincipalNames @{Add = 'HTTP/webserver6', 'HTTP/CONDEF6' }

New-ADUser User8 -Path "OU=Kerberoast,DC=CONDEF,DC=local" -AccountPassword (ConvertTo-SecureString "Temp1234567!!" -AsPlainText -Force) -DisplayName User8 -UserPrincipalName User8 -ChangePasswordAtLogon 0 -Enabled 1
Set-ADUser -Identity User8 -ServicePrincipalNames @{Add = 'HTTP/webserver7', 'HTTP/CONDEF7' }
