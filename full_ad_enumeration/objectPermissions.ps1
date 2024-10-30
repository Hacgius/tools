function ObjectPermissions {
    param (
        [string[]]$OBJECTS,
        [string[]]$TYPEPERMISSIONS=@("GenericALL","GenericWrite", "WriteOwner", "WriteDACL", "AllExtendedRights", "ForceChangePassword","Self")
    )
        if(!$PSBoundParameters.ContainsKey('OBJECTS')){
                return @"

ObjectPermissions -OBJECTS <object, ...> [-TYPERMISSIONS <typepermission, ...>]
            
Types of permission
------------------------------------------------------------
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
------------------------------------------------------------
"@;
        }
    
        foreach ($Object in $OBJECTS)
        {
                Write-Output `n`n"||||||||||||||||||||||||||||||||||||||||"
                foreach ($Permission in $TYPEPERMISSIONS)
                {
                        Write-Output `n`n"*--------------------------------------*"
                        $local:line = "Object:"+$Object+"`nType Permissions:"+$Permission
                        Write-Output $line
            Write-Output "----------------------------------------"

                        foreach ($securityIdentifier in $((Get-ObjectAcl -Identity $Object | ? {$_.ActiveDirectoryRights -eq $Permission} | Select SecurityIdentifier).securityIdentifier)) 
                        {
                                $local:line = $(Convert-SidToName $securityIdentifier)+" ("+$securityIdentifier+")"
                                Write-Output $line
                        }
                        Write-Output "*--------------------------------------*"`n`n
                }
        }
        Write-Output "||||||||||||||||||||||||||||||||||||||||"
}

function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}