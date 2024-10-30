#!/bin/bash
mkdir ad_auto
cd ad_auto
mkdir groups ous hostnames users privileges gpos sharefolders delegations
cd ../
mv enum_currentDomainSID.txt enum_currentDomain.txt enum_sessions.txt enum_account_policies.txt ad_auto/
mv enum_membersOfGroup*.txt enum_groups.txt ad_auto/groups
mv enum_OUs.txt enum_membersOfOU*.txt ad_auto/ous
mv enum_hostnames*.txt enum_domainControllers.txt ad_auto/hostnames
mv enum_users.txt enum_full_info_users.txt enum_spn.txt ad_auto/users
mv enum_privileges*.txt ad_auto/privileges
mv enum_GPOs.txt ad_auto/gpos
mv *delegations* ad_auto/delegations