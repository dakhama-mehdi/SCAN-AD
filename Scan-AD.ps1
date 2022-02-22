<#
.Synopsis
    SCAN-AD.ps1
     
    AUTHOR: Dakhama Mehdi
    
    This Script help to list the permissions ACE applied on AD and GPOs with warrantely, to prevent 
    an attack or audit/secure AD.
     
    #>


Import-Module ActiveDirectory

# Clear Variable
$genericgroups = $skipdeaultgroups  =  $conditions = $null
$genericgroups = $skipdeaultgroups = @()

#region Get info Domain
$dom= (Get-ADDomain)
$domsid = $dom.domainsid.tostring()
$domain = $dom.DistinguishedName
#endregion Get info Domain

# Search Type : Onelevel or Subtree
$levelsearch = "subtree"
$searchGPO = 'True'
$VerbosePreference = "SilentlyContinue" # Mode verbose "continue"

Push-Location AD:

# Collect and Skip the default account (Nt autority, Self, etc...)
$genericgroups += ((Get-Acl "AD:$((Get-ADRootDSE).schemaNamingContext)").Access).IdentityReference
# Collect all builtin groups without domain users and domain authentified
$skipdeaultgroups += (Get-ADGroup -filter 'SID -ne "S-1-5-32-545" -and SID -ne "S-1-5-32-546"' -Searchbase (Get-ADObject -Filter 'name -eq "Builtin"')).name
# Collect other admins groups like administrators entreprise and domaine
$skipdeaultgroups += (Get-ADGroup -Filter { AdminCOunt -eq 1 -and iscriticalsystemobject -like "*" }).Name
# Skip Domains clons group
$skipdeaultgroups += (Get-ADGroup ($domsid + '-522')).name


# Filtre the ACL
$conditions = {$genericgroups -notcontains $_.identityreference -and $skipdeaultgroups -notcontains $_.IdentityReference.Value.Split("\")[1] -and $_.IdentityReference -notlike "*SELF*" -and $_.IdentityReference -like "*\*" -and $_.AccessControlType -eq "Allow" }

#region Fonctions
 
#Fonction Get  GUID 

function getGuid ( $droits ) {

$GuidName = $null
    
Switch ($droits) {
"4c164200-20c0-11d0-a768-00aa006e0529"  {$GuidName = "Account Restrictions"}              
"00000000-0000-0000-0000-000000000000"  {$GuidName = "All"}                                      
"bf96793f-0de6-11d0-a285-00aa003049e2"  {$GuidName = "CN"}                                       
"bf967a86-0de6-11d0-a285-00aa003049e2"  {$GuidName = "Computer"}                                
"5cb41ed0-0e4c-11d0-a286-00aa003049e2"  {$GuidName = "Contact"}                                  
"bf9679e4-0de6-11d0-a285-00aa003049e2"  {$GuidName = "distinguishedName"}                        
"72e39547-7b18-11d1-adef-00c04fd8d5cd"  {$GuidName = "dNSHostName"}                                             
"f30e3bbe-9ff0-11d1-b603-0000f80367c1"  {$GuidName = "gPLink"}                                   
"bf967a9c-0de6-11d0-a285-00aa003049e2"  {$GuidName = "Group"}                                    
"7b8b558a-93a5-4af7-adca-c017e67f1057"  {$GuidName = "GroupManagedServiceAccount"}               
"ce206244-5827-4a86-ba1c-1c0c386c1b64"  {$GuidName = "ManagedServiceAccount"}                    
"bf9679c0-0de6-11d0-a285-00aa003049e2"  {$GuidName = "member"}                                   
"bf967a0e-0de6-11d0-a285-00aa003049e2"  {$GuidName = "name"}                                     
"bf967aa5-0de6-11d0-a285-00aa003049e2"  {$GuidName = "OrganizationalUnit"}                       
"bf967a0a-0de6-11d0-a285-00aa003049e2"  {$GuidName = "PwdLastSet"}                               
"00299570-246d-11d0-a768-00aa006e0529"  {$GuidName = "ResetPassword"}                           
"3e0abfd0-126a-11d0-a060-00aa006c33ed"  {$GuidName = "sAMAccountName"}                                                 
"f3a64788-5306-11d1-a9c5-0000f80367c1"  {$GuidName = "servicePrincipalName"}                     
"bf967aba-0de6-11d0-a285-00aa003049e2"  {$GuidName = "User"}                                     
"bf967a6d-0de6-11d0-a285-00aa003049e2"  {$GuidName = "userParameters"}                                  
"f3a64788-5306-11d1-a9c5-0000f80367c1"  {$GuidName = "Validated write to service principal name"}
"BF967ABB-0DE6-11D0-A285-00AA003049E2"  {$GuidName = "volume"}
"F30E3BBF-9FF0-11D1-B603-0000F80367C1"  {$GuidName = "gPOptions"}
"BF967AA8-0DE6-11D0-A285-00AA003049E2"  {$GuidName = "printQueue"}
"4828CC14-1437-45BC-9B07-AD6F015E5F28"  {$GuidName = "inetOrgPerson"}
"bf96794f-0de6-11d0-a285-00aa003049e2"  {$GuidName = "department"}
"bf967950-0de6-11d0-a285-00aa003049e2"  {$GuidName = "description"}	
"bf967953-0de6-11d0-a285-00aa003049e2"  {$GuidName = "displayName"}	
"f0f8ff8e-1191-11d0-a060-00aa006c33ed"  {$GuidName = "givenName"}
"bf967961-0de6-11d0-a285-00aa003049e2"  {$GuidName = "mail"}	
"bf9679f7-0de6-11d0-a285-00aa003049e2"  {$GuidName = "physicalDeliveryOfficeName"}	
"bf967a06-0de6-11d0-a285-00aa003049e2"  {$GuidName = "proxyAddresses"}	
"bf967a41-0de6-11d0-a285-00aa003049e2"  {$GuidName = "sn"}	
"bf967a49-0de6-11d0-a285-00aa003049e2"  {$GuidName = "telephoneNumber"}	
"d74a8762-22b9-11d3-aa62-00c04f8eedd8"  {$GuidName = "Administer Exchange information store"}
"e2a36dc9-ae17-47c3-b58b-be34c55ba633"  {$GuidName = "Create Inbound Forest Trust"}	
"ab721a53-1e2f-11d0-9819-00aa0040529b"  {$GuidName = "Change Password"}
"ba33815a-4f93-4c76-87f3-57574bff8109"  {$GuidName = "Migrate SID History"}	
"45ec5156-db7e-47bb-b53f-dbeb2d03c40f"  {$GuidName = "Reanimate Tombstones"}
"ab721a56-1e2f-11d0-9819-00aa0040529b"  {$GuidName = "Receive As"}
"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"  {$GuidName = "Replication Synchronization"}
"ab721a54-1e2f-11d0-9819-00aa0040529b"  {$GuidName = "Send As"}
"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"  {$GuidName = "Unexpire Password"}
"d74a875e-22b9-11d3-aa62-00c04f8eedd8"  {$GuidName = "View Exchange information store status"}
"edacfd8f-ffb3-11d1-b41d-00a0c968f939"  {$GuidName = "Apply Group Policy"}

default {$GuidName = $droits}


}

    return $GuidName
}

#==========================================================================
# Function		: Get-Criticality
# Arguments     : $objRights,$objAccess,$objFlags,$objInheritanceType
# Returns   	: Integer
# Description   : Check criticality and returns number for rating
#==========================================================================

Function Get-Criticality {
    Param($objRights,$objAccess,$objFlags,$objInheritanceType,$objObjectType,$objInheritedObjectType)

[int]$CriticalityFilter=0
$intCriticalityLevel = 0
$objAccess = "Allow"

Switch ($objRights)
{
    "ListChildren"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 0
        }
    }
    "Read permissions, Modify permissions"
    {
        $intCriticalityLevel = 4
    }
    "Modify permissions"
    {
        $intCriticalityLevel = 4
    }
    {($_ -match "WriteDacl") -or ($_ -match "WriteOwner")}
    {
        $intCriticalityLevel = 4
    }
    "DeleteChild, DeleteTree, Delete"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
        }
    }
    "Delete"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
        }
    }
    "GenericRead"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 1
    	}
    }
    "CreateChild"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
    	}
    }
    "DeleteChild"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
    	}
    }
    "ExtendedRight"
    {
        If ($objAccess -eq "Allow")
        {
            Switch ($objObjectType)
            {

                # Domain Administer Server =
                "ab721a52-1e2f-11d0-9819-00aa0040529b"
                {
                $intCriticalityLevel = 4
                }
                # Change Password =
                "ab721a53-1e2f-11d0-9819-00aa0040529b"
                {
                $intCriticalityLevel = 1
                }
                # Reset Password =
                "00299570-246d-11d0-a768-00aa006e0529"
                {
                $intCriticalityLevel = 3
                }
                # Send As =
                "ab721a54-1e2f-11d0-9819-00aa0040529b"
                {
                $intCriticalityLevel = 4
                }
                # Receive As =
                "ab721a56-1e2f-11d0-9819-00aa0040529b"
                {
                $intCriticalityLevel = 4
                }
                # Send To =
                "ab721a55-1e2f-11d0-9819-00aa0040529b"
                {
                $intCriticalityLevel = 4
                }
                # Open Address List =
                "a1990816-4298-11d1-ade2-00c04fd8d5cd"
                {
                $intCriticalityLevel = 1
                }
                # Replicating Directory Changes =
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                {
                $intCriticalityLevel = 4
                }
                # Replication Synchronization =
                "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
                {
                $intCriticalityLevel = 4
                }
                # Manage Replication Topology =
                "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2"
                {
                $intCriticalityLevel = 4
                }
                # Change Schema Master =
                "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"
                {
                $intCriticalityLevel = 4
                }
                # Change Rid Master =
                "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd"
                {
                $intCriticalityLevel = 4
                }
                # Do Garbage Collection =
                "fec364e0-0a98-11d1-adbb-00c04fd8d5cd"
                {
                $intCriticalityLevel = 4
                }
                # Recalculate Hierarchy =
                "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd"
                {
                $intCriticalityLevel = 4
                }
                # Allocate Rids =
                "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd"
                {
                $intCriticalityLevel = 4
                }
                # Change PDC =
                "bae50096-4752-11d1-9052-00c04fc2d4cf"
                {
                $intCriticalityLevel = 4
                }
                # Add GUID =
                "440820ad-65b4-11d1-a3da-0000f875ae0d"
                {
                $intCriticalityLevel = 4
                }
                # Change Domain Master =
                "014bf69c-7b3b-11d1-85f6-08002be74fab"
                {
                $intCriticalityLevel = 4
                }
                # Receive Dead Letter =
                "4b6e08c0-df3c-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Peek Dead Letter =
                "4b6e08c1-df3c-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Receive Computer Journal =
                "4b6e08c2-df3c-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Peek Computer Journal =
                "4b6e08c3-df3c-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Receive Message =
                "06bd3200-df3e-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Peek Message =
                "06bd3201-df3e-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Send Message =
                "06bd3202-df3e-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Receive Journal =
                "06bd3203-df3e-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Open Connector Queue =
                "b4e60130-df3f-11d1-9c86-006008764d0e"
                {
                $intCriticalityLevel = 1
                }
                # Apply Group Policy =
                "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
                {
                $intCriticalityLevel = 1
                }
                # Add/Remove Replica In Domain =
                "9923a32a-3607-11d2-b9be-0000f87a36b2"
                {
                $intCriticalityLevel = 4
                }
                # Change Infrastructure Master =
                "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd"
                {
                $intCriticalityLevel = 4
                }
                # Update Schema Cache =
                "be2bb760-7f46-11d2-b9ad-00c04f79f805"
                {
                $intCriticalityLevel = 4
                }
                # Recalculate Security Inheritance =
                "62dd28a8-7f46-11d2-b9ad-00c04f79f805"
                {
                $intCriticalityLevel = 4
                }
                # Check Stale Phantoms =
                "69ae6200-7f46-11d2-b9ad-00c04f79f805"
                {
                $intCriticalityLevel = 4
                }
                # Enroll =
                "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                {
                $intCriticalityLevel = 1
                }
                # Generate Resultant Set of Policy (Planning) =
                "b7b1b3dd-ab09-4242-9e30-9980e5d322f7"
                {
                $intCriticalityLevel = 1
                }
                # Refresh Group Cache for Logons =
                "9432c620-033c-4db7-8b58-14ef6d0bf477"
                {
                $intCriticalityLevel = 4
                }
                # Enumerate Entire SAM Domain =
                "91d67418-0135-4acc-8d79-c08e857cfbec"
                {
                $intCriticalityLevel = 4
                }
                # Generate Resultant Set of Policy (Logging) =
                "b7b1b3de-ab09-4242-9e30-9980e5d322f7"
                {
                $intCriticalityLevel = 1
                }
                # Create Inbound Forest Trust =
                "e2a36dc9-ae17-47c3-b58b-be34c55ba633"
                {
                $intCriticalityLevel = 4
                }
                # Replicating Directory Changes All =
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
                {
                $intCriticalityLevel = 4
                }
                # Migrate SID History =
                "BA33815A-4F93-4c76-87F3-57574BFF8109"
                {
                $intCriticalityLevel = 4
                }
                # Reanimate Tombstones =
                "45EC5156-DB7E-47bb-B53F-DBEB2D03C40F"
                {
                $intCriticalityLevel = 4
                }
                # Allowed to Authenticate =
                "68B1D179-0D15-4d4f-AB71-46152E79A7BC"
                {
                $intCriticalityLevel = 1
                }
                # Execute Forest Update Script =
                "2f16c4a5-b98e-432c-952a-cb388ba33f2e"
                {
                $intCriticalityLevel = 4
                }
                # Monitor Active Directory Replication =
                "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96"
                {
                $intCriticalityLevel = 3
                }
                # Update Password Not Required Bit =
                "280f369c-67c7-438e-ae98-1d46f3c6f541"
                {
                $intCriticalityLevel = 1
                }
                # Unexpire Password =
                "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"
                {
                $intCriticalityLevel = 1
                }
                # Enable Per User Reversibly Encrypted Password =
                "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"
                {
                $intCriticalityLevel = 1
                }
                # Query Self Quota =
                "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc"
                {
                $intCriticalityLevel = 1
                }
                # Read Only Replication Secret Synchronization =
                "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
                {
                $intCriticalityLevel = 4
                }
                # Reload SSL/TLS Certificate =
                "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8"
                {
                $intCriticalityLevel = 4
                }
                # Replicating Directory Changes In Filtered Set =
                "89e95b76-444d-4c62-991a-0facbeda640c"
                {
                $intCriticalityLevel = 4
                }
                # Run Protect Admin Groups Task =
                "7726b9d5-a4b4-4288-a6b2-dce952e80a7f"
                {
                $intCriticalityLevel = 4
                }
                # Manage Optional Features for Active Directory =
                "7c0e2a7c-a419-48e4-a995-10180aad54dd"
                {
                $intCriticalityLevel = 4
                }
                # Allow a DC to create a clone of itself =
                "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e"
                {
                $intCriticalityLevel = 4
                }
                # AutoEnrollment =
                "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
                {
                $intCriticalityLevel = 1
                }
                # Set Owner of an object during creation. =
                "4125c71f-7fac-4ff0-bcb7-f09a41325286"
                {
                $intCriticalityLevel = 1
                }
                # Bypass the quota restrictions during creation. =
                "88a9933e-e5c8-4f2a-9dd7-2527416b8092"
                {
                $intCriticalityLevel = 4
                }
                # Read secret attributes of objects in a Partition. =
                "084c93a2-620d-4879-a836-f0ae47de0e89"
                {
                $intCriticalityLevel = 4
                }
                # Write secret attributes of objects in a Partition. =
                "94825A8D-B171-4116-8146-1E34D8F54401"
                {
                $intCriticalityLevel = 4
                }   
                default
                {
                    $intCriticalityLevel = 1
                }
            }
            
        }
    }
    "GenericAll"
    {
        If ($objAccess -eq "Allow")
        {
            Switch ($objInheritanceType) 
    	    {
                "All"
                {
                    Switch ($objObjectType)
                    {
                        # Any =  4
                        "00000000-0000-0000-0000-000000000000"
                        {
                            $intCriticalityLevel = 4
                        }
                        # Privat-Information = 3
                        "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
                        {
                            $intCriticalityLevel = 3
                        }
                        # Password Reset = 4
                        "00299570-246d-11d0-a768-00aa006e0529"
                        {
                            $intCriticalityLevel = 3
                        }
                        # Membership = 4
                        "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
                        {
                            $intCriticalityLevel = 4
                        }
                        default
                        {
                           $intCriticalityLevel = 3
                        }
                    }
                }
    	 	    "None"
    	 	    {
                    $intCriticalityLevel = 4
                }
                "Children"
    	        {
                 
                }
                "Descendents"
                {
                    Switch ($objInheritedObjectType)
                    {
                        # Any =  4
                        "00000000-0000-0000-0000-000000000000"
                        {
                            $intCriticalityLevel = 4
                        }
                        # User = 4
                        "bf967aba-0de6-11d0-a285-00aa003049e2"
                        {
                            $intCriticalityLevel = 4

                        }
                        # Group = 4
                        "bf967a9c-0de6-11d0-a285-00aa003049e2"
                        {
                            $intCriticalityLevel = 4

                        }
                        # Computer = 4
                        "bf967a86-0de6-11d0-a285-00aa003049e2"
                        {
                            $intCriticalityLevel = 4

                        }
                        # ms-DS-Managed-Service-Account = 4
                        "ce206244-5827-4a86-ba1c-1c0c386c1b64"
                        {
                            $intCriticalityLevel = 4

                        }
                        # msDS-Group-Managed-Service-Account = 4
                        "7b8b558a-93a5-4af7-adca-c017e67f1057"
                        {
                            $intCriticalityLevel = 4

                        }
                        default
                        {
                            $intCriticalityLevel = 3
                        }
                    }
                                  
                }
    	        default
    	        {
                    $intCriticalityLevel = 3
                }
            }#End switch


    	}
    }
    "CreateChild, DeleteChild"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
    	}
    }
    "ReadProperty"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 1

            Switch ($objInheritanceType) 
            {
    	        "None"
    	        {

                }
                "Children"
    	        {
                 
                }
                "Descendents"
                {
                                  
                }
    	        default
    	        {

                }
            }#End switch
        }
    }
    {$_ -match "WriteProperty"}
    {
        If ($objAccess -eq "Allow")
        {
            Switch ($objInheritanceType) 
    	    {
                {($_ -match "All") -or ($_ -match "None")}
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            Switch ($objObjectType)
                            {
                                # Domain Password & Lockout Policies = 4
                                "c7407360-20bf-11d0-a768-00aa006e0529"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Account Restrictions = 4
                                "4c164200-20c0-11d0-a768-00aa006e0529"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Group Membership = 4
                                "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Public Information = 4
                                "e48d0154-bcf8-11d1-8702-00c04fb96050"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Email-Information = 0
                                "E45795B2-9455-11d1-AEBD-0000F80367C1"
                                {
                                    $intCriticalityLevel = 0
                                }
                                # Web-Information = 2
                                "E45795B3-9455-11d1-AEBD-0000F80367C1"
                                {
                                    #If it SELF then = 1
                                    if($objIdentity -eq "NT AUTHORITY\SELF")
                                    {
                                        $intCriticalityLevel = 1
                                    }
                                    else
                                    {
                                        $intCriticalityLevel = 1
                                    }
                                }
                                # Personal-Information = 2
                                "77B5B886-944A-11d1-AEBD-0000F80367C1"
                                {
                                    #If it SELF then = 1
                                    if($objIdentity -eq "NT AUTHORITY\SELF")
                                    {
                                        $intCriticalityLevel = 1
                                    }
                                    else
                                    {
                                        $intCriticalityLevel = 2
                                    }
                                }
                                # User-Account-Control = 4
                                "bf967a68-0de6-11d0-a285-00aa003049e2"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Service-Principal-Name = 4
                                "f3a64788-5306-11d1-a9c5-0000f80367c1"
                                {
                                    $intCriticalityLevel = 4
                                }
                                #  Is-Member-Of-DL = 4
                                "bf967991-0de6-11d0-a285-00aa003049e2"
                                {
                                    $intCriticalityLevel = 4
                                }
                                default
                                {
                                    $intCriticalityLevel = 2
                                }
                            }
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {

                        }
                        default
                        {
                            $intCriticalityLevel = 3
                        }
                    }#End switch
                }
                "Children"
    	        {

                 
                }
                "Descendents"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            Switch ($objObjectType)
                            {
                                # Domain Password & Lockout Policies = 4
                                "c7407360-20bf-11d0-a768-00aa006e0529"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Account Restrictions = 4
                                "4c164200-20c0-11d0-a768-00aa006e0529"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Group Membership = 4
                                "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Email-Information = 0
                                "E45795B2-9455-11d1-AEBD-0000F80367C1"
                                {
                                    $intCriticalityLevel = 0
                                }
                                # Web-Information = 2
                                "E45795B3-9455-11d1-AEBD-0000F80367C1"
                                {
                                    #If it SELF then = 1
                                    if($objIdentity -eq "NT AUTHORITY\SELF")
                                    {
                                        $intCriticalityLevel = 1
                                    }
                                    else
                                    {
                                        $intCriticalityLevel = 2
                                    }
                                }
                                # Personal-Information = 2
                                "77B5B886-944A-11d1-AEBD-0000F80367C1"
                                {
                                    #If it SELF then = 1
                                    if($objIdentity -eq "NT AUTHORITY\SELF")
                                    {
                                        $intCriticalityLevel = 1
                                    }
                                    else
                                    {
                                        $intCriticalityLevel = 2
                                    }
                                }
                                # User-Account-Control = 4
                                "bf967a68-0de6-11d0-a285-00aa003049e2"
                                {
                                    $intCriticalityLevel = 4
                                }
                                # Service-Principal-Name = 4
                                "f3a64788-5306-11d1-a9c5-0000f80367c1"
                                {
                                    $intCriticalityLevel = 4
                                }
                                #  Is-Member-Of-DL = 4
                                "bf967991-0de6-11d0-a285-00aa003049e2"
                                {
                                    $intCriticalityLevel = 4
                                }
                                default
                                {
                                    $intCriticalityLevel = 2
                                }
                            }
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            Switch ($objInheritedObjectType)
                            {
                                # User = 4 ,Group = 4,Computer = 4
                                {($_ -eq "bf967aba-0de6-11d0-a285-00aa003049e2") -or ($_ -eq "bf967a9c-0de6-11d0-a285-00aa003049e2") -or ($_ -eq "bf967a86-0de6-11d0-a285-00aa003049e2") -or ($_ -eq "ce206244-5827-4a86-ba1c-1c0c386c1b64") -or ($_ -eq "7b8b558a-93a5-4af7-adca-c017e67f1057")}
                                {

                                    Switch ($objObjectType)
                                    {
                                        # Account Restrictions = 4
                                        "4c164200-20c0-11d0-a768-00aa006e0529"
                                        {
                                            $intCriticalityLevel = 4
                                        }
                                        # Group Membership = 4
                                        "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
                                        {
                                            $intCriticalityLevel = 4
                                        }
                                        # Email-Information = 0
                                        "E45795B2-9455-11d1-AEBD-0000F80367C1"
                                        {
                                            $intCriticalityLevel = 0
                                        }
                                        # Web-Information = 2
                                        "E45795B3-9455-11d1-AEBD-0000F80367C1"
                                        {
                                            #If it SELF then = 1
                                            if($objIdentity -eq "NT AUTHORITY\SELF")
                                            {
                                                $intCriticalityLevel = 1
                                            }
                                            else
                                            {
                                                $intCriticalityLevel = 2
                                            }
                                        }
                                        # Personal-Information = 2
                                        "77B5B886-944A-11d1-AEBD-0000F80367C1"
                                        {
                                            #If it SELF then = 1
                                            if($objIdentity -eq "NT AUTHORITY\SELF")
                                            {
                                                $intCriticalityLevel = 1
                                            }
                                            else
                                            {
                                                $intCriticalityLevel = 2
                                            }
                                        }
                                        # User-Account-Control = 4
                                        "bf967a68-0de6-11d0-a285-00aa003049e2"
                                        {
                                            $intCriticalityLevel = 4
                                        }
                                        # Service-Principal-Name = 4
                                        "f3a64788-5306-11d1-a9c5-0000f80367c1"
                                        {
                                            $intCriticalityLevel = 4
                                        }
                                        #  Is-Member-Of-DL = 4
                                        "bf967991-0de6-11d0-a285-00aa003049e2"
                                        {
                                            $intCriticalityLevel = 4
                                        }
                                        default
                                        {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                }
                                default
                                {
                                    $intCriticalityLevel = 3
                                }
                            }
                               
                        }
                        default
                        {

                        }
                    }#End switch
   
                }
    	        default
    	        {
                    $intCriticalityLevel = 3
                }
            }#End switch
        }#End if Allow
    }
    {($_ -match "WriteDacl") -or ($_ -match "WriteOwner")}
    {
        $intCriticalityLevel = 4
    }
    default
    {
        If ($objAccess -eq "Allow")
        {
            if($objRights -match "Write")
            {
                $intCriticalityLevel = 2
            }         
            if($objRights -match "Create")
            {
                $intCriticalityLevel = 3
            }        
            if($objRights -match "Delete")
            {
                $intCriticalityLevel = 3
            }
            if($objRights -match "ExtendedRight")
            {
                $intCriticalityLevel = 3
            }             
            if($objRights -match "WriteDacl")
            {
                $intCriticalityLevel = 4
            }
            if($objRights -match "WriteOwner")
            {
                $intCriticalityLevel = 4
            }       
        }     
    }
}# End Switch

Switch ($intCriticalityLevel)
        {
            0 {$strLegendText = "Info";$strLegendColor = "DarkCyan"}
            1 {$strLegendText = "Low";$strLegendColor = "DarkGreen"}
            2 {$strLegendText = "Medium";$strLegendColor = "Gray"}
            3 {$strLegendText = "Warning";$strLegendColor = "DarkYellow"}
            4 {$strLegendText = "Critical";$strLegendColor = "Red"}
        }

$Object = @{
            Legende = $strLegendText
            Color = $strLegendColor
            }

return $Object

}

#==========================================================================
# Function		: Get-Rights
# Arguments     : $objRights,$objAccess,$objFlags,$objInheritanceType
# Returns   	: Integer
# Description   : Check criticality and returns number for rating
#==========================================================================

Function get-rights ($objRights,$objInheritanceType,$objFlags) {

Switch ($objRights)
    {
        "Self"
        {
            #Self right are never express in gui it's a validated write ( 0x00000008 ACTRL_DS_SELF)

                $objRights = ""
        }
        "GenericRead"
        {
                $objRights = "Read Permissions,List Contents,Read All Properties,List"
        }
        "CreateChild"
        {
                $objRights = "Create"	
        }
        "DeleteChild"
        {
            $objRights = "Delete"		
        }
        "GenericAll"
        {
            $objRights = "Full Control"		
        }
        "CreateChild, DeleteChild"
        {
            $objRights = "Create/Delete"		
        }
        "ReadProperty"
        {
            Switch ($objInheritanceType) 
    	    {
    	 	    "None"
    	 	    {
                     
                    Switch ($objFlags)
    	    	    { 
    		      	    "ObjectAceTypePresent"
                        {
                            $objRights = "Read"	
                        }
    		      	    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $objRights = "Read"	
                        }
                        default
    	 	            {$objRights = "Read All Properties"	}
                    }#End switch
                }
                    "Children"
    	 	    {
                     
                    Switch ($objFlags)
    	    	    { 
    		      	    "ObjectAceTypePresent"
                        {
                            $objRights = "Read"	
                        }
    		      	    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $objRights = "Read"	
                        }
                        default
    	 	            {$objRights = "Read All Properties"	}
                    }#End switch
                }
                "Descendents"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                        $objRights = "Read"	
                        }
                       	                
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                        $objRights = "Read"	
                        }
                        default
                        {$objRights = "Read All Properties"	}
                    }#End switch
                }
                default
                {$objRights = "Read All Properties"	}
            }#End switch
        }
        "ReadProperty, WriteProperty" 
        {
            $objRights = "Read All Properties;Write All Properties"			
        }
        "WriteProperty" 
        {
            Switch ($objInheritanceType) 
    	    {
    	 	    "None"
    	 	    {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            $objRights = "Write"	
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $objRights = "Write"	
                        }
                        default
                        {
                            $objRights = "Write All Properties"	
                        }
                    }#End switch
                }
                "Children"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            $objRights = "Write"	
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $objRights = "Write"	
                        }
                        default
                        {
                            $objRights = "Write All Properties"	
                        }
                    }#End switch
                }
                "Descendents"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            $objRights = "Write"	
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $objRights = "Write"	
                        }
                        default
                        {
                            $objRights = "Write All Properties"	
                        }
                    }#End switch
                }
                default
                {
                    $objRights = "Write All Properties"
                }
            }#End switch		
        }
        default
        {
  
        }
    }# End Switch  

    return $objRights
    } 

#==========================================================================
# Function		: ShowResult
# Arguments     : $AdObject
# Returns   	: Message final
# Description   : Check ACE, and return results
#==========================================================================

 function ShowResult {
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [psobject]$AdObject
    )

     Process {
        
        (Get-Acl -Path $AdObject).Access  | ? $conditions | ForEach-Object {
                
                $z = Get-Criticality $_.ActiveDirectoryRights $_.AccessControlType $_.ObjectFlags $_.InheritanceType $_.ObjectType $_.InheritedObjectType

                $r = get-rights $_.ActiveDirectoryRights $_.InheritanceType $_.ObjectFlags
                
                $y = (getGuid $_.InheritedObjectType )

                if ($y -eq 'ALL') { $y = $null }


                Write-Host $z.legende : $_.IdentityReference a $r sur : (getGuid $_.ObjectType) $y -ForegroundColor $z.color

            }

            Write-Host `r`n
        }

}

#endregion Fonctions

#==========================================================================
# Bloc		: Search on domain ROOT
#==========================================================================

 Write-Host $domain -ForegroundColor Yellow

 ShowResult $domain
 
#==========================================================================
# Action	: Search on ALL OU 'Onlevel or substree'
#==========================================================================

 (Get-ADOrganizationalUnit -SearchBase $domain -Filter * -SearchScope $levelsearch).DistinguishedName | ForEach-Object {

 Write-Host $_ -ForegroundColor Yellow
 
 ShowResult $_

 }

#==========================================================================
# Function		: Search on ALL Container 
#==========================================================================


(Get-ChildItem $domain  | ? {$_.objectClass -eq "container" -or $_.objectclass -eq "builtinDomain"}).distinguishedname | ForEach-Object {

Write-Host $_ -ForegroundColor Yellow

ShowResult $_

}

if ($searchGPO -eq 'true') {
#==========================================================================
# Function		: Search ACE on GPO ROOT Domain
#==========================================================================
 
 Write-Host $domain -ForegroundColor Yellow

 (Get-GPInheritance -Target $domain).GpoLinks | ForEach-Object {
 
 Write-Host GPO :  $_.DisplayName

 ShowResult (get-gpo $_.DisplayName).Path

} 

#==========================================================================
# Function		: Search ACE on GPO ALL OU 
#==========================================================================  
 
 (Get-ADOrganizationalUnit -SearchBase $domain -Filter * -SearchScope $levelsearch) | ForEach-Object {

Write-Host $_.DistinguishedName -ForegroundColor Yellow

$_.LinkedGroupPolicyObjects | ForEach-Object {

Write-Host GPO : (Get-GPO -Guid $_.Substring(4,36)).displayname 

 ShowResult $_

 }
}

}

Pop-Location
