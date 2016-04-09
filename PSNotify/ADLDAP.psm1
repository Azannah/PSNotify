#
# ADLDAP.psm1
#

function Test-Certificate {
<#
.Synopsis
	Tests specified certificate for certificate chain and revocation
.Description
	Tests specified certificate for certificate chain and revocation status for each certificate in chain
	exluding Root certificates
.Parameter Certificate
	Specifies the certificate to test certificate chain. This parameter may accept
	X509Certificate, X509Certificate2 objects or physical file path. this paramter accept
	pipeline input
.Parameter Password
	Specifies PFX file password. Password must be passed as SecureString.
.Parameter CRLMode
	Sets revocation check mode. May contain on of the following values:
	
	Online - perform revocation check downloading CRL from CDP extension ignoring cached CRLs. Default value
	Offline - perform revocation check using cached CRLs if they are already downloaded
	NoCheck - specified certificate will not checked for revocation status (not recommended)
.Parameter CRLFlag
	Sets revocation flags for chain elements. May contain one of the following values:
	
	ExcludeRoot - perform revocation check for each certificate in chain exluding root. Default value
	EntireChain - perform revocation check for each certificate in chain including root. (not recommended)
	EndCertificateOnly - perform revocation check for specified certificate only.
.Parameter VerificationFlags
	Sets verification checks that will bypassed performed during certificate chaining engine
	check. You may specify one of the following values:
	
	NoFlag - No flags pertaining to verification are included (default).
	IgnoreNotTimeValid - Ignore certificates in the chain that are not valid either because they have expired or they
		are not yet	in effect when determining certificate validity.
	IgnoreCtlNotTimeValid - Ignore that the certificate trust list (CTL) is not valid, for reasons such as the CTL
		has expired, when determining certificate verification.
	IgnoreNotTimeNested - Ignore that the CA (certificate authority) certificate and the issued certificate have
		validity periods that are not nested when verifying the certificate. For example, the CA cert can be valid
		from January 1 to December 1 and the issued certificate from January 2 to December 2, which would mean the
		validity periods are not nested.
	IgnoreInvalidBasicConstraints - Ignore that the basic constraints are not valid when determining certificate
		verification.
	AllowUnknownCertificateAuthority - Ignore that the chain cannot be verified due to an unknown certificate
		authority (CA).
	IgnoreWrongUsage - Ignore that the certificate was not issued for the current use when determining
		certificate verification.
	IgnoreInvalidName - Ignore that the certificate has an invalid name when determining certificate verification.
	IgnoreInvalidPolicy - Ignore that the certificate has invalid policy when determining certificate verification.
	IgnoreEndRevocationUnknown - Ignore that the end certificate (the user certificate) revocation is unknown when
		determining	certificate verification.
	IgnoreCtlSignerRevocationUnknown - Ignore that the certificate trust list (CTL) signer revocation is unknown
		when determining certificate verification.
	IgnoreCertificateAuthorityRevocationUnknown - Ignore that the certificate authority revocation is unknown 
		when determining certificate verification.
	IgnoreRootRevocationUnknown - Ignore that the root revocation is unknown when determining certificate verification.
	AllFlags - All flags pertaining to verification are included.	
.Example
	Get-ChilItem cert:\CurrentUser\My | Test-Certificate -CRLMode "NoCheck"
	
	Will check certificate chain for each certificate in current user Personal container.
	Certificates will not checked for revocation status.
.Example
	Test-Certificate C:\Certs\certificate.cer -CRLFlag "EndCertificateOnly"
	
	Will check certificate chain for certificate that is located in C:\Certs and named
	as Certificate.cer and revocation checking will be performed for specified certificate only
.Outputs
	This script return general info about certificate chain status
.Notes
  Based on a script of the same name by Vadims Podans
  http://www.sysadmins.lv/
#>
  [CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		$Certificate,
		[System.Security.SecureString]$Password,
		[System.Security.Cryptography.X509Certificates.X509RevocationMode]$CRLMode = "Online",
		[System.Security.Cryptography.X509Certificates.X509RevocationFlag]$CRLFlag = "ExcludeRoot",
		[System.Security.Cryptography.X509Certificates.X509VerificationFlags]$VerificationFlags = "NoFlag"
	)
	
	begin {
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
		$chain.ChainPolicy.RevocationFlag = $CRLFlag
		$chain.ChainPolicy.RevocationMode = $CRLMode
		$chain.ChainPolicy.VerificationFlags = $VerificationFlags
		function _getstatus_ ($status, $chain, $cert) {
			if ($status) {
				Write-Host "Current certificate $($cert.SerialNumber) chain and revocation status is valid" -ForegroundColor Green
			} else {
				Write-Warning "Current certificate $($cert.SerialNumber) chain is invalid due of the following errors:"
				$chain.ChainStatus | %{Write-Host $_.StatusInformation.trim() -ForegroundColor Red}
			}
      Write-Output $status
		}
	}
	
	process {
		if ($_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
			$status = $chain.Build($_)
			_getstatus_ $status $chain $_
		} else {
			if (!(Test-Path $Certificate)) {Write-Warning "Specified path is invalid"; return}
			else {
				if ((Resolve-Path $Certificate).Provider.Name -ne "FileSystem") {
					Write-Warning "Spicifed path is not recognized as filesystem path. Try again"; return
				} else {
					$Certificate = gi $(Resolve-Path $Certificate)
					switch -regex ($Certificate.Extension) {
					"\.CER|\.DER|\.CRT" {$cert.Import($Certificate.FullName)}
					"\.PFX" {
						if (!$Password) {$Password = Read-Host "Enter password for PFX file $certificate" -AsSecureString}
							$cert.Import($Certificate.FullName, $password, "UserKeySet")
						}
					"\.P7B|\.SST" {
						$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
						$cert.Import([System.IO.File]::ReadAllBytes($Certificate.FullName))
						}
					default {Write-Warning "Looks like your specified file is not a certificate file"; return}
					}
					$cert | %{
						$status = $chain.Build($_)
						_getstatus_ $status $chain $_
					}
					$cert.Reset()
					$chain.Reset()
				}
			}
		}
	}
}

function Get-ADLDAPGroupMember {
  [CmdletBinding()]
    Param(
      [Parameter(
        HelpMessage="Identity of the target AD group",
        Mandatory=$true,
        #ParameterSetName="remote",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [string]
      <#
        Specifies an Active Directory group object by providing one of the following values. The identifier in parentheses is the LDAP display name for the attribute.

        Distinguished Name

        Example: CN=saradavisreports,OU=europe,CN=users,DC=corp,DC=contoso,DC=com

        GUID (objectGUID)

        Example: 599c3d2e-f72d-4d20-8a88-030d99495f20

        Security Identifier (objectSid)

        Example: S-1-5-21-3165297888-301567370-576410423-1103

        Security Accounts Manager (SAM) Account Name (sAMAccountName)

        Example: saradavisreports

        The cmdlet searches the default naming context or partition to find the object. If two or more objects are found, the cmdlet returns a non-terminating error.

        This parameter can also get this object through the pipeline or you can set this parameter to an object instance.

        This example shows how to set the parameter to a distinguished name.

        -Identity  "CN=saradavisreports,OU=europe,CN=users,DC=corp,DC=contoso,DC=com"
      #>
      $Identity,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$false,
        #ParameterSetName="remote",
        #Position=0,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [string[]]
      $Attributes,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$false,
        #ParameterSetName="remote",
        #Position=0,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [string]
      $SearchBase,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$true,
        #ParameterSetName="remote",
        Position=1,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$false,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [string]
      $Server,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$false,
        #ParameterSetName="remote",
        #Position=0,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$false,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [int]
      $Port,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$false,
        #ParameterSetName="remote",
        Position=2,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [switch]
      $Recursive = $false,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$false,
        #ParameterSetName="remote",
        Position=3,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [switch]
      $Secure = $false,
      [Parameter(
        #HelpMessage="Identity of the target AD group",
        Mandatory=$false,
        #ParameterSetName="remote",
        Position=4,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$false,
        ValueFromRemainingArguments=$false)]
      #[Alias('Target')]
      [pscredential]
      $Credentials = $null
    )

    Begin {
      Add-Type -AssemblyName System.DirectoryServices.Protocols

      if ($Port -eq 0) {
        if ($Secure) {
          #Default, non-global catalog, secure LDAP port (default LDAPS GC port is 3269)
          $Port = 636
        } else {
          #Default, non-global catalog LDAP port (default LDAP GC port is 3268)
          $Port = 389
        }
      }

      $connection = bind_ldap_connection $Server $Port $Secure $Credentials
      $root_context = Script:get_root_context $connection

      function Script:bind_ldap_connection([string]$ldap_server, [string]$ldap_port, [bool]$ldap_secure, [pscredential]$ldap_credentials) {
        [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier $ldap_server, $ldap_port

        if ($Credentials -eq $null) {
          # Attempt kerberos authentication if no credentials are supplied
          [System.DirectoryServices.Protocols.LdapConnection]$connection = New-Object System.DirectoryServices.Protocols.LdapConnection $identifier
          $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Kerberos
        } else {
          # Otherwise, use basic authentication
          [System.DirectoryServices.Protocols.LdapConnection]$connection = New-Object System.DirectoryServices.Protocols.LdapConnection $identifier, $ldap_credentials.GetNetworkCredential()
          $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        }

        if ($ldap_secure) {
          $connection.SessionOptions.SecureSocketLayer = $true
          $connection.SessionOptions.VerifyServerCertificate = {
            Param(
              [System.DirectoryServices.Protocols.LdapConnection]$connection,
              [System.Security.Cryptography.X509Certificates.X509Certificate2]$connection_certificate
            )

            # 2do: This method does not check to see if the subject of the certificate matches the server queried
            # 2do: test a failed match
            return ($connection_certificate | Test-Certificate -CRLMode NoCheck)
          }
        }

        $connection.Bind()
        
        return $connection
      }

      function Script:get_identity_type($identity_string) {
        $search_attribute = "sAMAccountName"
        switch -Regex ($identity_string) {
          "^\w{2}=" { $search_attribute = "dn"; break }
          "^S-\d[\d-]+$" { $search_attribute = "objectSid"; break }
          "^[a-fA-F0-9\-]*$" { $search_attribute = "objectGUID"; break }
        }
        
        return $search_attribute
      }

      function Script:get_root_context($connection) {
        return (Script:query_ldap $connection  $null "(&(objectClass=*))" "Base" "rootdomainnamingcontext").Entries[0].Attributes["rootdomainnamingcontext"][0]
      }

      function Script:query_ldap($connection, $target, $search_filter, $search_scope, [string[]]$attributes) {
        # Reference: https://msdn.microsoft.com/en-us/library/bb332056.aspx
        $search_request = New-Object System.DirectoryServices.Protocols.SearchRequest $target, $search_filter, $search_scope, $attributes

        try {
          $search_response = [System.DirectoryServices.Protocols.SearchResponse] $connection.SendRequest($search_request)
        } catch {
          # log
          throw $_
        }
        return $search_response
      }
    }

    Process {
      <#if ($Port -eq 0) {
        if ($Secure) {
          #Default, non-global catalog, secure LDAP port (default LDAPS GC port is 3269)
          $Port = 636
        } else {
          #Default, non-global catalog LDAP port (default LDAP GC port is 3268)
          $Port = 389
        }
      }

      $connection = bind_ldap_connection $Server $Port $Secure $Credentials
      $root_context = Script:get_root_context $connection#>

      if ($SearchBase.Length -eq 0) {
        $SearchBase = $root_context
      }

      if ($Recursive) {
        $search_scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
      } else {
        $search_scope = [System.DirectoryServices.Protocols.SearchScope]::Base
      }

      $identity_type = Script:get_identity_type $Identity
      
      if ($identity_type -notlike "dn") {
        $query_results = Script:query_ldap $connection $root_context "($identity_type=$Identity)" "Subtree" $null
        #$query_results = Script:query_ldap $connection $SearchBase "($identity_type=$Identity)" "Subtree" $null
        #$query_results = Script:query_ldap $connection (Script:get_root_context $connection) "($identity_type=$Identity)" "Subtree" $null
        
        # All possible Identity values represent a unique object, so only one result should be returned
        # 2do: Validate inputs to eliminate wildcards in the parameters.
        $Identity = $query_results.Entries[0].DistinguishedName
      }

      # Now that we have the DN, get all entries that belong to the group, including nested membershipship, within the SearchBase
      #$query_results = Script:query_ldap $connection $SearchBase "(memberOf:1.2.840.113556.1.4.1941:=$Identity)" "Subtree" $null
      $query_results = Script:query_ldap $connection $SearchBase "(memberOf:1.2.840.113556.1.4.1941:=$Identity)" $search_scope $Attributes

      # Compile results into something like what you'd get from Get-ADGroupMember
      $return_objects = @()

      $query_results.Entries | % {
        $attributes_hash = @{}
        $directory_attributes = $_.Attributes

        $directory_attributes.Keys | % {
          if ($directory_attributes.Item($_).Count -gt 1) {
            $key = $_
            $attributes_hash[$key] = @()

            0..($directory_attributes.Item($_).Count - 1)| %{ $attributes_hash[$key] += $directory_attributes.Item($key)[$_] }
          } else {
            $attributes_hash[$_] = $directory_attributes.Item($_)[0]
          }
        }
        $return_objects += $attributes_hash
      }

      return $return_objects
    }

}

Export-ModuleMember -Function @(
  "Get-ADLDAPGroupMember"
)