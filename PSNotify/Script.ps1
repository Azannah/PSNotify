#
# Script.ps1
#
Set-StrictMode -Version Latest

function Script:Load-Assembly {
<#
.SYNOPSIS
Loads the specified assembly into the current application domain after checking to make sure the assembly isn't already loaded (based on file name). If the 
assembly is already loaded, the function will exit without re-loading the assembly.

.DESCRIPTION
Loads the specified assembly into the current application domain after checking to make sure the assembly isn't already loaded (based on file name). If the 
assembly is already loaded, the function will exit without re-loading the assembly to avoid conflicts.

Reference:
https://msdn.microsoft.com/en-us/library/dd153782(v=vs.110).aspx#avoid_loading_multiple_versions

.EXAMPLE
The following example loads a DLL file from specified path:

Script:Load-Assembly -Path "C:\Program Files\My Application\mylibrary.subnamespace.dll"

.EXAMPLE
This example accepts System.IO.FileInfo objects from the pipe and attempts to load them as assemblies:

Get-ChildItem -Filter *.dll | Script:Load-Assembly

.INPUTS
This function accepts string objects as well as any object that defines a FullName property that can be cast as a string (System.IO.FileInfo, for example)

.OUTPUTS
When PassThru is specified, returns a handle Runtime object that represents the types defined in the assembly

.NOTES
Author: Matthew Johnson
Requires: Powershell 2

Development notes:
Okay, this function might not even be needed. The only case in which it makes sense is when multiple functions in a script inadvertently load different versions of the same assembly.

Can the same version of an assembly be loaded multiple times from different paths?

It might be better to simply make the Private:Test-Assembly available to all script functions...

.LINK
https://msdn.microsoft.com/en-us/library/dd153782(v=vs.110).aspx#avoid_loading_multiple_versions

#>
  [CmdletBinding()]
  Param(
    [Parameter(
      HelpMessage="Provide the full path and name of the assembly to load",
      Mandatory=$true,
      #ParameterSetName="embedded",
      Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [Alias('FullName')]
    [string]
    # The full path and name of the assembly to load (eg., "C:\Program Files\My Application\mylibrary.subnamespace.dll")
    $Path,
    [Switch]
    $PassThru = $false
  )

  begin {
    # Get assemblies loaded into the current app domain
    $assemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    # Check's to see if the assembly is alrady loadded into the app domain
    function Private:Test-Assembly ([string]$name) {
      if (@($assemblies | ?{$_.Location -match "$name`$"}).Count -gt 0) {
        return $true
      }
      return $false
    }
  }

  process {
    if (-not (Test-Path $Path)) {
      throw [System.IO.FileNotFoundException] "$Path not found"
      break;
    }

    $file_name = $Path.Split("\")[-1]

    if (-not (Private:Test-Assembly $file_name)) {
      try {
        Add-Type -Path $Path -ErrorAction Stop -PassThru:$PassThru
      } catch {
        # Log
        throw $_
      }
    }
  }
}

function Script:Write-EmbeddedResource {
  [CmdletBinding()]  
  Param(
    [Parameter(
      HelpMessage="Provide a file name for the embedded resource",
      Mandatory=$true,
      #ParameterSetName="embedded",
      Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Specifies a file name to use when the embedded resource is written to disk.
    $Name,
    [Parameter(
      HelpMessage="A string containing the base64 encoded resource",
      Mandatory=$true,
      #ParameterSetName="embedded",
      Position=1,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # The embedded resource stored as a base64 string.
    $Base64,
    [Parameter(
      HelpMessage="Specify a folder path where the resource should be created on disk",
      Mandatory=$false,
      #ParameterSetName="embedded",
      Position=2,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # A path to the location where the embedded resource will be written to disk. Defaults to the Temp folder if not specified.
    $Path = $env:TEMP
  )

  process {
    if (-not (Test-Path $Path)) {
      throw [System.IO.DirectoryNotFoundException] "$Path not found"
      break;
    }

    $Name = ($Path -replace "\\$", "") + "\$Name"

    # 2do: need to handle pre-existing files better - existing file might be different version of DLL
    if (-not (Test-Path $Name)) {
      try {
        Set-Content -Path $Name -Value ([System.Convert]::FromBase64String($Base64)) -Encoding Byte
        return (Get-ChildItem $Name)
      } catch {
        # Need to log error
        throw $_
      }
    }

    # 2do: Make sure "throw" halts the script so this doesn't get executed if Set-Content fails.
    return (Get-ChildItem $Name)
  }
}

# 2do: formalize this function. For example, it needs a lot of error handling...
function Decompress-GZipItem{
  Param(
    $Infile,
    $Outfile = ($infile -replace '\.gz$','')
  )

  $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
  $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
  $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)

  $buffer = New-Object byte[](1024)
  
  while($true){
    $read = $gzipstream.Read($buffer, 0, 1024)
    
    if ($read -le 0) {break}
    
    $output.Write($buffer, 0, $read)
  }

  $gzipStream.Close()
  $output.Close()
  $input.Close()
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

function Get-EmailConnector {
# Perhaps eventually it would be best to use more general SMTP client classes https://msdn.microsoft.com/en-us/library/x5x13z6h(v=vs.110).aspx?cs-save-lang=1&cs-lang=csharp#code-snippet-1
  [CmdletBinding()]
  Param(
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$true,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [string]
    # The name of the SMTP server that will proxy email notification
    $SmtpServer,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [switch]
    # Specify if the SMTP connection should be secured using SSL
    $UseSsl,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$true,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [pscredential]
    # The name of the SMTP server that will proxy email notification
    $Credential
  )

  Begin {

  }

  Process {
    return New-Module {
      Param(
        [string]$SmtpServer,
        [switch]$UseSsl, 
        [pscredential]$Credential
      )

      function Send {
        Param(
          [psobject]$email_notification,
          [string[]]$recipient
        )

        $recipient_list = $recipient | % {
          try {
            return [System.Net.Mail.MailAddress] $_
          } catch {
            # 2do: Log
            Out-Null
          }
        }

        $recipient_list | % {
          if ($email_notification.Attachments -eq $null) {
            Send-MailMessage -To $_.ToString() `
                             -From $email_notification.Originator.ToString() `
                             -Subject $email_notification.Subject `
                             -Body $email_notification.Message `
                             -Priority $email_notification.Priority `
                             -Encoding $email_notification.Encoding `
                             -BodyAsHtml:$email_notification.MessageAsHtml `
                             -SmtpServer $SmtpServer `
                             -UseSsl:$UseSsl `
                             -Credential $Credential
          } else {
            Send-MailMessage -To $_.ToString() `
                             -From $email_notification.Originator.ToString() `
                             -Subject $email_notification.Subject `
                             -Body $email_notification.Message `
                             -Attachments $email_notification.Attachments `
                             -Priority $email_notification.Priority `
                             -Encoding $email_notification.Encoding `
                             -BodyAsHtml:$email_notification.MessageAsHtml `
                             -SmtpServer $SmtpServer `
                             -UseSsl:$UseSsl `
                             -Credential $Credential
          }
        }
      }

      Export-ModuleMember -Function "Send"
    } -AsCustomObject -ArgumentList $SmtpServer, $UseSsl, $Credential
  }

  End {

  }
}

function Get-GrowlConnector {
  [CmdletBinding(DefaultParameterSetName="local")]
  Param(
    [Parameter(
      HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$true,
      ParameterSetName="remote",
      Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [Alias('Target')]
    [string]
    # The short or fully qualified name of a remote computer
    $Computer,
    [Parameter(
      HelpMessage="Specify the a Growl password pre-defined on the remote system",
      Mandatory=$true,
      ParameterSetName="remote",
      Position=1,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # The Growl password pre-defined on the remote system
    $Password,
    [Parameter(
      HelpMessage="Provide the port Growl is listening on at the remote host (default is 23053)",
      Mandatory=$false,
      ParameterSetName="remote",
      Position=2,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [int]
    # The port Growl is listening on at the remote host. Defaults to 23053 if not specified.
    $Port = 23053
  )

  process {
    
    try {
      if ($PSCmdlet.ParameterSetName -eq "local") {
        $growl_connector = new-object "Growl.Connector.GrowlConnector"
      } else {
        $growl_connector = new-object "Growl.Connector.GrowlConnector" $Password, $Computer, $Port
      }
    } catch {
      # Log error
      throw $_
    }

    $custom_object = New-Module {
      Param(
        [Growl.Connector.GrowlConnector]$growl_connector
      )

      function Script:create_application ($application_name, $application_icon = $null) {
        $application = New-Object "Growl.Connector.Application" $application_name
        
        if (-not [string]::IsNullOrWhiteSpace($application_icon)) {
          $application.Icon = $application_icon
        }

        return $application
      }

      function Script:create_type ($type_id, $type_desc, $type_icon) {
        $type = New-Object "Growl.Connector.NotificationType" $type_id, $type_desc
        
        if (-not [string]::IsNullOrWhiteSpace($type_icon)) {
          $type.Icon = $type_icon
        }

        return $type
      }

      function Script:register_application($application, [Growl.Connector.NotificationType[]]$types) {
        $growl_connector.Register($application, $types)
      }

      function AddCallbackHandler ([scriptblock]$handler) {
        <#
          Example:
            $callback_handler = {
              Param($response, $context)
              Write-Host "Response:`n$response"
              Write-Host "`nContext:`n$($context|fl *)"
            }
        #>
        Register-ObjectEvent -InputObject $growl_connector -EventName NotificationCallback -Action $handler
      }
      
      function Notify ([psobject]$notification) {
        Script:register_application `
          (Script:create_application $notification.ApplicationName $notification.ApplicationIcon) `
          @(Script:create_type $notification.Name $notification.NotificationTypeDescription $notification.NotificationTypeIcon)

        if($notification.Context -eq $null) {
          $growl_connector.Notify($notification)
        } else {
          $growl_connector.Notify($notification, $notification.Context)
        }
      }

      Export-ModuleMember -Function "Notify", "AddCallbackHandler"
    } -AsCustomObject -ArgumentList $growl_connector

    return $custom_object
  }

}

function Merge-Tokens {
<#
.SYNOPSIS
Replaces tokens in a block of text with a specified value.
.DESCRIPTION
Replaces tokens in a block of text with a specified value.
.PARAMETER template
The block of text that contains text and tokens to be replaced.
.PARAMETER tokens
Token name/value hashtable.
.EXAMPLE
 $content = Get-Content .\template.txt | Merge-Tokens -tokens @{FirstName: 'foo'; LastName: 'bar'}
Pass template to function via pipeline.
.NOTES
  Original source: https://github.com/craibuc/PsTokens/blob/master/Merge-Tokens.ps1
#>

    [CmdletBinding()] 
    
    param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [String] $Template,

        [Parameter(Mandatory=$true)]
        [HashTable] $Tokens
    ) 

    begin {
      Write-Verbose "$($MyInvocation.MyCommand.Name)::Begin"

      function Script:is_iterable_token($token) {
        #if ($match.Value -match "^\s*{{\s*@?") {
        if ($token -match "^[{]{2}") {
          $count = 2 # The input token is wrapped: {{token_name remainder {{inside stuff}}}}
        } else {
          $count = 1 # The input token had been unwrapped: remainder {{inside stuff}}
        }

        if ([RegEx]::Matches($token, "[{]{2}").Count -ge $count) {
          return $true
        }
        return $false
      }

      function Script:unwrap_token($token) {
        $token_name = Script:get_token_name $token
        $regex_string = "^\s*{{\s*@?$token_name(?<remainder>.*)}}$"
        return [RegEx]::Match($token, $regex_string, "Singleline").Groups['remainder'].Value
      }

      function Script:get_token_name($token) {
        return [RegEx]::Match($token, "^\s*{{\s*@?(?<token_name>([^\s}{]|(?<d>[}{])(?!\k<d>))+)").Groups['token_name'].Value
      }
    }

    process {
      Write-Verbose "$($MyInvocation.MyCommand.Name)::Process" 

      # adapted based on this Stackoverflow answer: http://stackoverflow.com/a/29041580/134367
      <#
      [regex]::Replace( $template, '{{(?<tokenName>[\w\.]+)}}', {
        # {{TOKEN}}
        param($match)

        $tokenName = $match.Groups['tokenName'].Value
        Write-Debug $tokenName
              
        $tokenValue = Invoke-Expression "`$tokens.$tokenName"
        Write-Debug $tokenValue

        if ($tokenValue) {
          # there was a value; return it
          return $tokenValue
        } 
        else {
          # non-matching token; return token
          return $match
        }
      })
      #>

      # 2do: this breaks if tokens aren't seperated by white space (e.g. {{test}}{{test2}} doesn't work)
      [regex]::Replace( $template, "(((?<Open>\{{2})([^}{]|(?<![}{])[}{](?![}{]))*)+((?<Close-Open>\}{2})(?(Open)([^}{]|(?<![}{])[}{](?![}{])))*)+)+(?(Open)(?!))", {
        Param($match)

        $token_name = Script:get_token_name $match.Value

        if (-not $Tokens.ContainsKey($token_name)) {
          # Token doesn't exist in the provided hashtable of tokens. Return an empty string
          #return $match.Value
          return ""
        }

        $replacement_string = ""
        $token_remainder = Script:unwrap_token $match.Value

        $Tokens[$token_name] | % {
          $token_value = $_
                
          # If we're looking at a recurring pattern, recurse
          if (Script:is_iterable_token $match.Value) {
            $token_value | % {
              # Validate the input type - the only valid input is a hashtable
              if (-not ($_.GetType() -eq [hashtable])) {
                # It might be more useful to receive a message with unmatched tokens, instead of no message at all
                #throw [System.ArgumentException] "The provided input for $token_name should be a hashtable, but is of type $($_.GetType().Name)"
                # 2do: log
                return $match.Value
              }

              # Recurse by calling self
              Merge-Tokens -tokens $_ -template $token_remainder 
            } | % { $replacement_string += $_ }
                
          # If the pattern we're looking is not recurring...
          } else {
            $token_value | % { 
              # Should be a single-valued object (not an array or a collection)
              if ($_.GetType().FullName -Match "collection|array|\[\]") {
                # Here again, it might be more useful to receive a message with unmatched tokens, instead of no message at all
                # 2do: log
                return $match.Value
              }

              $replacement_string += ($_ + $token_remainder) 
            }
          }
        }

        return $replacement_string
      })
    }

    end { Write-Verbose "$($MyInvocation.MyCommand.Name)::End" }

}

function New-Notification {
  [CmdletBinding(DefaultParameterSetName='SearchTemplate')]
  Param(
    [Parameter(
      #HelpMessage="",
      Mandatory=$false,
      #ParameterSetName="",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string[]]
    # A string indicating the application to which a notification is relavant (Splunk, My Folder Monitor, etc.)
    $TemplateSearchPath = @("$($MyInvocation.PSScriptRoot)\templates", "$($MyInvocation.PSScriptRoot)"),
    [Parameter(
      #HelpMessage="",
      Mandatory=$false,
      ParameterSetName="SearchTemplate",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # A string indicating the application to which a notification is relavant (Splunk, My Folder Monitor, etc.)
    $TemplateFilter = "*default*",
    [Parameter(
      #HelpMessage="",
      Mandatory=$false,
      ParameterSetName="SearchTemplate",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [scriptblock]
    <#
      A ForEach-Object compatible [scriptblock] that, given a PowerShell [FileInfo] object, returns a
      [string] identifier representing a variant.
      
      Example:
      -VariantMappingFunction = {
        $_ -match "^.+_(?<variant>\w+)\.\w+$" | Out-Null; 
        if ([string]::IsNullOrEmpty($Matches['variant'])) { return 'default' } else { return $Matches['variant'] }  ;
      }

      The default variant mapping function looks for template files in the following format:

      file name part_variant.extension, where variant is case insensitive

      Note: If no defaults are defined for 'variant' and 'format', the first of each identifier encountered, or the last template
      discovered will become the de-facto 'default'. If no templates are discovered, default templates are used. Default 
      templates are 'text' formatted and have 'brief', 'standard', and 'detailed' variants.
    #>
    #$VariantMappingFunction = @{ default = { -not $PSItem } },
    $VariantMappingFunction = {
      $_.Name -match "^.+_(?<variant>\w+)\.\w+$" | Out-Null; 
      if ([string]::IsNullOrEmpty($Matches['variant'])) { return 'default' } else { return $Matches['variant'] }  ;
    },
    [Parameter(
      #HelpMessage="",
      Mandatory=$false,
      ParameterSetName="SearchTemplate",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [scriptblock]
    <#

    #>
    $FormatMappingFunction = {
      #$_ -match "^.+\.(?<extension>\w+)$" | Out-Null; 
      #switch ($Matches['extension']) {
      switch ($_.Extension) {
        {$_ -in ".htm",".html"} { return 'html' }
        {$_ -in ".txt",".text"} { return 'text' }
        default { return 'default' }
      }
    },
    [Parameter(
      #HelpMessage="",
      Mandatory=$true,
      ParameterSetName="ExplicitTemplate",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [hashtable[]]
    <# 
      An array of hashtables defining 'variant', 'format', 'template'. For example:
      
      @(
        @{
          variant = 'brief'; format = 'text';
          template = "C:\templates\this is a template.txt"
        },
        @{
          variant = 'default'; format = 'text';
          template = $file_info_object
        },
        @{
          variant = 'default'; format = 'text';
          template = "{{title}}`n{{application}} has issued a {{priority}} priority alert!"
        }
      )

      variant := [string]$variant_identifier
      
      format := [string]$format_identifier

      template := [FileInfo]$file_object | [string]$file_path | [string]$template_string

      Note: If no defaults are defined for 'variant' and 'format', the first of each identifier encountered will become the
      de-facto 'default'. If no templates are defined, default templates are used. Default templates are 'text' formatted
      and have 'brief', 'standard', and 'detailed' variants.

      @{ variant = [FileInfo]$file_object | [string]$file_path; ... }
      variant := A descriptor identifying a variant of the notification. Can by anything, but must define
                 at least one of the following 'brief', 'standard', 'detailed', 'default'. If only one
                 variant is defined, it becomes the de-facto default.
    #>
    $TemplateMap,
    [Parameter(
      #HelpMessage="",
      Mandatory=$true,
      #ParameterSetName="",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [hashtable]
    # A string indicating the application to which a notification is relavant (Splunk, My Folder Monitor, etc.)
    $TokenValues
  )

  Begin {
    #$Script:extension_map = @{ html = @("htm", "html"); text = @("txt","text") }

    function Script:get_template_map {
      if ($PSCmdlet.ParameterSetName -eq "SearchTemplate") {
        return Script:get_template_map_search
      }

      return Script:get_template_map_explicit
    }

    function Script:get_template_map_explicit {
      $template_map = @{}

      $TemplateMap | % {
        #2do: handle invalid inputs, such as no 'variant' key in hashtable
        #2do: handle template strings

        if (-not $template_map.ContainsKey($_['variant'])) {
          $template_map[$_['variant']] = @{}
        }

        if (Test-Path $_['template']) {
          $template_map[$_['variant']][$_['format']] = Get-Item $_['template']
        } else {
          # 2do: log and skip
        }
      }
    }

    function Script:get_template_map_search {
      $template_map = @{};
      
      $templates = $TemplateSearchPath | ? {
        Test-Path $_
      } | Get-ChildItem -Filter $TemplateFilter -Recurse -File

      # 2do: handle $templates -eq $null

      $templates | % {
        #$file_extension = $_.Extension
        #$file_name = $_.Name

        $template_variant = $_ | % $VariantMappingFunction
        
        $template_format = $_ | % $FormatMappingFunction


        if (-not $template_map.ContainsKey($template_variant)) {
          $template_map[$template_variant] = @{};
        }

        $template_map[$template_variant][$template_format] = $_
      }

      return $template_map
    }

    <#function Script:read_file_contents {
      Param(
        [string]$file_path
      )

      try {
        return Get-Content -Path $file_path -ErrorAction Stop | Out-String
      } catch {
        # 2do: log
        return = $null
      }
    }#>
  }

  Process {
    $notification = New-Module {
      Param(
        [hashtable]$tokens,
        [hashtable]$template_map
      )

      function Script:read_file_contents {
        Param(
          [string]$file_path
        )

        try {
          return Get-Content -Path $file_path -ErrorAction Stop | Out-String
        } catch {
          # 2do: log
          return = $null
        }
      }

      function GetFormats {
        Param(
          [string]$variant = $null
        )

        if ([string]::IsNullOrEmpty($variant)) {
          return {
            $template_map.Keys | % { $template_map[$_].Keys } | Sort-Object | Get-Unique
          }
        }

        return $template_map[$_].Keys
      }

      function GetNotification {
        Param(
          [string]$variant = "default",
          [string]$format = "default"
        )

        # 2do: handle template_maps that return template strings

        $template_string = Script:read_file_contents $template_map[$variant][$format].FullName

        return Merge-Tokens -Template $template_string -Tokens $tokens
      }

      function GetVariants {
        return $template_map.Keys
      }
      <#function GetText {
        Param(
          [ValidateSet("Brief", "Standard", "Detailed", "Default")]
          [string]$Format
        )
      }

      function GetHTML {
        Param(
          [ValidateSet("Brief", "Standard", "Detailed", "Default")]
          [string]$Format
        )
      }#>
      Export-ModuleMember -Function "GetNotification" -Variable "tokens"
    } -AsCustomObject -ArgumentList $TokenValues, (Script:get_template_map)

    return $notification
  }

  End {

  }
}

function New-EmailNotification {
  #[CmdletBinding(DefaultParameterSetName="standard")]
  [CmdletBinding()]
  Param(
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$true,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [System.Net.Mail.MailAddress]
    # The email addresses from which this notification is sent
    $Originator,
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [string]
    # The subject of the email notification
    $Subject = "",
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$true,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [string]
    # The message to include as the body of the email notification
    $Message,
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [string[]]
    # An optional array of attachments specified as a [string] path to files
    $Attachments,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [ValidateSet("High", "Normal", "Low")]
    [string]
    # Specifies the priority of the e-mail message. The valid values for this are Normal, High, and Low. Normal is the default.
    $Priority = "Normal",
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [ValidateSet("ASCII", "UTF8", "UTF7", "UTF32", "Unicode", "BigEndianUnicode", "Default", "OEM")]
    [string]
    # Specifies the encoding used for the body and subject. Valid values are ASCII, UTF8, UTF7, UTF32, Unicode, BigEndianUnicode, Default, and OEM. ASCII is the default.
    $Encoding = "ASCII",
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [switch]
    # The email addresses from which this notification is sent
    $MessageAsHtml
  )

  Begin {

  }

  Process {
    return New-Module {
      Param(
        [System.Net.Mail.MailAddress]$Originator,
        [string]$Subject, 
        [string]$Message, 
        [string[]]$Attachments,
        [string]$Priority,
        [string]$Encoding,
        [switch]$MessageAsHtml
      )

      Export-ModuleMember -Variable "Originator", "Subject", "Message", "Attachments", "Priority", "Encoding", "MessageAsHtml"
    } -AsCustomObject -ArgumentList $Originator, $Subject, $Message, $Attachments, $Priority, $Encoding, $MessageAsHtml
  }

  End {

  }
}

function New-GrowlNotification {
  #[CmdletBinding(DefaultParameterSetName="standard")]
  [CmdletBinding()]
  Param(
    [Parameter(
      HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$true,
      #ParameterSetName="standard",
      Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [Alias('Application','App')]
    [string]
    # A string indicating the application to which a notification is relavant (Splunk, My Folder Monitor, etc.)
    $ApplicationName,
    [Parameter(
      HelpMessage="Optionally, provide an icon graphic as a file path to identify the application",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=11, # Out of order, I know...
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [Alias('ApplicationNameIcon','AppIcon')]
    [string]
    # Optional. Specify a path to a graphic file that will be used to represent the application. This path is evaluated on the system displaying the notification, so the path must already exist on that system.
    $ApplicationIcon,
    [Parameter(
      HelpMessage="What type of notification is this ('Warning','TaskComplete')?",
      Mandatory=$true,
      #ParameterSetName="standard",
      Position=1,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Each application can have one or more types (specified here as a string without white space). For example ApplicationName = "Splunk", NotificationType = "SystemOffline"
    $NotificationType,
    [Parameter(
      HelpMessage="Optionally, provide a friendly description of the notification type",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=2,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Optional. Provides a friendly description of the NotificationType which is displayed to the notification's recipients. This description is remembered by the host for the specified NotificationType.
    $NotificationTypeDescription,
    [Parameter(
      HelpMessage="Optionally, provide an icon graphic as a file path to identify the notification type",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=12,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Optional. Specify a path to a graphic file that will be used to represent the notification type. If provided, this graphic overrides the ApplicationIcon graphic. This path is evaluated on the system displaying the notification, so the path must already exist on that system.
    $NotificationTypeIcon,
    [Parameter(
      HelpMessage="What should the notification be titled?",
      Mandatory=$false,
      #ParameterSetName="standard",
      Position=3,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Notifications must have a title or heading specified as a plain text string
    $Title,
    [Parameter(
      HelpMessage="What's the message?",
      Mandatory=$true,
      #ParameterSetName="standard",
      Position=4,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # The plain text message of the notification
    $Message,
    [Parameter(
      HelpMessage="Optionally, provide the path to a graphic file to associate with this message",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=14,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Optional. Specify a path to a graphic file that will be displayed with this notification. If provided, this graphic overrides the ApplicationIcon and NotificationTypeIcon graphics. This path is evaluated on the system displaying the notification, so the path must already exist on that system.
    $MessageIcon,
    [Parameter(
      HelpMessage="Specify the notification's priority (Emergency, High, Moderate, Normal, VeryLow)",
      Mandatory=$false,
      #ParameterSetName="standard",
      Position=5,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [ValidateSet("Emergency", "High", "Moderate", "Normal", "VeryLow")]
    [Growl.Connector.Priority]
    # Optional. Defines the notification's priority as either Emergency, High, Moderate, Normal, or VeryLow. Defaults to Normal priority.
    $Priority = [Growl.Connector.Priority]::Normal,
    [Parameter(
      HelpMessage="Optionally, provide an ID that can be used to identify and update this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      Position=6,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Optional. The supplied string becomes an ID that can be used to identify and update the notification after it has been issued with subseqent notifications.
    $NotificationID,
    [Parameter(
      HelpMessage="Provide a string ID used to distinguish callbacks for this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      Position=2,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # An ID specified as a string that's used to identify callbacks for this notification
    $CallbackID = "unspecified",
    [Parameter(
      HelpMessage="What data should be returned by the callback?",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=6,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [Object]
    # Can be an arbitrary type relevant to the callback event handler registered with the GrowlConnector object. Unless modified by the receiving instance of Growl, the callback data defined here is simply returned as-is.
    $CallbackData = $null,
    [Parameter(
      HelpMessage="What's the data type returned by the callback (default 'string')?",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=7,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [Object]
    # The Type does not need to be of a recognized language type – it can be any value that has meaning to the callback event handler. Defaults to "string" when not specified.
    $CallbackDataType = "string",
    [Parameter(
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=8,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [URI]
    # If specified, the CallbackURL supplied as a [URI] castable object is used instead of the callback event handler. No callback data or type is included in the URL query. Any query parameters must be constructed manually.
    $CallbackURL = $null,
    <#[Parameter(
      Mandatory=$false,
      ParameterSetName="standard",
      Position=9,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [string]
    # Specifies the method used by the CallbackURL, POST or GET. Defaults to GET if not specified.
    $CallbackURLMethod = "GET", # 2do: The manual mentions this, but the DLL I have doesn't have the functions described...#>
    [Parameter(
      HelpMessage="Should the message remain on-screen until clicked by the user?",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=10,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    [switch]
    # An ID specified as a string that's used to identify callbacks for this notification
    $Sticky
  )

  Process {
    try {
      $growl_notification = New-Object "Growl.Connector.Notification" $ApplicationName, $NotificationType, $CallbackID, $Title, $Message
    } catch {
      # Log
      throw $_
    }

    if (Test-Path Variable:MessageIcon) {
      $growl_notification.Icon = $MessageIcon
    }

    $growl_notification.Priority = $Priority

    if (Test-Path Variable:NotificationID) {
      $growl_notification.CoalescingID = $NotificationID
    }

    if ($Sticky) {
      $growl_notification.Sticky = $true
    }

    Add-Member -InputObject $growl_notification -MemberType NoteProperty -Name "ApplicationIcon" -Value $ApplicationIcon
    Add-Member -InputObject $growl_notification -MemberType NoteProperty -Name "NotificationTypeIcon" -Value $NotificationTypeIcon
    Add-Member -InputObject $growl_notification -MemberType NoteProperty -Name "NotificationTypeDescription" -Value $NotificationTypeDescription

    #if ((Test-Path Variable:CallbackURL) -and (($CallbackURL.PSObject.Properties.name -match "Segments") -and (-not $CallbackURL.Segments.Count -eq 0))) {
    if ((Test-Path Variable:CallbackURL) -and (-not $CallbackURL -eq $null)) {
      $callback_context = New-Object "Growl.Connector.CallbackContext" $CallbackURL
    } elseif (-not ($CallbackData -eq $null)) {
      $callback_context = New-Object "Growl.Connector.CallbackContext" $CallbackData, $CallbackDataType
    } else {
      $callback_context = $null
    }

    Add-Member -InputObject $growl_notification -MemberType NoteProperty -Name "Context" -Value $callback_context

    return $growl_notification
  }
}

function Process-SplunkAlert {
  [CmdletBinding()]
  Param(
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [string[]]
    # An array of computer names to contact with Growl notifications
    $GrowlAlert,
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [string[]]
    # An array of email to txt addresses used to alert staff via SMS
    $TxtAlert,
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [ValidateScript({Test-Path $_})]
    [string]
    # A location on the network where information related to alerts can be stored
    $AlertRepository, # 2do: 
    [Parameter(
      #HelpMessage="Specify the name of the application sending this notification",
      Mandatory=$false,
      #ParameterSetName="standard",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Application','App')]
    [hashtable]
    # A location on the network where information related to alerts can be stored
    $Splunk = $null
  )

  Begin {

    # 2do: convert this to a module function called Import-CSVHashtable
    function Script:csv_import_to_hashtable {
      Param([Parameter(ValueFromPipeline=$true)]$object)

      Process {
        return ($object | % {
          $hash_array = @{};
          $_.PSObject.Properties | % {
            $hash_array[$_.Name] = $_.Value
          }
          $hash_array
        })
      }
    }

  }

  Process {
    if (($Splunk -eq $null) -and (-not (Test-Path Env:\SPLUNK_ARG_0))) {
      throw [System.ArgumentNullException] "Splunk alert action environment variables not availabe - probably running with the wrong context"
    }

    # Make sure the AlertRepository doesn't have a trailing "\" character
    if (-not [string]::IsNullOrWhiteSpace($AlertRepository)) {
      $AlertRepository = $AlertRepository -replace "\\$", ""
    }

    if ($Splunk -eq $null) {
      $Splunk = @{
        script_name = (get-item Env:\SPLUNK_ARG_0).Value;
        event_count = (get-item Env:\SPLUNK_ARG_1).Value;
        search_terms = (get-item Env:\SPLUNK_ARG_2).Value;
        query_string = (get-item Env:\SPLUNK_ARG_3).Value;
        alert_name = (get-item Env:\SPLUNK_ARG_4).Value;
        trigger_reason = (get-item Env:\SPLUNK_ARG_5).Value;
        report_url = (get-item Env:\SPLUNK_ARG_6).Value;
        #not_used = (get-item Env:\SPLUNK_ARG_7).Value;
        results_gzip = (get-item Env:\SPLUNK_ARG_8).Value;
      }
    }
    
    # Get the raw output of the alert issued by Splunk in the form of a gziped CSV, decompress it, save to archive location, import into memory
    if (Test-Path $Splunk.results_gzip -PathType Leaf -Include *.gz) {
      # Attempt to decompress the results file from Splunk
      $results_file = ($env:TEMP + "\" + ($Splunk.results_gzip.split("\")[-1] -ireplace "\.gz",""))
      Decompress-GZipItem -Infile $splunk.results_gzip -Outfile $results_file

      # Make sure we end up with an array, even if there's only one result
      $results = @(Import-Csv -Path $results_file | csv_import_to_hashtable)
    }

    # 2do: add $results_file to $AlertRepository

    $template_file_name = [RegEx]::Replace($Splunk.alert_name, '[\\~#%&*{}/:<>?|\"-]', "_") # 2do: check to see if '-' is a legal character

    # Build a hashtable of tokens for the message template
    $alert_name_match_parts = [RegEx]::Match($Splunk.alert_name, "^(?<title>[^(]+)([(](?<priority>\w+)[)])?$") # Arg, smart indenting in VS... )

    $splunk_message = @{
      title = $alert_name_match_parts.Groups['title'].Value;
      priority = $alert_name_match_parts.Groups['priority'].Value;
      count = $results.Count; # We want to make sure we're counting sets, not key/value pairs in a hashtable
      membership_change = $results[0..([Math]::Min(1, $results.Count - 1))]; # return at most 2, [0..1]
      raw_report = "...unable to archive raw alert data...";
    }

    # Attempt to copy the results files to the AlertRepository
    try {
      $results_archive_file = $AlertRepository + "\" + (Get-Date -Format "yyyyMMdd-HHmmssfff-") + $template_file_name + (Get-Item $results_file).Extension
      Copy-Item -Path $results_file -Destination $results_archive_file -Force -ErrorAction Stop
      $splunk_message['raw_report'] = $results_archive_file
    } catch {
      # 2do: Log
    }

    # We want to make sure we're counting sets, not key/value pairs in a hashtable
    if ($results.Count -gt 2) {
      $splunk_message['ellipsis'] = @{ more_count = ($results.Count - 2)}
    }

    return (New-Notification -TemplateFilter "$template_file_name*" -TokenValues $splunk_message)

    #$merged_message = Merge-Tokens -Template $message_template -Tokens $splunk_message
  }
}

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

<#$Script:config = @{
  call_list = @(
    @{
      <# Look up members of the ldap group 'IT Staff', which contains user accounts # >
      source = "ldap_group";
      path = "S-1-5-21-324234234-1231-12352"; #This is junk text representing the SID for Infrastructure staff
      <# Use all methods available when attempting to contact group members # >
      methods = @("all");
      <# Members of this group recive notifications for the following priorities # >
      priorities = @("Emergency", "High");
      <# Cache the resulting list in case the ldap server isn't available # >
      cache = $true
    },
    @{
      <# Look up members of the ldap group 'Infrastructure Staff', which contains user accounts # >
      source = "ldap_group";
      path = "S-1-5-21-324234234-1231-12352"; #This is junk text representing the SID for Infrastructure staff
      <# Use all methods available when attempting to contact group members # >
      methods = @("email");
      <# Members of this group recive notifications for the following priorities # >
      priorities = @("Emergency", "High", "Medium");
      <# Cache the resulting list in case the ldap server isn't available # >
      cache = $true
    },
    @{
      <# Look up members of the ldap group 'Infrastructure Staff Computers', which contains computer accounts # >
      source = "ldap_group";
      path = "S-1-5-21-324234234-1231-12352"; #This is junk text representing the SID for Infrastructure staff
      <# Use all methods available when attempting to contact group members # >
      methods = @("all");
      <# Members of this group recive notifications for the following priorities # >
      priorities = @("Emergency", "High", "Medium");
      <# Cache the resulting list in case the ldap server isn't available # >
      cache = $true
    }
  )
}#>

$Script:resources = @{
  Name = "Growl.CoreLibrary.dll";
  Base64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAKBVYEwAAAAAAAAAAOAAAiELAQgAAEAAAAAgAAAAAAAA/lMAAAAgAAAAYAAAAABAAAAgAAAAEAAABAAAAAAAAAAEAAAAAAAAAACgAAAAEAAAHJ8AAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAKRTAABXAAAAAGAAALgDAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAwAAAAUUwAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAABDQAAAAgAAAAQAAAABAAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAALgDAAAAYAAAABAAAABQAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAIAAAAAQAAAAYAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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Z2F0ZQBFdmVudEFyZ3MATWFyc2hhbEJ5UmVmT2JqZWN0AEVudW0AU3lzdGVtLk5ldABXZWJDbGllbnQAU3lzdGVtLkRyYXdpbmcASW1hZ2UASW1hZ2VUb0J5dGVzAEltYWdlRnJvbUJ5dGVzAEltYWdlRnJvbVVybABTeXN0ZW0uSU8AU3RyZWFtAEltYWdlRnJvbVN0cmVhbQBNVVRFWF9OQU1FAFJFR0lTVFJZX0tFWQBpc0luc3RhbGxlZABpbnN0YWxsYXRpb25Gb2xkZXIAZGlzcGxheXNGb2xkZXIAVmVyc2lvbgBhc3NlbWJseVZlcnNpb24AU3lzdGVtLkRpYWdub3N0aWNzAEZpbGVWZXJzaW9uSW5mbwBmaWxlVmVyc2lvbgAuY3RvcgBnZXRfSXNBdmFpbGFibGUAZ2V0X0lzSW5zdGFsbGVkAGdldF9Jc0dyb3dsUnVubmluZwBEZXRlY3RJZkdyb3dsSXNSdW5uaW5nAFNob3dTZXR0aW5nc1dpbmRvdwBnZXRfSW5zdGFsbGF0aW9uRm9sZGVyAGdldF9EaXNwbGF5c0ZvbGRlcgBnZXRfQXNzZW1ibHlWZXJzaW9uAGdldF9GaWxlVmVyc2lvbgBJc0F2YWlsYWJsZQBJc0luc3RhbGxlZABJc0dyb3dsUnVubmluZwBJbnN0YWxsYXRpb25Gb2xkZXIARGlzcGxheXNGb2xkZXIAQXNzZW1ibHlWZXJzaW9uAEZpbGVWZXJzaW9uAFdyaXRlAGFkZF9Xcml0ZQByZW1vdmVfV3JpdGUAV3JpdGVMaW5lAEludm9rZQBJQXN5bmNSZXN1bHQAQXN5bmNDYWxsYmFjawBCZWdpbkludm9rZQBFbmRJbnZva2UARW5jb2RlAERlY29kZQBub3RpZmljYXRpb25VVUlEAHJlc3VsdABTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBEaWN0aW9uYXJ5YDIAY3VzdG9tSW5mbwBnZXRfTm90aWZpY2F0aW9uVVVJRABnZXRfUmVzdWx0AGdldF9DdXN0b21JbmZvAE5vdGlmaWNhdGlvblVVSUQAUmVzdWx0AEN1c3RvbUluZm8AdXJsAGRhdGEAaW1hZ2UAYWxyZWFkeUNvbnZlcnRlZFJlc291cmNlAGdldF9VcmwAc2V0X1VybABnZXRfRGF0YQBzZXRfRGF0YQBnZXRfSXNTZXQAZ2V0X0lzUmF3RGF0YQBnZXRfSXNVcmwAVG9TdHJpbmcAR2V0S2V5AG9wX0ltcGxpY2l0AFVybABEYXRhAElzU2V0AElzUmF3RGF0YQBJc1VybABJRF9GT1JNQVQAU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeQBNRDUAbWQ1AGlkAGdldF9JRABnZXRfTGVuZ3RoAGdldF9JRFBvaW50ZXIAR2VuZXJhdGVJRABJRABMZW5ndGgASURQb2ludGVyAE9uTm90aWZpY2F0aW9uQ2FsbGJhY2sASW50ZXJuYWxPbk5vdGlmaWNhdGlvbkNhbGxiYWNrAEluaXRpYWxpemVMaWZldGltZVNlcnZpY2UAdmFsdWVfXwBDTElDSwBDTE9TRQBUSU1FRE9VVABXZWJSZXF1ZXN0AFVyaQBHZXRXZWJSZXF1ZXN0AEdldFNhZmVGb2xkZXJOYW1lAEdldFNhZmVGaWxlTmFtZQBHZXRTYWZlTmFtZQBFbnN1cmVEaXJlY3RvcnlFeGlzdHMAQ29tYmluZQBzeW5jTG9jawBJUEFkZHJlc3MAbWFza3MASXNJblNhbWVTdWJuZXQAR2V0TG9jYWxTdWJuZXRNYXNrAEdldE5ldHdvcmtBZGRyZXNzAFN5c3RlbS5SZWZsZWN0aW9uAEFzc2VtYmx5SW5mb3JtYXRpb25hbFZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseVZlcnNpb25BdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAEd1aWRBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseUN1bHR1cmVBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUARGVidWdnaW5nTW9kZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAFN5c3RlbS5UaHJlYWRpbmcATW9uaXRvcgBFbnRlcgBNZW1vcnlTdHJlYW0AU3lzdGVtLkRyYXdpbmcuSW1hZ2luZwBJbWFnZUZvcm1hdABnZXRfUG5nAFNhdmUAR2V0QnVmZmVyAElEaXNwb3NhYmxlAERpc3Bvc2UARXhpdABieXRlcwBTdHJpbmcASXNOdWxsT3JFbXB0eQBnZXRfSXNGaWxlAGdldF9Mb2NhbFBhdGgARmlsZVN0cmVhbQBGaWxlTW9kZQBGaWxlQWNjZXNzAEZpbGVTaGFyZQBEb3dubG9hZERhdGEAc3RyZWFtAHNldF9Qb3NpdGlvbgBGcm9tU3RyZWFtAEJpdG1hcABJY29uAFRvQml0bWFwAE1pY3Jvc29mdC5XaW4zMgBSZWdpc3RyeQBSZWdpc3RyeUtleQBDdXJyZW50VXNlcgBPcGVuU3ViS2V5AEdldFZhbHVlAEZpbGUARXhpc3RzAFBhdGgAR2V0RGlyZWN0b3J5TmFtZQBBc3NlbWJseU5hbWUAR2V0QXNzZW1ibHlOYW1lAGdldF9WZXJzaW9uAEdldFZlcnNpb25JbmZvAEZvcm1hdABNdXRleABQcm9jZXNzU3RhcnRJbmZvAFByb2Nlc3MAU3RhcnQAT2Jzb2xldGVBdHRyaWJ1dGUAdmFsdWUARGVsZWdhdGUAUmVtb3ZlAGluZm8Ab2JqZWN0AG1ldGhvZABjYWxsYmFjawBzdHIAU3lzdGVtLlRleHQARW5jb2RpbmcAZ2V0X1VURjgAR2V0Qnl0ZXMAQ29udmVydABUb0Jhc2U2NFN0cmluZwBGcm9tQmFzZTY0U3RyaW5nAEdldFN0cmluZwBTZXJpYWxpemFibGVBdHRyaWJ1dGUAdmFsAHJlc291cmNlAGFyZ3MASGFzaEFsZ29yaXRobQBDb21wdXRlSGFzaABTdHJpbmdCdWlsZGVyAEJ5dGUAVG9Mb3dlcgBBcHBlbmQALmNjdG9yAENyZWF0ZQBTeXN0ZW0uU2VjdXJpdHkuUGVybWlzc2lvbnMAU2VjdXJpdHlQZXJtaXNzaW9uQXR0cmlidXRlAFNlY3VyaXR5QWN0aW9uAGFkZHJlc3MASVdlYlByb3h5AGdldF9Qcm94eQBJc0J5cGFzc2VkAEdldFByb3h5AElDcmVkZW50aWFscwBnZXRfQ3JlZGVudGlhbHMATmV0d29ya0NyZWRlbnRpYWwAZ2V0X1VzZXJOYW1lAGdldF9Eb21haW4ASHR0cFdlYlJlcXVlc3QAc2V0X0tlZXBBbGl2ZQBTZXJ2aWNlUG9pbnQAZ2V0X1NlcnZpY2VQb2ludABzZXRfTWF4SWRsZVRpbWUAc2V0X0V4cGVjdDEwMENvbnRpbnVlAG5hbWUAR2V0SW52YWxpZEZpbGVOYW1lQ2hhcnMAZGlzYWxsb3dlZENoYXJzAENoYXIAUmVwbGFjZQBwYXRoAERpcmVjdG9yeQBEaXJlY3RvcnlJbmZvAENyZWF0ZURpcmVjdG9yeQBwYXRoMQBwYXRoMgBsb2NhbEFkZHJlc3MAb3RoZXJBZGRyZXNzAElzTG9vcGJhY2sAZ2V0X0lzSVB2NkxpbmtMb2NhbABnZXRfSXNJUHY2U2l0ZUxvY2FsAEVxdWFscwBpcGFkZHJlc3MAU3lzdGVtLk5ldC5OZXR3b3JrSW5mb3JtYXRpb24ATmV0d29ya0ludGVyZmFjZQBHZXRBbGxOZXR3b3JrSW50ZXJmYWNlcwBJUEludGVyZmFjZVByb3BlcnRpZXMAR2V0SVBQcm9wZXJ0aWVzAFVuaWNhc3RJUEFkZHJlc3NJbmZvcm1hdGlvbkNvbGxlY3Rpb24AZ2V0X1VuaWNhc3RBZGRyZXNzZXMASUVudW1lcmF0b3JgMQBVbmljYXN0SVBBZGRyZXNzSW5mb3JtYXRpb24AR2V0RW51bWVyYXRvcgBnZXRfQ3VycmVudABnZXRfSVB2NE1hc2sATm9uZQBJUEFkZHJlc3NJbmZvcm1hdGlvbgBnZXRfQWRkcmVzcwBBZGQAU3lzdGVtLkNvbGxlY3Rpb25zAElFbnVtZXJhdG9yAE1vdmVOZXh0AENvbnRhaW5zS2V5AGdldF9JdGVtAHN1Ym5ldE1hc2sAR2V0QWRkcmVzc0J5dGVzAEFyZ3VtZW50RXhjZXB0aW9uAAAAHVMATwBGAFQAVwBBAFIARQBcAEcAcgBvAHcAbAAAAQARRABpAHMAcABsAGEAeQBzAAAVRwBsAG8AYgBhAGwAXAB7ADAAfQAAL0cAcgBvAHcAbABGAG8AcgBXAGkAbgBkAG8AdwBzAF8AUgB1AG4AbgBpAG4AZwAAE0cAcgBvAHcAbAAuAGUAeABlAAATLwBjAG0AZAA6AHMAaABvAHcAAC14AC0AZwByAG8AdwBsAC0AcgBlAHMAbwB1AHIAYwBlADoALwAvAHsAMAB9AAEFeAAyAABDTgBvACAAcAByAG8AeAB5ACAAcgBlAHEAdQBpAHIAZQBkACAAdABvACAAYQBjAGMAZQBzAHMAIAAnAHsAMAB9ACcAAWtQAHIAbwB4AHkAIAByAGUAcQB1AGkAcgBlAGQAIAB0AG8AIABhAGMAYwBlAHMAcwAgACcAewAwAH0AJwAgAC0AIAB1AHMAaQBuAGcAIABwAHIAbwB4AHkAIABhAHQAIAAnAHsAMQB9ACcAAYCDUAByAG8AeAB5ACAAYQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAbgBvAHQAIAByAGUAcQB1AGkAcgBlAGQAIABvAHIAIABpAHMAIAB1AHMAaQBuAGcAIABkAGUAZgBhAHUAbAB0ACAAYwByAGUAZABlAG4AdABpAGEAbABzAACAi1AAcgBvAHgAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgAgAHIAZQBxAHUAaQByAGUAZAAgAC0AIAB1AHMAaQBuAGcAIAB1AHMAZQByAG4AYQBtAGUAIAAnAHsAMAB9ACcAIABhAG4AZAAgAGQAbwBtAGEAaQBuACAAJwB7ADEAfQAnAAGAiUMAbwB1AGwAZAAgAG4AbwB0ACAAZABlAHQAZQByAG0AaQBuAGUAIABzAHUAYgBuAGUAdAAuACAATABvAGMAYQBsACAAYQBkAGQAcgBlAHMAcwA6ACAAewAwAH0AIAAtACAAUgBlAG0AbwB0AGUAIABBAGQAZAByAGUAcwBzADoAIAB7ADEAfQABZ0wAZQBuAGcAdABoAHMAIABvAGYAIABJAFAAIABhAGQAZAByAGUAcwBzACAAYQBuAGQAIABzAHUAYgBuAGUAdAAgAG0AYQBzAGsAIABkAG8AIABuAG8AdAAgAG0AYQB0AGMAaAAuAAAAAFJOiWsloPlB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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAAABgAAIAAAAAAAAAAAAAAAAAAAAEAAQAAADAAAIAAAAAAAAAAAAAAAAAAAAEAAAAAAEgAAABYYAAAYAMAAAAAAAAAAAAAYAM0AAAAVgBTAF8AVgBFAFIAUwBJAE8ATgBfAEkATgBGAE8AAAAAAL0E7/4AAAEAAAACAAEABAAAAAIAAAAEAD8AAAAAAAAABAAAAAIAAAAAAAAAAAAAAAAAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAAACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8AbgAAAAAAAACwBMACAAABAFMAdAByAGkAbgBnAEYAaQBsAGUASQBuAGYAbwAAAJwCAAABADAAMAAwADAAMAA0AGIAMAAAAEwAFQABAEMAbwBtAHAAYQBuAHkATgBhAG0AZQAAAAAAZQBsAGUAbQBlAG4AdAAgAGMAbwBkAGUAIABwAHIAbwBqAGUAYwB0AAAAAABMABIAAQBGAGkAbABlAEQAZQBzAGMAcgBpAHAAdABpAG8AbgAAAAAARwByAG8AdwBsAC4AQwBvAHIAZQBMAGkAYgByAGEAcgB5AAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAyAC4AMAAuADQALgAxAAAATAAWAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABHAHIAbwB3AGwALgBDAG8AcgBlAEwAaQBiAHIAYQByAHkALgBkAGwAbAAAAHAAJgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAAqQAgAGUAbABlAG0AZQBuAHQAIABjAG8AZABlACAAcAByAG8AagBlAGMAdAAgADIAMAAwADkAAABUABYAAQBPAHIAaQBnAGkAbgBhAGwARgBpAGwAZQBuAGEAbQBlAAAARwByAG8AdwBsAC4AQwBvAHIAZQBMAGkAYgByAGEAcgB5AC4AZABsAGwAAABEABIAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAAEcAcgBvAHcAbAAuAEMAbwByAGUATABpAGIAcgBhAHIAeQAAADAABgABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADIALgAwAC4ANAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMAaQBvAG4AAAAyAC4AMAAuADAALgAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAwAAAAANAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
},
@{
  Name = "Growl.Connector.dll"
  Base64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAKBVYEwAAAAAAAAAAOAAAiELAQgAAMAAAAAgAAAAAAAA/toAAAAgAAAA4AAAAABAAAAgAAAAEAAABAAAAAAAAAAEAAAAAAAAAAAgAQAAEAAApLMBAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAKTaAABXAAAAAOAAAKgDAAAAAAAAAAAAAAAAAAAAAAAAAAABAAwAAAAY2gAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAABLsAAAAgAAAAwAAAABAAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAKgDAAAA4AAAABAAAADQAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAAABAAAQAAAA4AAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAODaAAAAAAAASAAAAAIABQDkVAAANIUAAAkAAAAAAAAAAAAAAAAAAABQIAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhi5C3pNspPlcTmn3RdWh7ugOorkB83jxDXAoKaw3845nit+Qd2JsjvUkKTbG3lh6dwEDKGmceEt0ocrf4Uu8Y9RiAXRWJwGC32Ar+RVt7oGqETGJvEoCI5Cy6j0cjWjUNZep66fOMKQVkfQIBFJlc24MvyIZucSJ82cG9NavuAIDMAIAVAAAAAAAAAACKBEAAAoCfgEAAAR9BgAABAJ+AgAABH0HAAAEAn4DAAAEfQgAAAQCfgQAAAR9CQAABAJ+BQAABH0KAAAEAnMSAAAKfQsAAAQCcxMAAAp9DAAABCoeAnsGAAAEKh4CewcAAAQqHgJ7CAAABCoeAnsJAAAEKh4CewoAAAQqHgJ7CwAABCoeAnsMAAAEKj4CAygLAAAGAgMoDQAABio+AgMoDAAABgIDKA4AAAYqEzADAH4AAAABAAARAyx6cgEAAHACewYAAARzOgAABgpyKQAAcAJ7BwAABHM6AAAGC3JTAABwAnsIAAAEczoAAAYMcoMAAHACewkAAARzOgAABg1yrQAAcAJ7CgAABHM6AAAGEwQDBm/nAAAGAwdv5wAABgMIb+cAAAYDCW/nAAAGAxEEb+cAAAYqAAATMAIA2QAAAAEAABECOdIAAAADOcwAAAADcgEAAHBv7gAABgoGLBkGb0AAAAYoFAAACi0MAgZvQAAABn0GAAAEA3IpAABwb+4AAAYLBywZB29AAAAGKBQAAAotDAIHb0AAAAZ9BwAABANyUwAAcG/uAAAGDAgsGQhvQAAABigUAAAKLQwCCG9AAAAGfQgAAAQDcoMAAHBv7gAABg0JLBkJb0AAAAYoFAAACi0MAglvQAAABn0JAAAEA3KtAABwb+4AAAYTBBEELBsRBG9AAAAGKBQAAAotDQIRBG9AAAAGfQoAAAQqAAAAGzADALQAAAACAAARAzmtAAAAAigHAAAGbxUAAAoTBCsjEgQoFgAACgoSACgXAAAKEgAoGAAACnNMAAAGCwMHb+cAAAYSBCgZAAAKLdTeDhIE/hYEAAAbbxoAAArcAigIAAAGbxsAAAoTBSs6EgUoHAAACgwSAigdAAAKEgIoHgAACm8fAAAKc0wAAAYNAwlv5wAABgMSAigeAAAKKCAAAApv7QAABhIFKCEAAAotvd4OEgX+FgYAABtvGgAACtwqARwAAAIAEwAwQwAOAAAAAAIAXgBHpQAOAAAAABswAwB2AAAAAwAAEQIscgMsbwNv6gAABm8iAAAKCytIEgEoIwAACgoGLD0Gb0YAAAYsHgJvCAAABgZvPwAABgZvSAAABigkAAAKbyUAAAorFwJvBwAABgZvPwAABgZvQAAABm8mAAAKEgEoJwAACi2v3g4SAf4WCAAAG28aAAAK3CoAAAEQAAACABIAVWcADgAAAAA2AoACAAAEA4ADAAAEKjYCgAQAAAQDgAUAAAQqAzABAFEAAAAAAAAAKCgAAAqAAQAABHLdAABwgAIAAAQoKQAACm8qAAAKbysAAApvHwAACoADAAAEKCwAAApvHwAACoAEAAAEKCwAAApvLQAACm8fAAAKgAUAAAQqAAAAAzAKABIAAAAAAAAAAgMEBQ4EDgUUFhYUKBMAAAYqAAADMAIATAAAAAAAAAACKAEAAAYCA30NAAAEAgR9DgAABAIFfQ8AAAQCDgR9EAAABAIOBX0RAAAEAg4GfRQAAAQCDgd9EgAABAIOCH0TAAAEAg4JfRUAAAQqHgJ7DQAABCoiAgN9DQAABCoeAnsOAAAEKiICA30OAAAEKh4Cew8AAAQqIgIDfQ8AAAQqHgJ7EAAABCoiAgN9EAAABCoeAnsRAAAEKiICA30RAAAEKh4CexIAAAQqIgIDfRIAAAQqHgJ7EwAABCoiAgN9EwAABCoeAnsUAAAEKiICA30UAAAEKh4CexUAAAQqIgIDfRUAAAQqAAAAEzADAC0BAAAEAAARcvsAAHACKBQAAAZzOgAABgpyHQEAcAIoFgAABnM6AAAGC3JBAQBwAigYAAAGczoAAAYMcmEBAHACKBoAAAZzOgAABg1yhwEAcAIoHAAABnM6AAAGEwRyqwEAcAIoHgAABnM7AAAGEwVy0wEAcAIoIAAABhMKEgooLgAACnM6AAAGEwZy/wEAcAIoIgAABnM8AAAGEwdyIwIAcAIoJAAABnM6AAAGEwhz9QAABhMJEQkGb+cAAAYRCQdv5wAABhEJCG/nAAAGEQkJb+cAAAYRCREEb+cAAAYRCREFb+cAAAYRCREGb+cAAAYRCREIb+cAAAYCKCIAAAYsKAIoIgAABm8vAAAKLBsRCREHb+cAAAYRCQIoIgAABiggAAAKb+0AAAYCEQkoCQAABhEJKgAAABMwCgDaAAAABQAAEQJy+wAAcBdv7wAABgoCch0BAHAXb+8AAAYLAnJBAQBwFm/vAAAGDAJyYQEAcBdv7wAABg0CcocBAHAWb+8AAAYTBBEELQd+MAAAChMEAnIjAgBwFm/vAAAGEwUCcv8BAHAWb/IAAAYTBgJyqwEAcBZv8AAABhMHAnLTAQBwFm/vAAAGEwgWEwkRCCwuFhMKEQgSCigxAAAKEwsRCywc0BwAAAIoMgAAChEKjDAAAAEoMwAACiwEEQoTCQYHCAkRBBEGEQcRCREFcxMAAAYTDBEMAigKAAAGEQwqAAATMAUApAAAAAYAABECIIAAAAB9FwAABAIoEQAACgMoFAAACjqBAAAAAgN9GwAABAIEfRcAAAQCBX0YAAAEHijhAAAGCgIGKOIAAAZ9HAAABCg0AAAKA281AAAKCweOaQaOaViNNAAAAQwHFggWB45pKDYAAAoGFggHjmkGjmkoNgAACggEKNsAAAYNAgl9GQAABAkEKNsAAAYTBAIRBCjiAAAGfRoAAAQqAigqAAAGKmICIIAAAAB9FwAABAIoEQAACgIoKgAABiqGAn4wAAAKfRsAAAQCFH0cAAAEAhR9GQAABAIUfRoAAAQqHgJ7GwAABCoeAnscAAAEKh4CexkAAAQqHgJ7GgAABCoeAnsXAAAEKiICA30XAAAEKh4CexgAAAQqIgIDfRgAAAQqAAAAEzADABUAAAAHAAARAnsZAAAEAwJ7GAAABCjdAAAGCgYqAAAAEzAEABYAAAAHAAARAnsZAAAEAwJ7GAAABAQo3gAABgoGKgAAEzAEABYAAAAIAAARAnsZAAAEBAMCexgAAAQo4AAABgoGKl4CKBQAAAosBn4WAAAEKgIDBHMoAAAGKgAAEzAFALAAAAAJAAARDgUUUQIoFAAACjqfAAAAKDQAAAoCbzUAAAoKBCjjAAAGCwaOaQeOaViNNAAAAQwGFggWBo5pKDYAAAoHFggGjmkHjmkoNgAACggFKNsAAAYNCQUo2wAABhMEEQQo4gAABhMFAxEFKDgAAAosQQ4FcykAAAZRDgVQAn0bAAAEDgVQBH0cAAAEDgVQA30aAAAEDgVQBX0XAAAEDgVQCX0ZAAAEDgVQDgR9GAAABBcqFioucykAAAaAFgAABCoeAigRAAAKKj4CKBEAAAoCAwQoPQAABioTMAMAHwAAAAoAABECKBEAAAoELQdyWQIAcCsFcl8CAHAKAgMGKD0AAAYqrgIoEQAACgQsIQIDBG8fAAAKKD0AAAYEbzkAAAosDAIEbzoAAAooSQAABioAAzAEAJ8AAAAAAAAAAgN9SAAABAIEfUkAAAQCF31KAAAEAy0KBC0HAhd9SwAABAJ7SwAABC10BCwrBHJnAgBwGW87AAAKLB0CF31MAAAEAgRyZwIAcHKPAgBwbzwAAAp9TQAABAMsFANykQIAcCg4AAAKLAcCF31OAAAEAywVA3KnAgBwbz0AAAosCAIXfU8AAAQqAywUA3KtAgBwbz0AAAosBwIXfVAAAAQqHgJ7SAAABCoAAzADAEUAAAAAAAAAAihDAAAGLBcCKD4AAAYWcqcCAHBvPgAACm8/AAAKKgJ7UAAABCwXAntIAAAEFnKtAgBwbz4AAApvPwAACioCKD4AAAYqHgJ7SQAABCoeAntKAAAEKh4Ce0sAAAQqHgJ7TwAABCoeAntQAAAEKh4Ce04AAAQqHgJ7TAAABCoeAntNAAAEKh4Ce1EAAAQqIgIDfVEAAAQqAAATMAMAbQAAAAsAABEUCgIsZgJvQAAAChAAAigUAAAKLAhzOQAABgorTn5GAAAEAm9BAAAKCwdvQgAACiw6B29DAAAKcrkCAHBvRAAACm9FAAAKb0AAAAoHb0MAAApyzwIAcG9EAAAKb0UAAApvQAAACnM6AAAGCgYqanLnAgBwc0YAAAqARgAABHM5AAAGgEcAAAQqOgIDKE8AAAYEKDoAAAYqOgIDKE8AAAYEKDsAAAYqOgIDKE8AAAYEKDwAAAYqRnJhAwBwcqcCAHACKEcAAAoqHgIoAQAABipWAigBAAAGAgN9UgAABAIEfVMAAAQqHgJ7UgAABCoeAntTAAAEKgAAABMwAwBHAAAADAAAEXJvAwBwAihSAAAGDRIDKC4AAApzOgAABgpyhQMAcAIoUwAABnM6AAAGC3P1AAAGDAgGb+cAAAYIB2/nAAAGAggoCQAABggqABMwAwArAAAADQAAEQJybwMAcBdv8QAABgoCcoUDAHAWb+8AAAYLBgdzUQAABgwIAigKAAAGCCo6AihQAAAGAhcoWQAABipCAgMEKFEAAAYCFihZAAAGKh4Ce1QAAAQqIgIDfVQAAAQqKgIoWAAABhb+ASoyAntWAAAELAIXKhYqHgJ7VgAABCoeAntVAAAEKiICA31VAAAEKh4Ce1cAAAQqAAAAEzAFAB8AAAAOAAARBCwbBG94AAAGBG95AAAGBQNz0wAABgoCBn1WAAAEKgATMAMAOgEAAA8AABFz9QAABgoCKFgAAAYsIAIoWwAABi0YcqkDAHACKF0AAAZzOgAABgsGB2/nAAAGAihaAAAGLDlybwMAcAIoUgAABhMJEgkoLgAACnM6AAAGDHKFAwBwAihTAAAGczoAAAYNBghv5wAABgYJb+cAAAYCKFsAAAY5twAAAHJBAQBwAntWAAAEb9UAAAZzOgAABhMEcskDAHDQDQAAASgyAAAKAntWAAAEb9QAAAaMDQAAAShIAAAKczoAAAYTBXIDBABwAntWAAAEb3gAAAZzOgAABhMGcj8EAHACe1YAAARveQAABnM6AAAGEwdyhQQAcChJAAAKEwoSCnLFBABwKEoAAApzOgAABhMIBhEEb+cAAAYGEQVv5wAABgYRBm/nAAAGBhEHb+cAAAYGEQhv5wAABgIGKAkAAAYGKgAAEzADACsAAAAQAAARAnJvAwBwF2/xAAAGCgJyhQMAcBZv7wAABgsGB3NXAAAGDAgCKAoAAAYIKgATMAIAJQAAAA4AABEELA4DKNYAAAYKAgZ9VgAABAIDKBsBAAZ9VwAABAIDKAoAAAYqHgIoEQAACioAAAAbMAMAaQAAABEAABECLRByyQQAcHLdBABwc0sAAAp6Am9MAAAKb00AAAoKBgJvHwAACm9OAAAKCwfQEAAAAigyAAAKFm9PAAAKDAgsGQiOaRczEwgWmnQQAAACDQlvfwAABhME3gzeAybeAAJvHwAACioRBCoAAAABEAAAAAATAElcAAMBAAABdgIoEQAACgJzUAAACn1aAAAEAnNRAAAKfVsAAAQqHgJ7WwAABCr6Ayw6A29GAAAGLBECe1sAAAQDb0gAAAZvUgAACgNvQgAABiwHAihqAAAGKgIDbz4AAAYDb0AAAAYoaQAABioAAAATMAMAQQAAAAoAABEDKBQAAAotOAQoFAAACi0SBHI3BQBwco8CAHBvPAAAChACcjsFAHADBChHAAAKCgJ7WgAABAYoawAABm9TAAAKKkYCe1oAAAR+WQAABG9TAAAKKjIoNAAACgJvNQAACioyAntaAAAEb1QAAAoqAAAAEzACABUAAAASAAARAm9sAAAGCig0AAAKBm9VAAAKCwcqQihWAAAKKGsAAAaAWQAABCpSAgOMIgAAAm8fAAAKBBcocQAABip6AnJRBQBwA4wbAAACbx8AAAooVwAAChQWKHEAAAYqAAADMAMARwAAAAAAAAACc1gAAAp9YgAABAIoZgAABgIDfV8AAAQCBC0HfhYAAAQrAQR9YAAABAIFLBMELA0EfhYAAAT+ARb+ASsEFisBFn1hAAAEKjYCe2IAAAQDb1kAAAoqAAAAGzAEAH0CAAATAAARc1AAAAoKc1AAAAoLc1EAAAoMCAJ7WwAABG9aAAAKBwJ7WgAABG9TAAAKAntiAAAEb1sAAAoTDysrEg8oXAAACg0HflkAAARvUwAACgcJb2wAAAZvUwAACggJb2cAAAZvWgAAChIPKF0AAAotzN4OEg/+FgwAABtvGgAACtwHb1QAAAoTBAJ7YAAABBEEbzMAAAYTBQJ7YAAABG8xAAAGjCAAAAIoZQAABhMGAntgAAAEbzEAAAYsHhIFe2QAAAQo4gAABhMHclUFAHARBhEHKEcAAAoTBnKPAgBwEwgCe2EAAAQsPwJ7YAAABG8uAAAGEwkCe2AAAARvLAAABhMKcmUFAHACe2AAAARvLwAABowfAAACKGUAAAYRCREKKF4AAAoTCHJ9BQBwAntfAAAEEQYRCCheAAAKEwsGfl4AAARvUwAACgYRC29fAAAKKGsAAAZvUwAACgZ+WQAABG9TAAAKAntgAAAEbzEAAAYsGgYSBXtjAAAEb1MAAAoGflkAAARvUwAACisNBhIFe2MAAARvUwAACghvYAAAChMQOKwAAAASEChhAAAKEwwRDDmcAAAAEQxvYgAACjmQAAAAAntgAAAEEQxvYgAAChIFfGQAAARvNAAABhMNc2YAAAYTDhEOb2oAAAYRDnKRAgBwEQxvYwAACnM6AAAGb2gAAAYRDnKVBQBwEg17YwAABI5pExESESguAAAKczoAAAZvaAAABhEOb2oAAAYGEQ5vbAAABm9TAAAKBhINe2MAAARvUwAACgZ+WQAABG9TAAAKEhAoZAAACjpI////3g4SEP4WDQAAG28aAAAK3AZ+WQAABG9TAAAKBm9UAAAKKgAAAAEcAAACADcAOG8ADgAAAAACAJ4Bv10CDgAAAAB+cqMFAHBytQUAcHK/BQBwKEcAAAooawAABoBeAAAEKj4CA31jAAAEAgR9ZAAABCoeAigRAAAKKlYCKBEAAAoCA31lAAAEAgR9ZgAABCoeAntlAAAEKh4Ce2YAAAQqAAATMAMAKQAAABQAABECcgMEAHAXb+8AAAYKAnI/BABwF2/yAAAGKGYAAAoLBgdzdwAABgwIKoYCIPQBAAB9ZwAABAIEKGkAAAoCA31nAAAEAgV9aAAABCoeAntnAAAEKh4Ce2gAAAQqYgIoawAACgIDLQd+MAAACisBA31/AAAEKh4Ce38AAAQqOgIoAQAABgIDfYAAAAQqHgJ7gAAABCoiAgN9gAAABCoeAnuBAAAEKiICA32BAAAEKgAAABMwAwBlAAAAFQAAEXL7AABwAnuAAAAEczoAAAYKcscFAHACKIMAAAZzPAAABgtz9QAABgwIBm/nAAAGAiiDAAAGLCUCKIMAAAZvLwAACiwYCAdv5wAABggCKIMAAAYoIAAACm/tAAAGAggoCQAABggqAAAAEzADADEAAAAWAAARAnL7AABwF2/vAAAGCgJyxwUAcBZv8gAABgsGc4AAAAYMCAdvhAAABggCKAoAAAYIKiYCAwQodwAABio6Aih2AAAGAgN9ggAABCoeAih2AAAGKh4Ce4IAAAQqrgIoeAAABigUAAAKLRwCKHkAAAYoFAAACi0PAiiKAAAGKBQAAAosAhcqFioAABMwAwAbAAAAFwAAEQIoegAABgoGb3gAAAYGb3kAAAZzhwAABgsHKi4CAxQUFyiPAAAGKi4CAwQUFyiPAAAGKtoCcukFAHB9gwAABAIXfYYAAAQCKAEAAAYCA32DAAAEAgR9hAAABAIFfYUAAAQCDgR9hgAABCoeAnuDAAAEKiICA32DAAAEKloCe4QAAAQsBwJ7hAAABCoCe4MAAAQqIgIDfYQAAAQqHgJ7hQAABCoiAgN9hQAABCoeAnuGAAAEKiICA32GAAAEKgAAABMwAwCuAAAAGAAAEXIdAQBwAiiQAAAGczoAAAYKchcGAHACKJIAAAZzOgAABgty/wEAcAIolAAABnM8AAAGDHJLBgBwAiiWAAAGEwUSBShsAAAKczoAAAYNc/UAAAYTBBEEBm/nAAAGEQQJb+cAAAYCe4QAAAQsCBEEB2/nAAAGAiiUAAAGLCcCKJQAAAZvLwAACiwaEQQIb+cAAAYRBAIolAAABiggAAAKb+0AAAYCEQQoDQAABhEEKgAAEzAFAEoAAAAZAAARAnIdAQBwF2/vAAAGCgJyFwYAcBZv7wAABgsCcv8BAHAWb/IAAAYMAnJLBgBwFm/wAAAGDQYHCAlzjwAABhMEEQQCKA4AAAYRBCoiAhQomwAABiq+AnJ1BgBwfZUAAAQCIA1aAAB9lgAABAIggAAAAH2XAAAEAigRAAAKAgMongAABipaAgMomwAABgIEfZUAAAQCBX2WAAAEKh4Ce5QAAAQqAAATMAIAKQAAAAoAABEDCgYsBwZvQAAACgoGfjAAAAoobQAACiwIAgZ9lAAABCoCFH2UAAAEKh4Ce5cAAAQqIgIDfZcAAAQqHgJ7mAAABCoiAgN9mAAABCoAEzADABoAAAAaAAARAnuUAAAEAnuXAAAEAnuYAAAEKDYAAAYKBioKFyoAAAATMAUAPgAAABsAABECA2+mAAAGCgYsMgNvbAAABgsUEAEHBAUOBHOuAAAGDAL+BqgAAAZzbgAACg0Jc28AAAoTBBEECG9wAAAKKgAAGzAFANUBAAAcAAARFAoUCwN0FwAAAgwIe5oAAAQNCHubAAAEEwQIe5wAAAQTBXNxAAAKCgYCe5UAAAQCe5YAAARvcgAACt4eJgIgyQAAAHKJBgBwc1cAAAYIe50AAARvpQAABt4ABm9zAAAKCwcJFgmOaW90AAAK3h4mAiDJAAAActsGAHBzVwAABgh7nQAABG+lAAAG3gB+MAAAChMGIAAQAACNNAAAARMHKywHEQcWEQeOaW91AAAKEwgRCBYxJxEGKDQAAAoRBxYRCG92AAAKKFcAAAoTBhEGcmYHAHAYb3cAAAosxREEEQYIe50AAARvqgAABhEFLF9+MAAAChMGIAAQAACNNAAAARMHKywHEQcWEQeOaW91AAAKEwkRCRYxJxEGKDQAAAoRBxYRCW92AAAKKFcAAAoTBhEGcmYHAHAYb3cAAAosxREEEQYIe50AAARvqgAABt4eJgIgyQAAAHJwBwBwc1cAAAYIe50AAARvpQAABt4A3hATChEKbx8AAAooeAAACt4A3lIGLDYGb3kAAAosLgZveQAAChdvegAACgZveQAAChhvewAACt4DJt4ABm95AAAKb3wAAAoGb30AAAoHLA4Hb34AAAoHb38AAAoUCxQK3gMm3gDcKgAAAEGsAAAAAAAAIgAAABoAAAA8AAAAHgAAAAEAAAEAAAAAWgAAABQAAABuAAAAHgAAAAEAAAEAAAAAjAAAAMQAAABQAQAAHgAAAAEAAAEAAAAABAAAAGwBAABwAQAAEAAAAAMAAAEAAAAAmQEAAA4AAACnAQAAAwAAAAEAAAEAAAAAggEAAE4AAADQAQAAAwAAAAEAAAECAAAABAAAAH4BAACCAQAAUgAAAAAAAAATMAIAIAAAAB0AABECKIAAAAoKEgD+Fk4AAAFvHwAACn2ZAAAEAigRAAAKKhMwAgA9AAAAHQAAEQIogAAACgoSAP4WTgAAAW8fAAAKfZkAAAQCKBEAAAoCA32aAAAEAgR9mwAABAIFfZwAAAQCDgR9nQAABCpiAgJ7ngAABAMogQAACnQZAAACfZ4AAAQqYgICe54AAAQDKIIAAAp0GQAAAn2eAAAEKmICAnufAAAEAyiBAAAKdBkAAAJ9nwAABCpiAgJ7nwAABAMoggAACnQZAAACfZ8AAAQqYgICe6AAAAQDKIEAAAp0GgAAAn2gAAAEKmICAnugAAAEAyiCAAAKdBoAAAJ9oAAABCoiAhQomwAABioiAgMomwAABioqAgMEBSicAAAGKhoohAAACioaKIQAAAoqLgIDBBQUb70AAAYqLgIDBBQFb70AAAYqLgIDBAUUb70AAAYqAAAbMAUAYwEAAB4AABEDb4UAAAYKc4UAAAoLBBMLFhMMKxoRCxEMmgwIb5gAAAYNBwlvhgAAChEMF1gTDBEMEQuOaTLeFgIoowAABnNvAAAGEwQGbyIAAAoTDSsSEg0oIwAAChMFEQQRBW9oAAAGEg0oJwAACi3l3g4SDf4WCAAAG28aAAAK3BEEcv0HAHAEjmkTDhIOKC4AAApzOgAABm9oAAAGBSw+BW8aAQAGEwYRBm8iAAAKEw8rEhIPKCMAAAoTBxEEEQdvaAAABhIPKCcAAAot5d4OEg/+FggAABtvGgAACtwHb4cAAAoTECtPEhAoiAAAChMIc2YAAAYTCREIbyIAAAoTESsSEhEoIwAAChMKEQkRCm9oAAAGEhEoJwAACi3l3g4SEf4WCAAAG28aAAAK3BEEEQlvcgAABhIQKIkAAAotqN4OEhD+Fg8AABtvGgAACtwCEQQCJf4HpAAABnOpAAAGFg4EKKcAAAYqAAE0AAACAE0AH2wADgAAAAACAKsAH8oADgAAAAACAPsAHxoBDgAAAAACAOAAXDwBDgAAAAAqAgMUFG/EAAAGKi4CAxQUBG/FAAAGKi4CAxQEFG/FAAAGKi4CAxQEBW/FAAAGKi4CAwQUFG/FAAAGKi4CAwQUBW/FAAAGKi4CAwQFFG/FAAAGKgAbMAUA+wAAAB8AABEWCgNvJgAABgsXAiijAAAGc28AAAYMB28iAAAKEwcrDxIHKCMAAAoNCAlvaAAABhIHKCcAAAot6N4OEgf+FggAABtvGgAACtwELFgEb4oAAAYTBBEEKBQAAAotFAhyJQgAcBEEczoAAAZvaAAABiszCHIDBABwBG94AAAGczoAAAZvaAAABghyPwQAcARveQAABm8fAAAKczoAAAZvaAAABhcKBSw9BW8aAQAGEwURBW8iAAAKEwgrERIIKCMAAAoTBggRBm9oAAAGEggoJwAACi3m3g4SCP4WCAAAG28aAAAK3AIIAiX+B6QAAAZzqQAABgYOBCinAAAGKgABHAAAAgAeABw6AA4AAAAAAgC3AB7VAA4AAAAAEzAEADwAAAAgAAARcxgBAAYLBwMSAG8UAQAGDAhvWwAABiwKAggGBCjKAAAGKghvWAAABiwJAggEKMgAAAYqAggEKMkAAAYqJgIDBCjJAAAGKloCe54AAAQsDQJ7ngAABAMEb8wAAAYqWgJ7nwAABCwNAnufAAAEAwRvzAAABiqKBCweBG94AAAGLBYCe6AAAAQsDgJ7oAAABAMEBW/QAAAGKmICAwQodwAABgIFfasAAAQCDgR9rAAABCoeAnurAAAEKh4Ce6wAAAQqGzAFAGYAAAAhAAARAih6AAAGChgLAnLJAwBwF2/vAAAGDAgoFAAACi0X0A0AAAEoMgAACggXKIsAAAqlDQAAAQsCckEBAHAWb+8AAAYNBm94AAAGBm95AAAGBwlz0wAABhMEEQQTBd4GJhQTBd4AEQUqAAABEAAAAAAAAF1dAAYBAAABHgIoEQAACiobMAMAzgAAACIAABEojAAACoCuAAAEc40AAAqArwAABNAfAAACKDIAAAoojgAACm+PAAAKDCsiCG+QAAAKpR8AAAIKfq8AAAQGjB8AAAIoZQAABgZvkQAACghvkgAACi3W3hEIdSkAAAENCSwGCW8aAAAK3HOTAAAKgLAAAATQIAAAAigyAAAKKI4AAApvjwAAChMEKyMRBG+QAAAKpSAAAAILfrAAAAQHjCAAAAIoZQAABgdvlAAAChEEb5IAAAot1N4VEQR1KQAAARMFEQUsBxEFbxoAAArcKgAAARwAAAIAKQAuVwARAAAAAAIAiAAwuAAVAAAAABswAwBHAAAAIwAAEQItEHJfCABwcncIAHBzSwAACnoCIIAAAAAo2gAABgoGDN4iC3LfCABwB2+VAAAKb5YAAAoHb5cAAAooRwAACnOYAAAKeggqAAEQAAAAABMAECMAIgMAAAEbMAMAWAAAACQAABECLRByXwgAcHJ3CABwc0sAAAp6KDQAAAoCbzUAAAoKBgMo2wAABgsHKOIAAAYMCBME3iINct8IAHAJb5UAAApvlgAACglvlwAACihHAAAKc5gAAAp6EQQqARAAAAAAEwAgMwAiAwAAARswAwCwAAAAJQAAEQItEHINCQBwciMJAHBzSwAACnoDEwQRBCAAAQAAMBQRBCCgAAAALh8RBCAAAQAALh4rNBEEIIABAAAuGxEEIAACAAAuGisgc5kAAAoKKx5zmgAACgorFnObAAAKCisOc5wAAAoKKwZznQAACgoUCwYTBQYCb54AAAoL3gwRBSwHEQVvGgAACtwHDd4iDHLfCABwCG+VAAAKb5YAAAoIb5cAAAooRwAACnOYAAAKegkqARwAAAIAcgAKfAAMAAAAAAAAEwB5jAAiAwAAASYCAxoo3QAABioAABMwBAANAAAACAAAERQKAgMEEgAo3gAABioAAAAbMAQAYgEAACYAABEDLRByDQkAcHKJCQBwc0sAAAp6EgD+FQwAAAIEEwgRCBdZRQQAAAACAAAADgAAABoAAAAnAAAAKzNznwAACg0eCx4MKzdzoAAACg0eCx4MKytzoQAACg0fGAseDCsec6IAAAoNHxgLHxAMKxASAAN9YwAABAYTB93jAAAAAo5pBy8kcucJAHAEjCAAAAIHjDAAAAECjmmMMAAAASheAAAKc5gAAAp6CQIHKOYAAAZvowAACgVQLQgJb6QAAAorCAkFUG+lAAAKCW+mAAAKjmkILilytAoAcASMIAAAAgiMMAAAAQlvpgAACo5pjDAAAAEoXgAACnOYAAAKehIACW+mAAAKfWQAAAQJGG+nAAAKCRdvqAAACglvqQAAChMEEQQDFgOOaW+qAAAKEwUSABEFfWMAAAQGEwfeJRMGcm8LAHARBm+VAAAKb5YAAAoRBm+XAAAKKEcAAApzmAAACnoRByoAAEEcAAAAAAAAEwAAACcBAAA6AQAAJQAAAAMAAAEbMAQAMAAAACcAABECAwQaKOAAAAYL3iIKcpULAHAGb5UAAApvlgAACgZvlwAACihHAAAKc5gAAAp6ByoBEAAAAAAAAAwMACIDAAABGzAEAEgBAAAoAAARBC0QcrsLAHBy2QsAcHNLAAAKegUTCBEIF1lFBAAAAAIAAAAVAAAAKAAAADwAAAArTnOfAAAKDR4KHgsJb6sAAAoMK0NzoAAACg0eCh4LCW+rAAAKDCswc6EAAAoNHxgKHgsJb6sAAAoMKxxzogAACg0fGAofEAsggAAAAAwrCAQTB92+AAAACQhvrAAACgKOaQYvJHI/DABwBYwgAAACBowwAAABAo5pjDAAAAEoXgAACnOYAAAKegkCBijmAAAGb6MAAAoDjmkHLiRyDA0AcAWMIAAAAgeMMAAAAQOOaYwwAAABKF4AAApzmAAACnoJA2+lAAAKCRhvpwAACgkXb6gAAAoJb60AAAoTBBEEBBYEjmlvqgAAChMFEQUTB94lEwZylQsAcBEGb5UAAApvlgAAChEGb5cAAAooRwAACnOYAAAKehEHKkEcAAAAAAAAEwAAAA0BAAAgAQAAJQAAAAMAAAETMAIAFAAAAAgAABECjTQAAAEKfq4AAAQGb64AAAoGKhswAwCZAAAAKQAAEQItEHLHDQBwctMNAHBzSwAACnoCjmkYWgoGBnOvAAAKCxYTBSs6AhEFkQwIHw9fDQgaYxMEB3IrDgBwEQRvsAAACm+xAAAKJgdyKw4AcAlvsAAACm+xAAAKJhEFF1gTBREFAo5pMr8Hbx8AAAoTB94lEwZyTQ4AcBEGb5UAAApvlgAAChEGb5cAAAooRwAACnOYAAAKehEHKgAAAAEQAAAAABMAXnEAJQMAAAETMAUATgAAACoAABECLRBydw4AcHKLDgBwc0sAAAp6Am8+AAAKGFuNNAAAAQoWCyshAgcYWhhvsgAACiADAgAAFAYHjzQAAAEoswAACiYHF1gLBwaOaTLZBirKAigUAAAKLRl+rwAABAJvtAAACiwMfq8AAAQCb7UAAAoqcu8OAHACKLYAAApzmAAACnqqfrAAAAQCb7cAAAosDH6wAAAEAm+4AAAKKnJHDwBwAii2AAAKc5gAAAp6GzAEAGgAAAArAAARFgoGA1gLBwKOaTEjcrUPAHByxQ8AcAOMMAAAAQKOaYwwAAABKEcAAApzuQAACnoDjTQAAAEMAggDKLoAAAoIEwTeIg1ylBAAcAlvlQAACm+WAAAKCW+XAAAKKEcAAApzmAAACnoRBCoBEAAAAAAvABRDACIDAAABAzADAHMAAAAAAAAAAyxvA29BAAAGLGcDb0YAAAYsDgJ7wAAABANvuwAACis4A29DAAAGLA4Ce74AAAQDb7sAAAorIgNvRAAABiwOAnu/AAAEA2+7AAAKKwwCe70AAAQDb7sAAAoCAyi7AAAKAnvBAAAEA28+AAAGA2+8AAAKKgAbMAIAMgAAAAMAABEDbyIAAAoLKw8SASgjAAAKCgIGKOcAAAYSASgnAAAKLejeDhIB/hYIAAAbbxoAAArcKgAAARAAAAIABwAcIwAOAAAAAB4Ce70AAAQqHgJ7vgAABCoeAnu/AAAEKh4Ce8AAAAQqGzACAFQAAAADAAARAnvAAAAEbyIAAAoLKywSASgjAAAKCgZvRgAABiwcBm9HAAAGA29jAAAKKDgAAAosCQYDb0kAAAYrCRIBKCcAAAoty94OEgH+FggAABtvGgAACtwqARAAAAIADAA5RQAOAAAAAIYCe8EAAAQDb70AAAosDQJ7wQAABANvvgAACip+RwAABCoAABMwAgAjAAAALAAAEQIDKO4AAAYKBCwRBiwIBm9AAAAGLQYDKPQAAAYGb0AAAAYqABMwAwA9AAAALQAAERYKAgMEKO8AAAYLBygUAAAKLSgHb18AAAoLByUMLBwIcsgQAHAoOAAACi0NCHLSEABwKDgAAAosAhcKBioAAAATMAMAEAAAAAoAABECAwQo7wAABgoGKL8AAAoqEzACADwAAAAsAAARAgMo7gAABgoELBEGLAgGb0AAAAYtBgMo9AAABgZvRgAABiwMBm9IAAAGKCQAAAoqBm9AAAAGKMAAAAoqEzAEAFIAAAAuAAARc/UAAAYKAhiNaAAAARMEEQQWHw2dEQQXHwqdEQRvwQAACgsHEwUWEwYrHREFEQaaDAgoSgAABg0JLAcGCW/nAAAGEQYXWBMGEQYRBY5pMtsGKgAAEzAFABwAAAAvAAARIC8BAABy2hAAcBeNAQAAAQoGFgKiBnN7AAAGevoCc8IAAAp9vQAABAJzwgAACn2+AAAEAnPCAAAKfb8AAAQCc8IAAAp9wAAABAJzwwAACn3BAAAEAijCAAAKKh4Ce8YAAAQqIgIDfcYAAAQqHgJ7xwAABCoiAgN9xwAABCoeAnvJAAAEKiICA33JAAAEKh4Ce8gAAAQqHgJ7ygAABCoeAnvLAAAEKjYCe8wAAAQDb8QAAAoqHgJ7zAAABCpqAnvLAAAELBACe8sAAARvxQAAChYxAhcqFioAEzACAEEAAAAdAAARAihJAAAKfcgAAAQCKIAAAAoKEgD+Fk4AAAFvHwAACn3KAAAEAnPCAAAKfcsAAAQCc8YAAAp9zAAABAIoEQAACipKAigRAAAKAnPHAAAKfc0AAAQqHgJ7zQAABCqWAygUAAAKLRwCe80AAAQDb8gAAAotDgIDFARzCwEABigGAQAGKk4Ce80AAAQDbw0BAAYDb8kAAAoqkgMoFAAACi0bAnvNAAAEA2/IAAAKLA0Ce80AAAQDb8oAAAomKgATMAYADQAAABoAABECAwQFFhIAKAkBAAYqAAAAGzAGAGgAAAAwAAARDgUUUQMoFAAACiwCFioDb18AAAoQAQJ7zQAABG/LAAAKb8wAAAoNKyISAyjNAAAKCgZvDQEABgMEBQ4EDgUoNwAABgsHLAQXDN4bEgMozgAACi3V3g4SA/4WFgAAG28aAAAK3BYqCCoBEAAAAgAnAC9WAA4AAAAAOgIDcgoRAHAEKAsBAAYqcgIoEQAACgIDfc8AAAQCBH3QAAAEAgV90QAABCobMAIATAAAADEAABECKBEAAAoDcj4RAHBvzwAACgoDclARAHBvzwAACgsXDANyaBEAcG/QAAAKDN4DJt4AAgYo0QAACn3PAAAEAgd90AAABAIIfdEAAAQqARAAAAAAIAAOLgADAQAAAR4Ce88AAAQqIgIDfc8AAAQqHgJ70AAABCoiAgN90AAABCoeAnvRAAAEKiICA33RAAAEKgATMAQATwAAAAoAABECe88AAAQo0gAACgoDcj4RAHAG0CYAAAEoMgAACm/TAAAKA3JQEQBwAnvQAAAE0CYAAAEoMgAACm/TAAAKA3JoEQBwAnvRAAAEb9QAAAoqABMwBAALAAAAMgAAEQIDBBIAKBUBAAYqABMwAwAZAAAAMwAAEQQUUQUUUQIDBSgWAQAGCgQGb1wAAAZRBioAAAAbMAQABQIAADQAABEYChQLBHP1AAAGUSg0AAAKA281AAAKDAhz1QAACg0JEw0Jc9YAAAoTBBEEEw4WEwUXEwY4IgEAABEEb9cAAAoTBxEGOQABAAARBygXAQAGEwgRCG9CAAAKOdkAAAACEQhvQwAACnJ8EQBwb0QAAApvRQAACn3VAAAEAhEIb0MAAApyjBEAcG9EAAAKb0UAAAp91gAABAJ71gAABHJRBQBwGG87AAAKLBMCAnvWAAAEFhdvPwAACn3WAAAEAnvVAAAEcr8FAHAoOAAACixX0BsAAAIoMgAACgJ71gAABCgzAAAKLC7QGwAAAigyAAAKAnvWAAAEFiiLAAAKpRsAAAIKc1YAAAYLBhgzAxcTBRYTBitIICwBAAByoBEAcHNXAAAGCytCIC4BAABy1hEAcHNXAAAGCyswIC0BAABy/hEAcHNXAAAGCyseEQcoSgAABhMJBFARCW/nAAAGEQRv2AAACjnS/v//ByxuEQUsRQRQcm8DAHAWb/EAAAYTCgRQcoUDAHAWb+8AAAYTCxEKFjEQEQssDBEKEQtzVwAABgsrKSD0AQAAcioSAHBzVwAABgsrFwRQcqkDAHAWb+8AAAYTDAcRDG9eAAAGBwRQBhf+AW9jAAAGKxAg9AEAAHIqEgBwc1cAAAYL3gwRDiwHEQ5vGgAACtzeDBENLAcRDW8aAAAK3AcqAAAAQTQAAAIAAAAtAAAAvAEAAOkBAAAMAAAAAAAAAAIAAAAhAAAA1gEAAPcBAAAMAAAAAAAAADJ+1AAABAJvQQAACipCclYSAHBzRgAACoDUAAAEKh4CKBEAAAoqAAAbMAMAUAAAADUAABFz9QAABgoGLEUCKBUAAAoNKyMSAygWAAAKCxIBKBcAAAoSASgYAAAKcx0BAAYMBghv5wAABhIDKBkAAAot1N4OEgP+FgQAABtvGgAACtwGKgEQAAACABAAMEAADgAAAAAbMAMATwAAADYAABFzHAEABgoCLEQCb+sAAAZvIgAACgwrHRICKCMAAAoLBywSBgdvPwAABgdvQAAABm8mAAAKEgIoJwAACi3a3g4SAv4WCAAAG28aAAAK3AYqAAEQAAACABUAKj8ADgAAAAAeAigSAAAKKjoCAyggAQAGBCg6AAAGKjoCAyggAQAGBCg7AAAGKjoCAyggAQAGBCg8AAAGKkZyYQMAcHKtAgBwAihHAAAKKgBCU0pCAQABAAAAAAAMAAAAdjIuMC41MDcyNwAAAAAFAGwAAABcLwAAI34AAMgvAAAQJwAAI1N0cmluZ3MAAAAA2FYAALgSAAAjVVMAkGkAABAAAAAjR1VJRAAAAKBpAACUGwAAI0Jsb2IAAAAAAAAAAgAAAVcftgkJAgAAAPoBMwAWAAABAAAAbgAAACgAAADWAAAAIAEAAEEBAAABAAAA2AAAAGgAAAAcAAAANgAAAAEAAAADAAAAEwAAAEoAAABtAAAAFgAAAAEAAAADAAAABgAAAAAACgABAAAAAAAGAG8CaAIGAHYCaAIGAIACaAIGAIoCaAIGAJQCaAIGAKYCaAIGAMYCqwIGAOoCzQIGAPgCqwIKANsDyQMOADIMEwwKAMIMyQMKAB8PyQMGAHwUaAIGAIkUaAIGAKAWgxYGAO4YaAIGALgazQIGAMoazQIOAL0bEwwGAOkb1xsGAA8c1xsGACwc1xsGAGQcRRwGAHIcRRwGAIYc1xsGAJ8c1xsGALoc1xsGANUc1xsGAO4c1xsGAA0d1xsGACod1xsGAEMd1xsGAG0dWh2LAIEdAAAGALAdkB0GANAdkB0GAPIdaAInAAceAAAGACAeqwIGAEweaAIfAAceAAAGAGweaAIGAHge1xsGAJYe1xsGAKseaAIGAL8eaAIGAPQeaAIGAJcQaAIGABMfaAIGAE0fQR8GAF8faAIGAGQfaAIGAI0fRRwGALQfaAIOAO0fEwwOAP8fEwwOACMgEwwGAIIgaAIGALkg1xsGAMwg1xsGAPIgqwIGAD4hRRwGAFQhRRwGAF8haAIGAHUhaAIGAIkhaAIGAKEhaAIGALIhaAIGAAwi+yEGACUi+yEOAEUiMiIOAFciMiIGAHkibyIKAJQiyQMOAKgiMiIOAMciMiIGAPwiaAIGALgUaAIGABEjaAIKACMjyQMOAIQjbiMGAL0jqiMGAOEjgxYGABUkgxYGACEkgxYGAC8kgxYGAD0kgxYGAEskgxYGAHcIgxYGAHIkgxYGAIskgxYGAKQkgxYGAMMkgxYGANMkgxYGAAclgxYGAB8lgxYGADMlgxYGAKslQR8GAPMl3iUGAAAmaAIGACQmaAIGAEkmaAIGAGEmaAInAIYmAACnAQceAAAKALQmyQMGANImbyIGAN8mbyIGAOwmbyIAAAAAAQAAAAAAAQABAAEAEAAeAC8ABQABAAEAAQAQAD8ALwAIAA0AEgABABAATAAvAAUAFgAoAAEAEABQAC8ABQAdADkAAAAQAFcALwAUAFIATAABABAAZAAvAAgAUgBQAAEAEABqAC8AHABUAFYAAQEQAHMALwAFAFgAZAABABAAfwAvAAUAWABmAAEAEACOAC8AKABcAG8ACQEQAJ0ALwAJAGMAdQABABAArgAvAAUAZQB2AAEgEAC/AC8ADQBnAHsAgQEQAM4ALwAFAGkAfgABARAA3wAvABEAfwB+AAEAEAD0AC8ACACAAIAAAQAQAAABLwA0AIIAhwABABAAEAEvAAgAgwCNAIEBEAAhAS8ABQCHAJoAgQAQACsBLwAFAJIAmgAEAQAAOQEAABUAmQCpAAMAEABWAQAABQCZAK0AAQAQAGYBLwBUAJ4ArwACAQAAdQEAABUAoQDLAAIBAACKAQAAFQChAM8AAQEAAJ8BLwAZAKEA0wABAQAArAEvABkApQDTAAEAEAC1AS8ANACrANMAAQEAAMIBLwAFAK0A1wACAQAAzwEAABkAsQDnAAIBAADhAQAAGQC3AOcAAQAQAPgBLwAGAL0A5wABAQAACQIvABkAwgD2AAEAEAAVAi8ABQDGAPYAASAQACECLwAFAM0AAwEBIBAAMQIvAAUAzgAKAQEAEAA6Ai8ABQDSABQBASAQAEgCLwAKANcAGgEAABAAVAIvABQA1wAdAREABQMYABEAGAMYABEALAMYABEAQwMYABEAVwMYAAEAbgMYAAEAegMYAAEAhwMYAAEAlwMYAAEApAMYAAEAtAMbAAEA5AMsAAEA6QUYAAEA+QUYAAEA/gUYAAEAAQYYAAEABwYYAAEADAZ9AAEAEwaAAAEAHAaEAAEAIQYYABYAUgfgAAEAVwfkAAEAZQfoAAEAeQftAAEAhwcYAAEAjwcYAAEAmAcYAFSAmQgYAFSArAgYAFGAwQgYAFGA3wgYAFGA9ggYAFGADgkYAFGAKwkYAFaASQkYAFaAWQkYAFaAagkYAFaAewkYAFaAjwkYAFaAoQkYAFaAuwkYAFaA0AkYAFaA4gkYAFaA8gkYAFaABQoYAFaAFwoYAFaAKwoYAFaAQQoYAFaAXAoYAFaAeQoYAFaAmQoYAFaAtwoYAFaA2goYAFaA9woYAFaAHAsYAFaAMAsYAFaAQAsYAFaAVAsYAFaAaQsYAFaAgQsYAFaAlgsYAFaArgsYAFaAuQsYAFaAywsYAFaA1AsYAFaA4gsYAFaA8gsYAFaAAgwYABEAOAwZBzYARAwdBwEA+QUYAAEAUwwYAAEAVwx9AAEAXwx9AAEAawx9AAEAggwYAAEAmQx9AAEApgx9AAEAtQx9AAEAzQwhBwEASw5TBwEAVQ4YAAEAhA59AAEAiQ4YAAEAlg5sBwEAow5wB1SAgg8YADQAkA/tAAQAnw++BwQApQ/FB1GA9w8YAFGABRAYABEAFhDtAAEAKhAYAAEANhDgAAEAOhB9AAEASRD7BwYAZBDtAAYAcxDtAAEAdhAYAAEAexAYAAEASw5TBwEAnBAwCFaAwxAYAFaAzRAYAFaA4hAYAFaA+BAYAFaADBEYAFaAKBEYAFaAQBEYAFaAUhEYAFaAbxEYAFaAhREYAFaAkREYAFaAnREYAFaAtREYAFaA0BEYAFaA8REYAFaADBIYAFaALRIYAFaASxIYAFaAZRIYAFaAdxIYAFaAihIYAFaAmBIYACEApRIYAAEA+QUYAAEAHAaEAAEAwRIYAAEA+QUYAAEApRIYAAEAHAaEAAEA+hJ9AFaAwxBTB1aAMhNTB1aAQhNTB1aAUhNTB1aAYxNTB1aAnRFTB1aAfBNTB1aAixNTB1aAnxNTB1aAZRJTB1aAbxFTB1aAtBNTB1GAvRMYAAEAjwcYAAEAwRMYAAEAyhNTBwEAzxPkAAEAZQfoACYArRQYAAYAshTtAAYAuBR5DwYAwRR9AAYA0RR9DwEA2xSADwEABxWADwEAPBWKDwYG7xVTB1aA9xUtEFaA+hUtEFaAAxYtEAYG7xVTB1aACRaAAFaAERaAAFaAGhaAAFaAIRaAAFaAJhaAAAEAMBZKEAEANxYYAFGAehYYABEAthaKEBEAuhaOEBEAxBaXEAYG7xVTB1aAOxfkAFaAPxfkAFaARBfkAFaASxfkAFaAUhfkAAYG7xVTB1aAWRfoAFaAYxfoAFaAZxfoAFaAaxfoAFaAdRfoAAEAeRc2EQEAgRc2EQEAjxc2EQEAmxc2EQEApBc+EQYG7xVTB1aAvBiEEVaAxRiEEVaAzBiEEQEA1hgYAAEA4xgYAAEA9xiJEQEABBkYAAEAERkYAAEAGxk2EQEAMxmNEQEAbRquEVGAmhoYAAEAjwcYAAEAVQ4YAAEArhp9AFaAcBsYAFaAhxsYABEAkhsZBwEApRsYAAEArRsYANAgAAAAAIYY+wM1AAEAMCEAAAAAhggBBDkAAQA4IQAAAACGCBEEOQABAEAhAAAAAIYIIgQ5AAEASCEAAAAAhgg2BDkAAQBQIQAAAACGCEcEOQABAFghAAAAAIYIWwQ9AAEAYCEAAAAAhgh0BEYAAQBoIQAAAACEAI8EUAABAHghAAAAAJQArwRXAAIAiCEAAAAAhADRBFAABAAUIgAAAACUAO4EVwAFAPwiAAAAAIQADQVQAAcA2CMAAAAAlAAqBVcACABsJAAAAACWAEkFYAAKAHokAAAAAJYAYAVgAAwAiCQAAAAAkRjUFqEQDgDoJAAAAACGGPsDiAAOAAglAAAAAIYY+wORABMAYCUAAAAAhgguBjkAHABoJQAAAACGCEIGoAAcAHElAAAAAIYIVgY5AB0AeSUAAAAAhghfBqAAHQCCJQAAAACGCGgGOQAeAIolAAAAAIYIbwagAB4AkyUAAAAAhgh2BjkAHwCbJQAAAACGCIAGoAAfAKQlAAAAAIYIigY5ACAArCUAAAAAhgiTBqAAIAC1JQAAAACGCJwGpQAhAL0lAAAAAIYIpwapACEAxiUAAAAAhgiyBq4AIgDOJQAAAACGCL8GswAiANclAAAAAIYIzAa5ACMA3yUAAAAAhgjVBr4AIwDoJQAAAACGCN4GOQAkAPAlAAAAAIYI7wagACQA/CUAAAAAhgAAB8QAJQA4JwAAAACWAAoHygAlACAoAAAAAIQY+wPxACYA0CgAAAAAgRj7AzUAKQDpKAAAAACBAJ0HNQApAAspAAAAAIYIsAc5ACkAEykAAAAAhgi9BzkAKQAbKQAAAACECMYH+wApACMpAAAAAIYI2Ac5ACkAKykAAAAAhgjkBwABKQAzKQAAAACECPYHBQEpADwpAAAAAIYICAgLASoARCkAAAAAhAggCBEBKgBQKQAAAACGADgIGAErAHQpAAAAAIYAOAgfASwAmCkAAAAAhgBACCkBLgC6KQAAAACWAEgIMgEwANQpAAAAAJYAVAg9ATMAkCoAAAAAkRjUFqEQOQCcKgAAAACGGPsDNQA5AKQqAAAAAIYY+wMlBzkAtCoAAAAAhhj7AysHOwDfKgAAAACGGPsDMQc9AAwrAAAAAIEA2wwlBz8AtysAAAAAhghWBjkAQQDAKwAAAACGCOYMOQBBABEsAAAAAIYI9Qw5AEEAGSwAAAAAhgj/DKUAQQAhLAAAAACGCAsNpQBBACksAAAAAIYIGw2lAEEAMSwAAAAAhgguDaUAQQA5LAAAAACGCD8NpQBBAEEsAAAAAIYIUA2lAEEASSwAAAAAhghrDTkAQQBRLAAAAACGCIYNOAdBAFksAAAAAIYImA09B0EAZCwAAAAAlgCqDUMHQgDdLAAAAACRGNQWoRBDAPgsAAAAAIYY+wMlB0MABy0AAAAAhhj7AysHRQAWLQAAAACGGPsDMQdHACUtAAAAAJEAQA5OB0kANy0AAAAAhBj7AzUASgA/LQAAAACGGPsDVgdKAFUtAAAAAIYIYQ5cB0wAXS0AAAAAhghvDjkATABoLQAAAADGAQAHxABMALwtAAAAAJYACgdgB0wA8y0AAAAAhhj7AzUATQACLgAAAACGGPsDVgdNABMuAAAAAIYIrw6lAE8AGy4AAAAAhgi4DqkATwAkLgAAAACGCMEOpQBQAC8uAAAAAIYIzQ6lAFAAPC4AAAAAgwjcDnUHUABELgAAAACGCO0OOQBQAEwuAAAAAIYI/g6gAFAAVS4AAAAAhggPD3oHUQBgLgAAAACGAC4PgAdRAIwuAAAAAMYAAAfEAFQA1C8AAAAAlgAKB4kHVAAMMAAAAACDAD4PkQdVAD0wAAAAAIEY+wM1AFcASDAAAAAAlgB8D6QHVwDQMAAAAACGGPsDNQBYAO4wAAAAAIMIsA/NB1gA9jAAAAAAhgC/D9YHWAA4MQAAAACEAL8PJQdZAIUxAAAAAIYAyQ81AFsAlzEAAAAAlADWD9wHWwCkMQAAAADGAeUP+wBcALQxAAAAAMYA7g85AFwA1TEAAAAAkRjUFqEQXADmMQAAAACGGPsDAwhcAPsxAAAAAIYY+wMMCF4AHDIAAAAAhBj7AxIIXwBvMgAAAACGAFIQGghiAIAyAAAAAMYA5Q/7AGMAKDUAAAAAkRjUFqEQYwBINQAAAACGGPsDIAhjAFg1AAAAAIQY+wM1AGUAYDUAAAAAhhj7AyUHZQB2NQAAAACGCIAQOQBnAH41AAAAAIYIiRA5AGcAiDUAAAAAlgAKBygIZwC9NQAAAACGGPsDNAhoAN81AAAAAIYIYQ5cB2sA5zUAAAAAhgihEDwIawDvNQAAAACGGPsDoABrAAg2AAAAAIYIsRI5AGwAEDYAAAAAhhj7A6AAbAAfNgAAAACGCFYGOQBtACc2AAAAAIYIXwagAG0AMDYAAAAAhgjMBrkAbgA4NgAAAACGCNUGvgBuAEQ2AAAAAIYAAAfEAG8AuDYAAAAAlgAKB8UObwD1NgAAAACGGPsDJQdwAP82AAAAAIYY+wOgAHIADjcAAAAAgRj7AzUAcwAWNwAAAACGCMUSOQBzAB43AAAAAIYA1RKlAHMATDcAAAAAlgAKB80OcwBzNwAAAACGGPsDoAB0AH83AAAAAIYY+wMlB3UAizcAAAAAhhj7A9UOdwDCNwAAAACGCFYGOQB7AMo3AAAAAIYIXwagAHsA0zcAAAAAhgixEjkAfADqNwAAAACGCAIToAB8APM3AAAAAIYIzAa5AH0A+zcAAAAAhgjVBr4AfQAEOAAAAACGCBITpQB+AAw4AAAAAIYIHhOpAH4AGDgAAAAAhgAAB8QAfwDUOAAAAACWAAoH3g5/ACo5AAAAAIQY+wM1AIAAMzkAAAAAhBj7A6AAgABjOQAAAACEGPsDKw+BAHo5AAAAAIYIsAc5AIQAhDkAAAAAhgjgE6AAhAC5OQAAAACGCO0TAAGFAME5AAAAAIYIAhQFAYUAyjkAAAAAhggICAsBhgDSOQAAAACGCCAIEQGGANw5AAAAAIQAFxQyD4cAAAAAAAAAxAUeFDcPhwAAAAAAAADEBTEUPQ+JAAI6AAAAAMQBSBRED4sACDoAAAAAhABVFEoPjABUOgAAAACBAFoUVA+QAAAAAAADAIYY+wNZD5EAAAAAAAMAxgF1FDcPkwAAAAAAAwDGAZcUXw+VAAAAAAADAMYBoxRpD5kA5DwAAAAAhBj7AzUAmgAQPQAAAACGGPsDbw+aAFk9AAAgAIYI5hSED54Acj0AACAAhgj1FIQPnwCLPQAAIACGCBUVhA+gAKQ9AAAgAIYIJxWED6EAvT0AACAAhghRFY4PogDWPQAAIACGCGoVjg+jAO89AAAAAIYY+wM1AKQA+D0AAAAAhhj7A6AApAABPgAAAACGGPsDKw+lAAw+AAAAAIYAhhWlAKgAEz4AAAAAlgCVFZQPqAAaPgAAAADGAasVmA+oACY+AAAAAMYBqxWhD6oAMj4AAAAAxgGrFasPrQBAPgAAAADGAasVtw+wAOQ/AAAAAMYBtBXED7QA7z8AAAAAxgG0FcoPtQD7PwAAAADGAbQV0Q+3AAdAAAAAAMYBtBXaD7kAE0AAAAAAxgG0FeQPvAAfQAAAAADGAbQV7A++ACtAAAAAAMYBtBX1D8EAOEAAAAAAxgG0FQAQxABcQQAAAADEAB4UNw/IAKRBAAAAAMQAMRQ9D8oArkEAAAAAhAC7FT0PzADFQQAAAACEAMgVPQ/OANxBAAAAAIQA2BUMENAAAAAAAAMAhhj7A1kP0wAAAAAAAwDGAXUUPQ/VAAAAAAADAMYBlxQVENcAAAAAAAMAxgGjFGkP2wAAAAAAAwCGGPsDWQ/cAAAAAAADAMYBdRQMEN4AAAAAAAMAxgGXFCAQ4QAAAAAAAwDGAaMUaQ/mAP9BAAAAAIYY+wNOEOcAGEIAAAAAhghGFlcQ6wAgQgAAAACGCFEWOQDrAChCAAAAAJYACgdcEOsArEIAAAAAgRj7AzUA7AC0QgAAAACRGNQWoRDsAKxDAAAAAJYA2xZOB+wAEEQAAAAAlgDbFqUQ7QCERAAAAACWANsWrBDvAFxFAAAAAJYAOAi1EPEAaEUAAAAAlgA4CL4Q8wCERQAAAACWADgIyhD2ABBHAAAAAJYAQAjZEPoAXEcAAAAAlgBACOQQ/QDMSAAAAACWAOcW8hABAexIAAAAAJYA9Rb4EAIBpEkAAAAAlgD/FtwHAwH+SQAAAACWAAsX/hAEATFKAAAAAJYAGhcEEQUBXEoAAAAAkQAsFwsRBgHgSgAAAACGAL8P1gcIAWBLAAAAAIYArxdQAAkBsEsAAAAAhgi6F0cRCgG4SwAAAACGCMYXRxEKAcBLAAAAAIYI2BdHEQoByEsAAAAAhgjoF0cRCgHQSwAAAACGAPUXPQcKAUBMAAAAAIYACRhQEQsBZEwAAAAAhgANGFYRDAGUTAAAAACGACIYXBEOAeBMAAAAAIYAOBhiERAB/EwAAAAAhgBKGGgREgFETQAAAACWAGEYbxEUAaRNAAAAAJEAbRh2ERUBzE0AAAAAhhj7AzUAFgELTgAAAACGCEAZOQAWARNOAAAAAIYIURmgABYBHE4AAAAAhghiGTkAFwEkTgAAAACGCHEZoAAXAS1OAAAAAIYIgBk5ABgBNU4AAAAAhgiRGaAAGAE+TgAAAACGCKIZlBEZAUZOAAAAAIYIsxk5ABkBTk4AAAAAhgjBGUcRGQFWTgAAAACGAN0ZoAAZAWROAAAAAIYI7hmZERoBbE4AAAAAhgD/GaUAGgGITgAAAACGGPsDNQAaAdVOAAAAAIYY+wM1ABoB6E4AAAAAhgh3GrgRGgHwTgAAAACGAIUaKwcaARZPAAAAAIYAhRrDERwBKk8AAAAAhgCJGqAAHQFQTwAAAACGAMcNyhEeAWxPAAAAAIYAxw3SESEB8E8AAAAAhhj7AysHJgH/TwAAAACGGPsDHhIoARxQAAAAAIQY+wMlEisBhFAAAAAAhgjbGjkALQGMUAAAAACGCO4aoAAtAZVQAAAAAIYIARs5AC4BnVAAAAAAhggRG6AALgGmUAAAAACGCCEbpQAvAa5QAAAAAIYILxupAC8BuFAAAAAAxgE9GyUSMAEUUQAAAACGALcbMhIyASxRAAAAAIYAtxs7EjQBVFEAAAAAgQC3G0gSNwGcUwAAAACWAMMbUhI5AbpTAAAAAIYY+wM1ADoBqVMAAAAAkRjUFqEQOgHEUwAAAACGAAAHxAA6ATBUAAAAAJYACgdYEjoBnFQAAAAAhhj7AzUAOwGkVAAAAACGGPsDJQc7AbNUAAAAAIYY+wMrBz0BwlQAAAAAhhj7AzEHPwHRVAAAAACRAEAOTgdBAQAAAQB5FwAAAQDuHQAAAgB5FwAAAQB5FwAAAQDuHQAAAgB5FwAAAQB5FwAAAQDuHQAAAgB5FwAAAQD5BQAAAgClGwAAAQD5BQAAAgClGwAAAQDpBQAAAgDdHgAAAwD+BQAABAABBgAABQAHBgAAAQDpBQAAAgDdHgAAAwD+BQAABAABBgAABQAHBgAABgAcBgAABwAMBgAACAATBgAACQAhBgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQB5FwAAAQCPBwAAAgBXBwAAAwBlBwAAAQDuHgAAAQDuHgAAAQCfDwAAAQCfDwAAAgBvHwAAAQByHwAAAgBvHwAAAQCPBwAAAgBXBwAAAwBlBwAAAQCPBwAAAgCHBwAAAwCYBwAABABXBwAABQBlBwIABgCBHwAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQDuHgAAAQDjHwAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQD5BQAAAQBLDgAAAgBVDgAAAQB5FwAAAQBLDgAAAgAyIAAAAQDuHgAAAQDuHgAAAQA3FgAAAgBDIAAAAwBTIAAAAQB5FwAAAQB5FwAAAgBtIAAAAQB4IAAAAQDrIAAAAQD5BQAAAgBTDAAAAQBTDAAAAQAqEAAAAgA2EAAAAQAqEAAAAQAqEAAAAgA2EAAAAwA6EAAAAQAuIQAAAQByHwAAAgBvHwAAAQB2EAAAAgB7EAAAAQB5FwAAAQBLDgAAAgAyIAAAAwCcEAAAAQClEgAAAQD5BQAAAQDuHgAAAQDuHgAAAQB5FwAAAQB2EAAAAgB7EAAAAQDBEgAAAQB5FwAAAQD5BQAAAQD5BQAAAgClEgAAAQD5BQAAAgClEgAAAwAcBgAABAD6EgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQB5FwAAAQCPBwAAAQCPBwAAAgDBEwAAAwDKEwAAAQDuHgAAAQDuHgAAAQDuHgAAAQDIIQAAAgDVIQAAAQDbIQAAAgDVIQAAAQDkIQAAAQDkIQAAAgDnIQAAAwDrIQAABADVIQAAAQDuHQAAAQDlIgAAAgDsIgAAAQDbIQAAAgDVIQAAAQDbIQAAAgDVIQAAAwDzIgAABADlIgAAAQAwFgAAAQCfDwAAAgDnIQAAAwDrIQAABADVIQAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQDuHgAAAQCPBwAAAQCPBwAAAgDBEwAAAwDKEwAAAQBDIwAAAgBPIwAAAQBDIwAAAgBPIwAAAwDVIQAAAQBDIwAAAgBPIwAAAwCjDgAAAQBDIwAAAgBPIwAAAwCjDgAABADVIQAAAQBhIwAAAQBhIwAAAgDVIQAAAQBhIwAAAgCjDgAAAQBhIwAAAgCjDgAAAwDVIQAAAQBhIwAAAgBDIAAAAQBhIwAAAgBDIAAAAwDVIQAAAQBhIwAAAgBDIAAAAwCjDgAAAQBhIwAAAgBDIAAAAwCjDgAABADVIQAAAQDIIQAAAgDVIQAAAQDbIQAAAgDVIQAAAQDbIQAAAgDVIQAAAQDbIQAAAgDVIQAAAQDbIQAAAgCWDgAAAwDVIQAAAQDlIgAAAgDsIgAAAQDbIQAAAgDVIQAAAQDbIQAAAgDVIQAAAwDzIgAABADlIgAAAQAwFgAAAQDlIgAAAgDsIgAAAQDbIQAAAgCWDgAAAwDVIQAAAQDbIQAAAgCWDgAAAwDVIQAABADzIgAABQDlIgAAAQAwFgAAAQB2EAAAAgB7EAAAAwAwFgAABAA3FgAAAQB5FwAAAQDJIwAAAQDJIwAAAgD4IwAAAQAKJAAAAgD4IwAAAQA2EAAAAgAKJAAAAQA2EAAAAgAKJAAAAwBkJAAAAQA2EAAAAgAKJAAAAwBkJAAABABvHwAAAQA2EAAAAgBvHwAAAwByHwAAAQA2EAAAAgBvHwAAAwByHwAABABkJAAAAQCUJQAAAQCfDwAAAQDKJQAAAQD5BQAAAQD5BQAAAQA2EAAAAgAcJgAAAQDrIAAAAQB5FwAAAQClDwAAAQD5BQAAAQD5BQAAAgBAJgAAAQD5BQAAAgBAJgAAAQD5BQAAAgBAJgAAAQD5BQAAAgBAJgAAAQBZJgAAAQBsJgAAAQDuHgAAAQDuHgAAAQDuHgAAAQB3JgAAAQCPBwAAAgCuGgAAAQCPBwAAAQCPBwAAAQCHBwAAAgCYBwAAAwBXBwAAAQCHBwAAAgCYBwAAAwBXBwAABABlBwIABQCBHwAAAQCPBwAAAgCuGgAAAQCPBwAAAgBVDgAAAwCuGgAAAQB3JgAAAgChJgAAAQDuHgAAAQDuHgAAAQDuHgAAAQB3JgAAAgChJgAAAQBZJgIAAgChJgAAAQBZJgIAAgChJgIAAwB5FwAAAQBZJgIAAgB5FwAAAQDjHwAAAQB5FwAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQD5BQAAAgBTDAAAAQD5BSUAIQCpAPsDoACxAPsDoAC5APsDoADBAPsDoADJAPsDqQDRAPsDoADZAPsDoADhAPsDoADpAPsDoADxAPsDoAD5APsDoAABAfsDoAAJAfsDoAARAfsDYRIhAfsDaBIpAfsDNQAJAPsDNQAUAPsDNQAcAPsDNQAxAfkdJBMUABIeKRMkAC8ePRMsADseURMsAPUMVhMkAEMepQBJAVgeNQAcABIeKRM0AC8ePRM8ADseURM8APUMVhMJAO4POQBRAGAebRM0AEMepQAMABIemRNEAC8eURNRAGAeqxMcAIUashMUAIUashNEAEMepQBZAQEExhNhAYEeyhNhAaMe0BNpAbMe1hNZAc8e3BN5AbMe1hOBAe4POQBRAPoepQAxAQQfGACBAQof+xOJASUfAhQxADcfCxSZAVYfJhSZAeUPLBSpAWofMhSxAfsDNQAxAZofVhRRAKYfpQBRAIAQOAcxAcUfbhQxAdAfdhQxAcUffBQxAdgfXAcxAYkagRQxAegfOQBZAL0bhxTBAfMfpQChAA8gjRTJARogkxTRAfUMOQBZAPsDoAAxASsgoRQxAKMevxSJAGIgxxSJAO4PzBTZAfsDJQcJAJgg8RSJAaAg8RSJAcMg9xTpAdcg/hRMAPsDNQBUAPsDNQBUAIUaIhVMAAAhKBVMAAkhMxWZAREhORVZARshxhMxASchRRVcAPsDNQBcAIUaIhVUAAAhKBVcABIemRNkAC8eURNkAEMepQAxASsgWhUxATYhOQBUABIemRNsAC8eURNhAIAQ+wBhAGgGOQBsAEMepQD5AfsDnhVRAGAepRUJAvsDNQARAvsDNQAZAPsDoAAZAvsDshUhAPsDNQApAu4POQAxAbohVhQxAvsDWQ85AvsDChY5AiwiVA9BAvsDNQBBAk8iHxZBAmUiJRZRAoAiKxZRAoYiMxaZAREhOxYxAYsibhRZAp4idhFBAq8iQxZhAroiqQBhAtYiSRZhAt8iNQBBAt8iNQBRAt8iNQBRAlgeNQBxAgEjZxZ5AgkjcxZ5AokacxaBAvsDKweJAiwjlA90APsDNQB0AIUaIhV0ABIemRN8AC8eURN8AEMepQCRAvsDoAAxALcbPxiBAJkjVRiEAPsDNQAxAKAjYhipARIeaxiZAi8ecRiEAIUashOZAkMepQCMAPsDNQCMAIUashMZAJgg8RTpAVYGOQAZANUjOQChAvsDoACpAvsDNQCxAvsDNQC5AvsDNQDBAvsDNQDJAvsDNQDRAtsWpBjZAvsDNQDhAvsDNQDpAvsDNQDxAvsDNQD5AuYkvBj5Au4kNQD5AvkkvBj5AgAl+wD5AhMlwhj5AiolyRj5AkQl0BgRA1Ql1hj5AmglXAf5AnYlaBL5AoQl0BiBAJslvBgZA/sDERkxAbklFxkZA8MlHBkxAdQlgRShAQofMRmEABAmRBmEABogShkxASsgURmMABAmRBmMABogShkxA/sDJQepAWofVxkMAIUaIhWUAIUashOUABAmRBmUABogShk5A1Em5hlRAGAe6xkxAWYm8RkMAPsDNQCUAPsDNQCcAIUaIhUMAHwmXAecAPsDNQCkAPsDNQCkABAmRBmkAIUashOkAIkaRBmkAJYmHBqsABIeMhq0AC8eVhO0AEMepQCRABEhzBSRAKkmfBRZA7smTgdZA8ImTgeRAMkmXxqRAMkmKwdhA/sDvBhpA/sDcxpxA/cmOQBpAwAnpQAOAHQAXAEOAHgAZwEOAHwAbAEOAIAAkwEOAIQAmgEOAIgAnwEOAIwAtAEOAJAAywEOAJQA6gEOAJgACwIOAJwALAIOAKAAUwIOAKQAdgIOAKgAqQIOAKwA0gIOALAA9QIOALQAFAMOALgAOQMOALwAXAMOAMAAgwMOAMQArgMOAMgA4wMOAMwAHAQOANAAWwQOANQAlgQOANgA2wQOANwAFAUOAOAAXQUOAOQAcgUOAOgAfwUOAOwApgUOAPAAzwUOAPQA/gUOAPgAJwYOAPwAVgYOAAABawYOAAQBjgYOAAgBnwYOAAwBugYOABAB2QYOABQB+AYOAGABqQcOAHAB6wcOAHQB9AcOAKQBRggOAKgBwQgOAKwB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DwGTAAIAEQGVAAEAEgGVAAoAEQAPEzUTSRNbE2QToxMVFRsVSxVSFWIVsxe7F1oYdRjTGQ0aExooGj4aBIAAAAIAAAAAAAAAAQAAAG0SLwAAAAIAAAAAAAAAAAAAAAEAXwIAAAAAAgAAAAAAAAAAAAAAIwDJAwAAAAACAAAAAAAAAAAAAAABAGgCAAAAABYAFQAXABUAGQAYABoAGAAfAB4AIAAeAAAAADxNb2R1bGU+AEdyb3dsLkNvbm5lY3Rvci5kbGwARXh0ZW5zaWJsZU9iamVjdABHcm93bC5Db25uZWN0b3IATm90aWZpY2F0aW9uAEtleQBIZWFkZXIAQ3VzdG9tSGVhZGVyAEVycm9yAFJlc3BvbnNlAERpc3BsYXlOYW1lAE1lc3NhZ2VTZWN0aW9uAE1lc3NhZ2VCdWlsZGVyAEVuY3J5cHRpb25SZXN1bHQAQ2FsbGJhY2tEYXRhQmFzZQBHcm93bEV4Y2VwdGlvbgBFcnJvckRlc2NyaXB0aW9uAERpc3BsYXlOYW1lQXR0cmlidXRlAEFwcGxpY2F0aW9uAENhbGxiYWNrQ29udGV4dABOb3RpZmljYXRpb25UeXBlAEVycm9yQ29kZQBDb25uZWN0b3JCYXNlAFJlc3BvbnNlUmVjZWl2ZWRFdmVudEhhbmRsZXIAQ29ubmVjdGlvblN0YXRlAEdyb3dsQ29ubmVjdG9yAFJlc3BvbnNlRXZlbnRIYW5kbGVyAENhbGxiYWNrRXZlbnRIYW5kbGVyAFJlc3BvbnNlVHlwZQBQcmlvcml0eQBDYWxsYmFja0RhdGEAQ3J5cHRvZ3JhcGh5AEhhc2hBbGdvcml0aG1UeXBlAFN5bW1ldHJpY0FsZ29yaXRobVR5cGUASGVhZGVyQ29sbGVjdGlvbgBSZXF1ZXN0VHlwZQBSZXF1ZXN0SW5mbwBQYXNzd29yZE1hbmFnZXIAUGFzc3dvcmQATWVzc2FnZVBhcnNlcgBSZXF1ZXN0RGF0YQBEYXRhSGVhZGVyAG1zY29ybGliAFN5c3RlbQBPYmplY3QAVmFsdWVUeXBlAEV4Y2VwdGlvbgBBdHRyaWJ1dGUATXVsdGljYXN0RGVsZWdhdGUARW51bQBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBMaXN0YDEAU3lzdGVtLlJ1bnRpbWUuU2VyaWFsaXphdGlvbgBJU2VyaWFsaXphYmxlAERpY3Rpb25hcnlgMgBkZWZhdWx0TWFjaGluZU5hbWUAZGVmYXVsdFNvZnR3YXJlTmFtZQBkZWZhdWx0U29mdHdhcmVWZXJzaW9uAGRlZmF1bHRQbGF0Zm9ybU5hbWUAZGVmYXVsdFBsYXRmb3JtVmVyc2lvbgBtYWNoaW5lTmFtZQBzb2Z0d2FyZU5hbWUAc29mdHdhcmVWZXJzaW9uAHBsYXRmb3JtTmFtZQBwbGF0Zm9ybVZlcnNpb24AY3VzdG9tVGV4dEF0dHJpYnV0ZXMAR3Jvd2wuQ29yZUxpYnJhcnkAUmVzb3VyY2UAY3VzdG9tQmluYXJ5QXR0cmlidXRlcwAuY3RvcgBnZXRfTWFjaGluZU5hbWUAZ2V0X1NvZnR3YXJlTmFtZQBnZXRfU29mdHdhcmVWZXJzaW9uAGdldF9QbGF0Zm9ybU5hbWUAZ2V0X1BsYXRmb3JtVmVyc2lvbgBnZXRfQ3VzdG9tVGV4dEF0dHJpYnV0ZXMAZ2V0X0N1c3RvbUJpbmFyeUF0dHJpYnV0ZXMAQWRkSW5oZXJpdGVkQXR0cmlidXRlc1RvSGVhZGVycwBTZXRJbmhlcnRpZWRBdHRyaWJ1dGVzRnJvbUhlYWRlcnMAQWRkQ29tbW9uQXR0cmlidXRlc1RvSGVhZGVycwBTZXRDb21tb25BdHRyaWJ1dGVzRnJvbUhlYWRlcnMAQWRkQ3VzdG9tQXR0cmlidXRlc1RvSGVhZGVycwBTZXRDdXN0b21BdHRyaWJ1dGVzRnJvbUhlYWRlcnMAU2V0U29mdHdhcmVJbmZvcm1hdGlvbgBTZXRQbGF0Zm9ybUluZm9ybWF0aW9uAE1hY2hpbmVOYW1lAFNvZnR3YXJlTmFtZQBTb2Z0d2FyZVZlcnNpb24AUGxhdGZvcm1OYW1lAFBsYXRmb3JtVmVyc2lvbgBDdXN0b21UZXh0QXR0cmlidXRlcwBDdXN0b21CaW5hcnlBdHRyaWJ1dGVzAGFwcGxpY2F0aW9uTmFtZQBuYW1lAGlkAHRpdGxlAHRleHQAc3RpY2t5AHByaW9yaXR5AGljb24AY29hbGVzY2luZ0lEAGdldF9BcHBsaWNhdGlvbk5hbWUAc2V0X0FwcGxpY2F0aW9uTmFtZQBnZXRfTmFtZQBzZXRfTmFtZQBnZXRfSUQAc2V0X0lEAGdldF9UaXRsZQBzZXRfVGl0bGUAZ2V0X1RleHQAc2V0X1RleHQAZ2V0X1N0aWNreQBzZXRfU3RpY2t5AGdldF9Qcmlvcml0eQBzZXRfUHJpb3JpdHkAZ2V0X0ljb24Ac2V0X0ljb24AZ2V0X0NvYWxlc2NpbmdJRABzZXRfQ29hbGVzY2luZ0lEAFRvSGVhZGVycwBGcm9tSGVhZGVycwBBcHBsaWNhdGlvbk5hbWUATmFtZQBJRABUaXRsZQBUZXh0AFN0aWNreQBJY29uAENvYWxlc2NpbmdJRABOb25lAGhhc2hBbGdvcml0aG0AZW5jcnlwdGlvbkFsZ29yaXRobQBlbmNyeXB0aW9uS2V5AGtleUhhc2gAcGFzc3dvcmQAc2FsdABJbml0aWFsaXplRW1wdHlLZXkAZ2V0X1Bhc3N3b3JkAGdldF9TYWx0AGdldF9FbmNyeXB0aW9uS2V5AGdldF9LZXlIYXNoAGdldF9IYXNoQWxnb3JpdGhtAHNldF9IYXNoQWxnb3JpdGhtAGdldF9FbmNyeXB0aW9uQWxnb3JpdGhtAHNldF9FbmNyeXB0aW9uQWxnb3JpdGhtAEVuY3J5cHQARGVjcnlwdABHZW5lcmF0ZUtleQBDb21wYXJlAFNhbHQARW5jcnlwdGlvbktleQBLZXlIYXNoAEhhc2hBbGdvcml0aG0ARW5jcnlwdGlvbkFsZ29yaXRobQBEQVRBX0hFQURFUl9QUkVGSVgAQ1VTVE9NX0hFQURFUl9QUkVGSVgAR1JPV0xfUkVTT1VSQ0VfUE9JTlRFUl9QUkVGSVgAQk9PTF9IRUFERVJfVFJVRV9WQUxVRQBCT09MX0hFQURFUl9GQUxTRV9WQUxVRQBIRUFERVJfTkFNRV9SRUdFWF9HUk9VUF9OQU1FAEhFQURFUl9WQUxVRV9SRUdFWF9HUk9VUF9OQU1FAFJFU1BPTlNFX0FDVElPTgBBUFBMSUNBVElPTl9OQU1FAEFQUExJQ0FUSU9OX0lDT04ATk9USUZJQ0FUSU9OU19DT1VOVABOT1RJRklDQVRJT05fTkFNRQBOT1RJRklDQVRJT05fRElTUExBWV9OQU1FAE5PVElGSUNBVElPTl9FTkFCTEVEAE5PVElGSUNBVElPTl9JQ09OAE5PVElGSUNBVElPTl9JRABOT1RJRklDQVRJT05fVElUTEUATk9USUZJQ0FUSU9OX1RFWFQATk9USUZJQ0FUSU9OX1NUSUNLWQBOT1RJRklDQVRJT05fUFJJT1JJVFkATk9USUZJQ0FUSU9OX0NPQUxFU0NJTkdfSUQATk9USUZJQ0FUSU9OX0NBTExCQUNLX1JFU1VMVABOT1RJRklDQVRJT05fQ0FMTEJBQ0tfVElNRVNUQU1QAE5PVElGSUNBVElPTl9DQUxMQkFDS19DT05URVhUAE5PVElGSUNBVElPTl9DQUxMQkFDS19DT05URVhUX1RZUEUATk9USUZJQ0FUSU9OX0NBTExCQUNLX1RBUkdFVABOT1RJRklDQVRJT05fQ0FMTEJBQ0tfQ09OVEVYVF9UQVJHRVQAUkVTT1VSQ0VfSURFTlRJRklFUgBSRVNPVVJDRV9MRU5HVEgAT1JJR0lOX01BQ0hJTkVfTkFNRQBPUklHSU5fU09GVFdBUkVfTkFNRQBPUklHSU5fU09GVFdBUkVfVkVSU0lPTgBPUklHSU5fUExBVEZPUk1fTkFNRQBPUklHSU5fUExBVEZPUk1fVkVSU0lPTgBFUlJPUl9DT0RFAEVSUk9SX0RFU0NSSVBUSU9OAFJFQ0VJVkVEAFNVQlNDUklCRVJfSUQAU1VCU0NSSUJFUl9OQU1FAFNVQlNDUklCRVJfUE9SVABTVUJTQ1JJUFRJT05fVFRMAFN5c3RlbS5UZXh0LlJlZ3VsYXJFeHByZXNzaW9ucwBSZWdleAByZWdFeEhlYWRlcgBOb3RGb3VuZEhlYWRlcgB2YWwAaXNWYWxpZABpc0JsYW5rTGluZQBpc0dyb3dsUmVzb3VyY2VQb2ludGVyAGdyb3dsUmVzb3VyY2VQb2ludGVySUQAaXNJZGVudGlmaWVyAGlzQ3VzdG9tSGVhZGVyAGlzRGF0YUhlYWRlcgBCaW5hcnlEYXRhAGdyb3dsUmVzb3VyY2UASW5pdGlhbGl6ZQBnZXRfQWN0dWFsTmFtZQBnZXRfVmFsdWUAZ2V0X0lzVmFsaWQAZ2V0X0lzQmxhbmtMaW5lAGdldF9Jc0N1c3RvbUhlYWRlcgBnZXRfSXNEYXRhSGVhZGVyAGdldF9Jc0lkZW50aWZpZXIAZ2V0X0lzR3Jvd2xSZXNvdXJjZVBvaW50ZXIAZ2V0X0dyb3dsUmVzb3VyY2VQb2ludGVySUQAZ2V0X0dyb3dsUmVzb3VyY2UAc2V0X0dyb3dsUmVzb3VyY2UAUGFyc2VIZWFkZXIAQWN0dWFsTmFtZQBWYWx1ZQBJc1ZhbGlkAElzQmxhbmtMaW5lAElzQ3VzdG9tSGVhZGVyAElzRGF0YUhlYWRlcgBJc0lkZW50aWZpZXIASXNHcm93bFJlc291cmNlUG9pbnRlcgBHcm93bFJlc291cmNlUG9pbnRlcklEAEdyb3dsUmVzb3VyY2UARm9ybWF0TmFtZQBlcnJvckNvZGUAZGVzY3JpcHRpb24AZ2V0X0Vycm9yQ29kZQBnZXRfRXJyb3JEZXNjcmlwdGlvbgBpc09LAGluUmVzcG9uc2VUbwBjYWxsYmFja0RhdGEAcmVxdWVzdERhdGEAZ2V0X0lzT0sAc2V0X0lzT0sAZ2V0X0lzRXJyb3IAZ2V0X0lzQ2FsbGJhY2sAZ2V0X0NhbGxiYWNrRGF0YQBnZXRfSW5SZXNwb25zZVRvAHNldF9JblJlc3BvbnNlVG8AZ2V0X1JlcXVlc3REYXRhAENhbGxiYWNrUmVzdWx0AFNldENhbGxiYWNrRGF0YQBTZXRBdHRyaWJ1dGVzRnJvbUhlYWRlcnMASXNPSwBJc0Vycm9yAElzQ2FsbGJhY2sASW5SZXNwb25zZVRvAEZldGNoAEhFQURFUl9GT1JNQVQAYmxhbmtMaW5lQnl0ZXMAYnl0ZXMAYmluYXJ5RGF0YQBnZXRfQmluYXJ5RGF0YQBBZGRIZWFkZXIAQWRkQmxhbmtMaW5lAEdldFN0cmluZ0J5dGVzAEdldEJ5dGVzAFRvU3RyaW5nAFBST1RPQ09MX05BTUUAUFJPVE9DT0xfVkVSU0lPTgBwcm90b2NvbEhlYWRlckJ5dGVzAG1lc3NhZ2VUeXBlAGtleQBpbmNsdWRlS2V5SGFzaABzZWN0aW9ucwBBZGRNZXNzYWdlU2VjdGlvbgBFbmNyeXB0ZWRCeXRlcwBJVgBkYXRhAHR5cGUAZ2V0X0RhdGEAZ2V0X1R5cGUARGF0YQBUeXBlAGFyZ3MAZ2V0X0FkZGl0aW9uYWxJbmZvAEFkZGl0aW9uYWxJbmZvAFRJTUVEX09VVABVTlJFQ09HTklaRURfUkVRVUVTVABVTlNVUFBPUlRFRF9ESVJFQ1RJVkUAVU5TVVBQT1JURURfVkVSU0lPTgBOT19OT1RJRklDQVRJT05TX1JFR0lTVEVSRUQASU5WQUxJRF9SRVNPVVJDRV9MRU5HVEgATUFMRk9STUVEX1JFUVVFU1QAVU5SRUNPR05JWkVEX1JFU09VUkNFX0hFQURFUgBJTlRFUk5BTF9TRVJWRVJfRVJST1IASU5WQUxJRF9LRVkATUlTU0lOR19LRVkAUkVRVUlSRURfSEVBREVSX01JU1NJTkcAVU5TVVBQT1JURURfSEFTSF9BTEdPUklUSE0AVU5TVVBQT1JURURfRU5DUllQVElPTl9BTEdPUklUSE0AQVBQTElDQVRJT05fTk9UX1JFR0lTVEVSRUQATk9USUZJQ0FUSU9OX1RZUEVfTk9UX1JFR0lTVEVSRUQARkxBU0hfQ09OTkVDVElPTlNfTk9UX0FMTE9XRUQAU1VCU0NSSVBUSU9OU19OT1RfQUxMT1dFRABBTFJFQURZX1BST0NFU1NFRABDT05ORUNUSU9OX0ZBSUxVUkUAV1JJVEVfRkFJTFVSRQBSRUFEX0ZBSUxVUkUAZGlzcGxheU5hbWUAZ2V0X0Rpc3BsYXlOYW1lAHVybABnZXRfQ2FsbGJhY2tVcmwAU2hvdWxkS2VlcENvbm5lY3Rpb25PcGVuAENhbGxiYWNrVXJsAGVuYWJsZWQAc2V0X0Rpc3BsYXlOYW1lAGdldF9FbmFibGVkAHNldF9FbmFibGVkAEVuYWJsZWQATkVUV09SS19GQUlMVVJFAElOVkFMSURfUkVRVUVTVABVTktOT1dOX1BST1RPQ09MAFVOS05PV05fUFJPVE9DT0xfVkVSU0lPTgBOT1RfQVVUSE9SSVpFRABVTktOT1dOX0FQUExJQ0FUSU9OAFVOS05PV05fTk9USUZJQ0FUSU9OAFRDUF9QT1JUAEVPTQBob3N0bmFtZQBwb3J0AGtleUhhc2hBbGdvcml0aG0Ac2V0X1Bhc3N3b3JkAGdldF9LZXlIYXNoQWxnb3JpdGhtAHNldF9LZXlIYXNoQWxnb3JpdGhtAEdldEtleQBPblJlc3BvbnNlUmVjZWl2ZWQAT25Db21tdW5pY2F0aW9uRmFpbHVyZQBPbkJlZm9yZVNlbmQAU2VuZABTZW5kQXN5bmMAS2V5SGFzaEFsZ29yaXRobQBJbnZva2UASUFzeW5jUmVzdWx0AEFzeW5jQ2FsbGJhY2sAQmVnaW5JbnZva2UARW5kSW52b2tlAEdVSUQAQnl0ZXMARGVsZWdhdGUAV2FpdEZvckNhbGxiYWNrAFVzZXJTdGF0ZQBPS1Jlc3BvbnNlAGFkZF9PS1Jlc3BvbnNlAHJlbW92ZV9PS1Jlc3BvbnNlAEVycm9yUmVzcG9uc2UAYWRkX0Vycm9yUmVzcG9uc2UAcmVtb3ZlX0Vycm9yUmVzcG9uc2UATm90aWZpY2F0aW9uQ2FsbGJhY2sAYWRkX05vdGlmaWNhdGlvbkNhbGxiYWNrAHJlbW92ZV9Ob3RpZmljYXRpb25DYWxsYmFjawBJc0dyb3dsUnVubmluZwBJc0dyb3dsUnVubmluZ0xvY2FsbHkAUmVnaXN0ZXIATm90aWZ5AE9uT0tSZXNwb25zZQBPbkVycm9yUmVzcG9uc2UAT25Ob3RpZmljYXRpb25DYWxsYmFjawB2YWx1ZV9fAE9LAENBTExCQUNLAEVSUk9SAFZlcnlMb3cATW9kZXJhdGUATm9ybWFsAEhpZ2gARW1lcmdlbmN5AHJlc3VsdABub3RpZmljYXRpb25JRABnZXRfUmVzdWx0AGdldF9Ob3RpZmljYXRpb25JRABSZXN1bHQATm90aWZpY2F0aW9uSUQAaGV4Q2hhcnQAU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeQBSYW5kb21OdW1iZXJHZW5lcmF0b3IAcm5nAGhhc2hUeXBlcwBlbmNyeXB0aW9uVHlwZXMALmNjdG9yAENvbXB1dGVIYXNoAEdlbmVyYXRlQnl0ZXMASGV4RW5jb2RlAEhleFVuZW5jb2RlAEdldEtleUhhc2hUeXBlAEdldEVuY3J5cHRpb25UeXBlAEdldEtleUZyb21TaXplAE1ENQBTSEExAFNIQTI1NgBTSEEzODQAU0hBNTEyAFBsYWluVGV4dABSQzIAREVTAFRyaXBsZURFUwBBRVMAaGVhZGVycwBjdXN0b21IZWFkZXJzAGRhdGFIZWFkZXJzAHBvaW50ZXJzAGFsbEhlYWRlcnMAQWRkSGVhZGVycwBnZXRfSGVhZGVycwBnZXRfQ3VzdG9tSGVhZGVycwBnZXRfRGF0YUhlYWRlcnMAZ2V0X1BvaW50ZXJzAEFzc29jaWF0ZUJpbmFyeURhdGEAR2V0AEdldEhlYWRlclN0cmluZ1ZhbHVlAEdldEhlYWRlckJvb2xlYW5WYWx1ZQBHZXRIZWFkZXJJbnRWYWx1ZQBHZXRIZWFkZXJSZXNvdXJjZVZhbHVlAEZyb21NZXNzYWdlAFRocm93UmVxdWlyZWRIZWFkZXJNaXNzaW5nRXhjZXB0aW9uAEhlYWRlcnMAQ3VzdG9tSGVhZGVycwBEYXRhSGVhZGVycwBQb2ludGVycwBSRUdJU1RFUgBOT1RJRlkAU1VCU0NSSUJFAHJlY2VpdmVkRnJvbQByZWNlaXZlZEJ5AERhdGVUaW1lAHRpbWVSZWNlaXZlZAByZWNlaXZlZFdpdGgAcmVxdWVzdElEAHByZXZpb3VzUmVjZWl2ZWRIZWFkZXJzAGhhbmRsaW5nSW5mbwBnZXRfUmVjZWl2ZWRGcm9tAHNldF9SZWNlaXZlZEZyb20AZ2V0X1JlY2VpdmVkQnkAc2V0X1JlY2VpdmVkQnkAZ2V0X1JlY2VpdmVkV2l0aABzZXRfUmVjZWl2ZWRXaXRoAGdldF9UaW1lUmVjZWl2ZWQAZ2V0X1JlcXVlc3RJRABnZXRfUHJldmlvdXNSZWNlaXZlZEhlYWRlcnMAU2F2ZUhhbmRsaW5nSW5mbwBnZXRfSGFuZGxpbmdJbmZvAFdhc0ZvcndhcmRlZABSZWNlaXZlZEZyb20AUmVjZWl2ZWRCeQBSZWNlaXZlZFdpdGgAVGltZVJlY2VpdmVkAFJlcXVlc3RJRABQcmV2aW91c1JlY2VpdmVkSGVhZGVycwBIYW5kbGluZ0luZm8AcGFzc3dvcmRzAGdldF9QYXNzd29yZHMAQWRkAFJlbW92ZQBQYXNzd29yZHMAREVGQVVMVF9ERVNDUklQVElPTgBwZXJtYW5lbnQAU2VyaWFsaXphdGlvbkluZm8AU3RyZWFtaW5nQ29udGV4dABnZXRfQWN0dWFsUGFzc3dvcmQAc2V0X0FjdHVhbFBhc3N3b3JkAGdldF9EZXNjcmlwdGlvbgBzZXRfRGVzY3JpcHRpb24AZ2V0X1Blcm1hbmVudABzZXRfUGVybWFuZW50AEdldE9iamVjdERhdGEAQWN0dWFsUGFzc3dvcmQARGVzY3JpcHRpb24AUGVybWFuZW50AEdOVFBfU1VQUE9SVEVEX1ZFUlNJT04AQkxBTktfTElORQByZWdFeE1lc3NhZ2VIZWFkZXIAdmVyc2lvbgBkaXJlY3RpdmUAUGFyc2UATWF0Y2gAUGFyc2VHTlRQSGVhZGVyTGluZQBTeXN0ZW0uUmVmbGVjdGlvbgBBc3NlbWJseUluZm9ybWF0aW9uYWxWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlWZXJzaW9uQXR0cmlidXRlAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBHdWlkQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlDdWx0dXJlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBTeXN0ZW0uRGlhZ25vc3RpY3MARGVidWdnYWJsZUF0dHJpYnV0ZQBEZWJ1Z2dpbmdNb2RlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAb2JqAFN0cmluZwBJc051bGxPckVtcHR5AEVudW1lcmF0b3IAR2V0RW51bWVyYXRvcgBLZXlWYWx1ZVBhaXJgMgBnZXRfQ3VycmVudABnZXRfS2V5AE1vdmVOZXh0AElEaXNwb3NhYmxlAERpc3Bvc2UAb3BfSW1wbGljaXQARW52aXJvbm1lbnQAQXNzZW1ibHkAR2V0RXhlY3V0aW5nQXNzZW1ibHkAQXNzZW1ibHlOYW1lAEdldE5hbWUAVmVyc2lvbgBnZXRfVmVyc2lvbgBPcGVyYXRpbmdTeXN0ZW0AZ2V0X09TVmVyc2lvbgBub3RpZmljYXRpb25OYW1lAHZhbHVlAEludDMyAGdldF9Jc1NldABFbXB0eQBUcnlQYXJzZQBSdW50aW1lVHlwZUhhbmRsZQBHZXRUeXBlRnJvbUhhbmRsZQBJc0RlZmluZWQAU3lzdGVtLlRleHQARW5jb2RpbmcAZ2V0X1VURjgAQnl0ZQBBcnJheQBDb3B5AGl2AGVuY3J5cHRlZEJ5dGVzAG1hdGNoaW5nS2V5AE91dEF0dHJpYnV0ZQBvcF9FcXVhbGl0eQBnZXRfSXNSYXdEYXRhAFN0cmluZ0NvbXBhcmlzb24AU3RhcnRzV2l0aABSZXBsYWNlAGdldF9MZW5ndGgAbGluZQBUcmltAEdyb3VwAGdldF9TdWNjZXNzAEdyb3VwQ29sbGVjdGlvbgBnZXRfR3JvdXBzAGdldF9JdGVtAENhcHR1cmUARm9ybWF0AGVycm9yRGVzY3JpcHRpb24AY2FsbGJhY2tDb250ZXh0AGNhbGxiYWNrUmVzdWx0AGdldF9VdGNOb3cAaXNDYWxsYmFjawBlbnVtRmllbGQAQXJndW1lbnROdWxsRXhjZXB0aW9uAEdldFR5cGUAZ2V0X1VuZGVybHlpbmdTeXN0ZW1UeXBlAEZpZWxkSW5mbwBHZXRGaWVsZABNZW1iZXJJbmZvAEdldEN1c3RvbUF0dHJpYnV0ZXMAaGVhZGVyAElFbnVtZXJhYmxlYDEAQWRkUmFuZ2UAVG9BcnJheQBHZXRTdHJpbmcAZ2V0X05ld0xpbmUAQ29uY2F0AHNlY3Rpb24AVG9VcHBlcgBTdHJ1Y3RMYXlvdXRBdHRyaWJ1dGUATGF5b3V0S2luZABTZXJpYWxpemFibGVBdHRyaWJ1dGUAUGFyYW1BcnJheUF0dHJpYnV0ZQBBdHRyaWJ1dGVVc2FnZUF0dHJpYnV0ZQBBdHRyaWJ1dGVUYXJnZXRzAEJvb2xlYW4Ab3BfSW5lcXVhbGl0eQByZXNwb25zZVRleHQAc3RhdGUAcmVzcG9uc2UAbWIAZGVsAHdhaXRGb3JDYWxsYmFjawBTeXN0ZW0uVGhyZWFkaW5nAFBhcmFtZXRlcml6ZWRUaHJlYWRTdGFydABUaHJlYWQAU3RhcnQAU3lzdGVtLk5ldC5Tb2NrZXRzAFRjcENsaWVudABDb25uZWN0AE5ldHdvcmtTdHJlYW0AR2V0U3RyZWFtAFN5c3RlbS5JTwBTdHJlYW0AV3JpdGUAUmVhZABFbmRzV2l0aABEZWJ1Z0luZm8AV3JpdGVMaW5lAFNvY2tldABnZXRfQ2xpZW50AHNldF9CbG9ja2luZwBTb2NrZXRTaHV0ZG93bgBTaHV0ZG93bgBDbG9zZQBvYmplY3QAbWV0aG9kAGNhbGxiYWNrAEd1aWQATmV3R3VpZABDb21iaW5lAE9ic29sZXRlQXR0cmlidXRlAERldGVjdG9yAERldGVjdElmR3Jvd2xJc1J1bm5pbmcAYXBwbGljYXRpb24Abm90aWZpY2F0aW9uVHlwZXMAbm90aWZpY2F0aW9uAFN5c3RlbS5Db21wb25lbnRNb2RlbABEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDcmVhdGUAR2V0VmFsdWVzAFN5c3RlbS5Db2xsZWN0aW9ucwBJRW51bWVyYXRvcgBpbnB1dFN0cmluZwBnZXRfTWVzc2FnZQBDcnlwdG9ncmFwaGljRXhjZXB0aW9uAGhhc2hBbGdvcml0aG1UeXBlAGlucHV0Qnl0ZXMAU0hBMU1hbmFnZWQAU0hBMjU2TWFuYWdlZABTSEEzODRNYW5hZ2VkAFNIQTUxMk1hbmFnZWQATUQ1Q3J5cHRvU2VydmljZVByb3ZpZGVyAGFsZ29yaXRobVR5cGUAUkMyQ3J5cHRvU2VydmljZVByb3ZpZGVyAERFU0NyeXB0b1NlcnZpY2VQcm92aWRlcgBUcmlwbGVERVNDcnlwdG9TZXJ2aWNlUHJvdmlkZXIAUmlqbmRhZWxNYW5hZ2VkAFN5bW1ldHJpY0FsZ29yaXRobQBzZXRfS2V5AEdlbmVyYXRlSVYAc2V0X0lWAGdldF9JVgBQYWRkaW5nTW9kZQBzZXRfUGFkZGluZwBDaXBoZXJNb2RlAHNldF9Nb2RlAElDcnlwdG9UcmFuc2Zvcm0AQ3JlYXRlRW5jcnlwdG9yAFRyYW5zZm9ybUZpbmFsQmxvY2sAZ2V0X0Jsb2NrU2l6ZQBzZXRfQmxvY2tTaXplAENyZWF0ZURlY3J5cHRvcgBsZW5ndGgAR2V0Tm9uWmVyb0J5dGVzAFN0cmluZ0J1aWxkZXIAZ2V0X0NoYXJzAEFwcGVuZABoZXhTdHJpbmcAU3Vic3RyaW5nAFN5c3RlbS5HbG9iYWxpemF0aW9uAE51bWJlclN0eWxlcwBJRm9ybWF0UHJvdmlkZXIAQ29udGFpbnNLZXkAa2V5U2l6ZQBBcmd1bWVudE91dE9mUmFuZ2VFeGNlcHRpb24AcmVxdWlyZWQAQ29udmVydABUb0ludDMyAG1lc3NhZ2UAQ2hhcgBTcGxpdABoZWFkZXJOYW1lAGluZm8AZ2V0X0NvdW50AFZhbHVlQ29sbGVjdGlvbgBnZXRfVmFsdWVzAGNvbnRleHQAR2V0Qm9vbGVhbgBCYXNlNjQARGVjb2RlAEVuY29kZQBBZGRWYWx1ZQBNZW1vcnlTdHJlYW0AU3RyZWFtUmVhZGVyAFRleHRSZWFkZXIAUmVhZExpbmUAZ2V0X0VuZE9mU3RyZWFtAAAnTwByAGkAZwBpAG4ALQBNAGEAYwBoAGkAbgBlAC0ATgBhAG0AZQABKU8AcgBpAGcAaQBuAC0AUwBvAGYAdAB3AGEAcgBlAC0ATgBhAG0AZQABL08AcgBpAGcAaQBuAC0AUwBvAGYAdAB3AGEAcgBlAC0AVgBlAHIAcwBpAG8AbgABKU8AcgBpAGcAaQBuAC0AUABsAGEAdABmAG8AcgBtAC0ATgBhAG0AZQABL08AcgBpAGcAaQBuAC0AUABsAGEAdABmAG8AcgBtAC0AVgBlAHIAcwBpAG8AbgABHUcAcgBvAHcAbABDAG8AbgBuAGUAYwB0AG8AcgAAIUEAcABwAGwAaQBjAGEAdABpAG8AbgAtAE4AYQBtAGUAASNOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAE4AYQBtAGUAAR9OAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEkARAABJU4AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0AVABpAHQAbABlAAEjTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBUAGUAeAB0AAEnTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBTAHQAaQBjAGsAeQABK04AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0AUAByAGkAbwByAGkAdAB5AAEjTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBJAGMAbwBuAAE1TgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBDAG8AYQBsAGUAcwBjAGkAbgBnAC0ASQBEAAEFTgBvAAAHWQBlAHMAACd4AC0AZwByAG8AdwBsAC0AcgBlAHMAbwB1AHIAYwBlADoALwAvAAEBABVJAGQAZQBuAHQAaQBmAGkAZQByAAAFWAAtAAELRABhAHQAYQAtAAEVSABlAGEAZABlAHIATgBhAG0AZQAAF0gAZQBhAGQAZQByAFYAYQBsAHUAZQAAeSgAPwA8AEgAZQBhAGQAZQByAE4AYQBtAGUAPgBbAF4AXAByAFwAbgA6AF0AKwApADoAXABzACsAKAA/ADwASABlAGEAZABlAHIAVgBhAGwAdQBlAD4AKABbAFwAcwBcAFMAXQAqAFwAWgApAHwAKAAuACsAKQApAAANewAwAH0AewAxAH0AABVFAHIAcgBvAHIALQBDAG8AZABlAAEjRQByAHIAbwByAC0ARABlAHMAYwByAGkAcAB0AGkAbwBuAAEfUgBlAHMAcABvAG4AcwBlAC0AQQBjAHQAaQBvAG4AATlOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEMAYQBsAGwAYgBhAGMAawAtAFIAZQBzAHUAbAB0AAE7TgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBDAGEAbABsAGIAYQBjAGsALQBDAG8AbgB0AGUAeAB0AAFFTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBDAGEAbABsAGIAYQBjAGsALQBDAG8AbgB0AGUAeAB0AC0AVAB5AHAAZQABP04AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0AQwBhAGwAbABiAGEAYwBrAC0AVABpAG0AZQBzAHQAYQBtAHAAAQN1AAATZQBuAHUAbQBGAGkAZQBsAGQAAFlGAGUAdABjAGgAOgAgACcAZQBuAHUAbQBGAGkAZQBsAGQAJwAgAHAAYQByAGEAbQBlAHQAZQByACAAYwBhAG4AbgBvAHQAIABiAGUAIABuAHUAbABsAC4AAQMNAAAVewAwAH0AOgAgAHsAMQB9AA0ACgAAAy0AAQ97ADAAfQA6AHsAMQB9AAAXewAwAH0AOgB7ADEAfQAuAHsAMgB9AAAXewAwAH0AIAB7ADEAfQAgAHsAMgB9AAANTABlAG4AZwB0AGgAABF7ADAAfQAvAHsAMQB9ACAAAAlHAE4AVABQAAAHMQAuADAAACFBAHAAcABsAGkAYwBhAHQAaQBvAG4ALQBJAGMAbwBuAAEtVQBuAGQAZQBmAGkAbgBlAGQAIABOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAAM04AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0ARABpAHMAcABsAGEAeQAtAE4AYQBtAGUAASlOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEUAbgBhAGIAbABlAGQAARMxADIANwAuADAALgAwAC4AMQAAUVQAaABlACAAZABlAHMAdABpAG4AYQB0AGkAbwBuACAAcwBlAHIAdgBlAHIAIAB3AGEAcwAgAG4AbwB0ACAAcgBlAGEAYwBoAGEAYgBsAGUAAICJVABoAGUAIAByAGUAcQB1AGUAcwB0ACAAZgBhAGkAbABlAGQAIAB0AG8AIABiAGUAIABzAGUAbgB0ACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABkAHUAZQAgAHQAbwAgAGEAIABuAGUAdAB3AG8AcgBrACAAcAByAG8AYgBsAGUAbQAuAAAJDQAKAA0ACgAAgItUAGgAZQAgAHIAZQBzAHAAbwBuAHMAZQAgAGYAYQBpAGwAZQBkACAAdABvACAAYgBlACAAcgBlAGEAZAAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACAAZAB1AGUAIAB0AG8AIABhACAAbgBlAHQAdwBvAHIAawAgAHAAcgBvAGIAbABlAG0ALgAAJ04AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAHMALQBDAG8AdQBuAHQAATlOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEMAYQBsAGwAYgBhAGMAawAtAFQAYQByAGcAZQB0AAEXaQBuAHAAdQB0AFMAdAByAGkAbgBnAABnQwBvAG0AcAB1AHQAZQBIAGEAcwBoADoAIAAnAGkAbgBwAHUAdABTAHQAcgBpAG4AZwAnACAAcABhAHIAYQBtAGUAdABlAHIAIABjAGEAbgBuAG8AdAAgAGIAZQAgAG4AdQBsAGwAAS1DAG8AbQBwAHUAdABlAEgAYQBzAGgAOgAgAHsAMAB9ACAALQAgAHsAMQB9AAEVaQBuAHAAdQB0AEIAeQB0AGUAcwAAZUMAbwBtAHAAdQB0AGUASABhAHMAaAA6ACAAJwBpAG4AcAB1AHQAQgB5AHQAZQBzACcAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGMAYQBuAG4AbwB0ACAAYgBlACAAbgB1AGwAbAABXUUAbgBjAHIAeQBwAHQAOgAgACcAaQBuAHAAdQB0AEIAeQB0AGUAcwAnACAAcABhAHIAYQBtAGUAdABlAHIAIABjAGEAbgBuAG8AdAAgAGIAZQAgAG4AdQBsAGwAAYDLRQBuAGMAcgB5AHAAdAA6ACAAQQBsAGcAbwByAGkAdABoAG0AIAAnAHsAMAB9ACcAIAByAGUAcQB1AGkAcgBlAHMAIABhAG4AIABtAGkAbgBpAG0AdQBtACAAawBlAHkAIABzAGkAegBlACAAbwBmACAAewAxAH0AIAAtACAAKAB5AG8AdQAgAHMAdQBwAHAAbABpAGUAZAAgAGEAIABrAGUAeQAgAHQAaABhAHQAIAB3AGEAcwAgAHsAMgB9ACAAbABvAG4AZwApAAGAuUUAbgBjAHIAeQBwAHQAOgAgAEEAbABnAG8AcgBpAHQAaABtACAAJwB7ADAAfQAnACAAcgBlAHEAdQBpAHIAZQBzACAAYQBuACAASQBWACAAcwBpAHoAZQAgAG8AZgAgAHsAMQB9ACAALQAgACgAeQBvAHUAIABzAHUAcABwAGwAaQBlAGQAIABhAG4AIABJAFYAIAB0AGgAYQB0ACAAdwBhAHMAIAB7ADIAfQAgAGwAbwBuAGcAKQABJUUAbgBjAHIAeQBwAHQAOgAgAHsAMAB9ACAALQAgAHsAMQB9AAElRABlAGMAcgB5AHAAdAA6ACAAewAwAH0AIAAtACAAewAxAH0AAR1lAG4AYwByAHkAcAB0AGUAZABCAHkAdABlAHMAAGVEAGUAYwByAHkAcAB0ADoAIAAnAGUAbgBjAHIAeQBwAHQAZQBkAEIAeQB0AGUAcwAnACAAcABhAHIAYQBtAGUAdABlAHIAIABjAGEAbgBuAG8AdAAgAGIAZQAgAG4AdQBsAGwAAYDLRABlAGMAcgB5AHAAdAA6ACAAQQBsAGcAbwByAGkAdABoAG0AIAAnAHsAMAB9ACcAIAByAGUAcQB1AGkAcgBlAHMAIABhAG4AIABtAGkAbgBpAG0AdQBtACAAawBlAHkAIABzAGkAegBlACAAbwBmACAAewAxAH0AIAAtACAAKAB5AG8AdQAgAHMAdQBwAHAAbABpAGUAZAAgAGEAIABrAGUAeQAgAHQAaABhAHQAIAB3AGEAcwAgAHsAMgB9ACAAbABvAG4AZwApAAGAuUQAZQBjAHIAeQBwAHQAOgAgAEEAbABnAG8AcgBpAHQAaABtACAAJwB7ADAAfQAnACAAcgBlAHEAdQBpAHIAZQBzACAAYQBuACAASQBWACAAcwBpAHoAZQAgAG8AZgAgAHsAMQB9ACAALQAgACgAeQBvAHUAIABzAHUAcABwAGwAaQBlAGQAIABhAG4AIABJAFYAIAB0AGgAYQB0ACAAdwBhAHMAIAB7ADIAfQAgAGwAbwBuAGcAKQABC2IAeQB0AGUAcwAAV0gAZQB4AEUAbgBjAG8AZABlADoAIAAnAGIAeQB0AGUAcwAnACAAcABhAHIAYQBtAGUAdABlAHIAIABjAGEAbgBuAG8AdAAgAGIAZQAgAG4AdQBsAGwAASEwADEAMgAzADQANQA2ADcAOAA5AEEAQgBDAEQARQBGAAApSABlAHgARQBuAGMAbwBkAGUAOgAgAHsAMAB9ACAALQAgAHsAMQB9AAETaABlAHgAUwB0AHIAaQBuAGcAAGNIAGUAeABVAG4AZQBuAGMAbwBkAGUAOgAgACcAaABlAHgAUwB0AHIAaQBuAGcAJwAgAHAAYQByAGEAbQBlAHQAZQByACAAYwBhAG4AbgBvAHQAIABiAGUAIABuAHUAbABsAAFXTgBvACAAbQBhAHQAYwBoAGkAbgBnACAAaABhAHMAaAAgAHQAeQBwAGUAIABmAG8AdQBuAGQAIABmAG8AcgAgAG4AYQBtAGUAIAAnAHsAMAB9ACcALgABbU4AbwAgAG0AYQB0AGMAaABpAG4AZwAgAGUAbgBjAHIAeQBwAHQAaQBvAG4AIABhAGwAZwBvAHIAaQB0AGgAbQAgAGYAbwB1AG4AZAAgAGYAbwByACAAbgBhAG0AZQAgACcAewAwAH0AJwAuAAEPawBlAHkAUwBpAHoAZQAAgM1HAGUAdABLAGUAeQBGAHIAbwBtAFMAaQB6AGUAOgAgAFQAaABlACAAcgBlAHEAdQBlAHMAdABlAGQAIABrAGUAeQAgAHMAaQB6AGUAIABpAHMAIABsAG8AbgBnAGUAcgAgAHQAaABhAG4AIAB0AGgAZQAgAHMAdQBwAHAAbABpAGUAZAAgAGsAZQB5AC4AIABLAGUAeQAgAHMAaQB6AGUAOgAgAHsAMAB9ACwAIABrAGUAeQAgAGwAZQBuAGcAdABoADoAIAB7ADEAfQAAM0cAZQB0AEsAZQB5AEYAcgBvAG0AUwBpAHoAZQA6ACAAewAwAH0AIAAtACAAewAxAH0AAQlUAFIAVQBFAAAHWQBFAFMAAC9SAGUAcQB1AGkAcgBlAGQAIABoAGUAYQBkAGUAcgAgAG0AaQBzAHMAaQBuAGcAADNbAE4AbwAgAGQAZQBzAGMAcgBpAHAAdABpAG8AbgAgAHAAcgBvAHYAaQBkAGUAZABdAAARcABhAHMAcwB3AG8AcgBkAAAXZABlAHMAYwByAGkAcAB0AGkAbwBuAAATcABlAHIAbQBhAG4AZQBuAHQAAA9WAGUAcgBzAGkAbwBuAAATRABpAHIAZQBjAHQAaQB2AGUAADVVAG4AcgBlAGMAbwBnAG4AaQB6AGUAZAAgAHIAZQBzAHAAbwBuAHMAZQAgAHQAeQBwAGUAACdVAG4AcwB1AHAAcABvAHIAdABlAGQAIAB2AGUAcgBzAGkAbwBuAAArVQBuAHIAZQBjAG8AZwBuAGkAegBlAGQAIAByAGUAcwBwAG8AbgBzAGUAACtJAG4AdABlAHIAbgBhAGwAIABzAGUAcgB2AGUAcgAgAGUAcgByAG8AcgAAXygARwBOAFQAUAAvACkAKAA/ADwAVgBlAHIAcwBpAG8AbgA+ACgALgBcAC4ALgApACkAXABzACsAKAA/ADwARABpAHIAZQBjAHQAaQB2AGUAPgAoAFwAUwArACkAKQAAAAAqaOwSTtmlQqy7pRQZnwSvAAi3elxWGTTgiQYVEh0BEhQGFRIlAg4OAgYOBwYVEiUCDg4IE+WdguAHsGQIBhUSJQIOEikDIAABAyAADgggABUSJQIODgkgABUSJQIOEikGIAEBEoCECAACARIIEoCEBQACAQ4OAygADggoABUSJQIODgkoABUSJQIOEikCBgIDBhFwAwYSKQggBQEODg4ODg4gCQEODg4ODhIpAhFwDgQgAQEOAyAAAgQgAQECBCAAEXAFIAEBEXAEIAASKQUgAQESKQUgABKAhAcAARIMEoCEAygAAgQoABFwBCgAEikDBhIQAwYRfAQGEYCAAwYdBQkgAwEOEXwRgIAEIAAdBQQgABF8BSABARF8BSAAEYCABiABARGAgAYgAREwHQUJIAIRMB0FEB0FCCACHQUdBR0FCgADEhAOEXwRgIAOAAYCDg4OEXwRgIAQEhAEKAAdBQQoABF8BSgAEYCACkQAYQB0AGEALQAEWAAtACZ4AC0AZwByAG8AdwBsAC0AcgBlAHMAbwB1AHIAYwBlADoALwAvAAZZAGUAcwAETgBvABRIAGUAYQBkAGUAcgBOAGEAbQBlABZIAGUAYQBkAGUAcgBWAGEAbAB1AGUAHlIAZQBzAHAAbwBuAHMAZQAtAEEAYwB0AGkAbwBuACBBAHAAcABsAGkAYwBhAHQAaQBvAG4ALQBOAGEAbQBlACBBAHAAcABsAGkAYwBhAHQAaQBvAG4ALQBJAGMAbwBuACZOAG8AdABpAGYAaQBjAGEAdABpAG8AbgBzAC0AQwBvAHUAbgB0ACJOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAE4AYQBtAGUAMk4AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0ARABpAHMAcABsAGEAeQAtAE4AYQBtAGUAKE4AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0ARQBuAGEAYgBsAGUAZAAiTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBJAGMAbwBuAB5OAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEkARAAkTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBUAGkAdABsAGUAIk4AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0AVABlAHgAdAAmTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBTAHQAaQBjAGsAeQAqTgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBQAHIAaQBvAHIAaQB0AHkANE4AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAC0AQwBvAGEAbABlAHMAYwBpAG4AZwAtAEkARAA4TgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBDAGEAbABsAGIAYQBjAGsALQBSAGUAcwB1AGwAdAA+TgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBDAGEAbABsAGIAYQBjAGsALQBUAGkAbQBlAHMAdABhAG0AcAA6TgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4ALQBDAGEAbABsAGIAYQBjAGsALQBDAG8AbgB0AGUAeAB0AEROAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEMAYQBsAGwAYgBhAGMAawAtAEMAbwBuAHQAZQB4AHQALQBUAHkAcABlADhOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEMAYQBsAGwAYgBhAGMAawAtAFQAYQByAGcAZQB0AEhOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAtAEMAYQBsAGwAYgBhAGMAawAtAEMAbwBuAHQAZQB4AHQALQBUAGEAcgBnAGUAdAAUSQBkAGUAbgB0AGkAZgBpAGUAcgAMTABlAG4AZwB0AGgAJk8AcgBpAGcAaQBuAC0ATQBhAGMAaABpAG4AZQAtAE4AYQBtAGUAKE8AcgBpAGcAaQBuAC0AUwBvAGYAdAB3AGEAcgBlAC0ATgBhAG0AZQAuTwByAGkAZwBpAG4ALQBTAG8AZgB0AHcAYQByAGUALQBWAGUAcgBzAGkAbwBuAChPAHIAaQBnAGkAbgAtAFAAbABhAHQAZgBvAHIAbQAtAE4AYQBtAGUALk8AcgBpAGcAaQBuAC0AUABsAGEAdABmAG8AcgBtAC0AVgBlAHIAcwBpAG8AbgAURQByAHIAbwByAC0AQwBvAGQAZQAiRQByAHIAbwByAC0ARABlAHMAYwByAGkAcAB0AGkAbwBuABBSAGUAYwBlAGkAdgBlAGQAGlMAdQBiAHMAYwByAGkAYgBlAHIALQBJAEQAHlMAdQBiAHMAYwByAGkAYgBlAHIALQBOAGEAbQBlAB5TAHUAYgBzAGMAcgBpAGIAZQByAC0AUABvAHIAdAAgUwB1AGIAcwBjAHIAaQBwAHQAaQBvAG4ALQBUAFQATAADBhItAwYSFAMGEjEFIAIBDg4FIAIBDgIGIAIBDhIpBCAAEjEFIAEBEjEFAAESFA4EKAASMQQAAQ4OAgYIBSACAQgOAyAACAcAARIcEoCEAygACAMGEnQEBhKAnAQgABJ0BSAAEoCcCCADAQ4SSBE1BwABEiASgIQHIAIBEoCEAgQoABJ0BSgAEoCcBAABDhwUewAwAH0AOgAgAHsAMQB9AA0ACgAGBhUSHQEFBwYVEh0BEjEIIAAVEh0BEjEFIAEBEhQFAAEdBQ4IKAAVEh0BEjEIRwBOAFQAUAAGMQAuADAABwYVEh0BEigIIAIBEYCIEhAFIAEBEWwHIAMBDhIQAgUgAQESKAcgAgEdBR0FBwABEjQSgIQDBh0cByADAQgOHRwEIAAdHAQoAB0celQAaABlACAAcwBlAHIAdgBlAHIAIAB0AGkAbQBlAGQAIABvAHUAdAAgAHcAYQBpAHQAaQBuAGcAIABmAG8AcgAgAHQAaABlACAAcgBlAG0AYQBpAG4AZABlAHIAIABvAGYAIAB0AGgAZQAgAHIAZQBxAHUAZQBzAHQAKFUAbgByAGUAYwBvAGcAbgBpAHoAZQBkACAAcgBlAHEAdQBlAHMAdAAqVQBuAHMAdQBwAHAAbwByAHQAZQBkACAAZABpAHIAZQBjAHQAaQB2AGUAJlUAbgBzAHUAcABwAG8AcgB0AGUAZAAgAHYAZQByAHMAaQBvAG4ANk4AbwAgAG4AbwB0AGkAZgBpAGMAYQB0AGkAbwBuAHMAIAByAGUAZwBpAHMAdABlAHIAZQBkAC5JAG4AdgBhAGwAaQBkACAAcgBlAHMAbwB1AHIAYwBlACAAbABlAG4AZwB0AGgAIk0AYQBsAGYAbwByAG0AZQBkACAAcgBlAHEAdQBlAHMAdAA4VQBuAHIAZQBjAG8AZwBuAGkAegBlAGQAIAByAGUAcwBvAHUAcgBjAGUAIABoAGUAYQBkAGUAcgAqSQBuAHQAZQByAG4AYQBsACAAcwBlAHIAdgBlAHIAIABlAHIAcgBvAHIAIEkAbgB2AGEAbABpAGQAIABrAGUAeQAgAGgAYQBzAGgAIE0AaQBzAHMAaQBuAGcAIABrAGUAeQAgAGgAYQBzAGgALlIAZQBxAHUAaQByAGUAZAAgAGgAZQBhAGQAZQByACAAbQBpAHMAcwBpAG4AZwBGVQBuAHMAdQBwAHAAbwByAHQAZQBkACAAcABhAHMAcwB3AG8AcgBkACAAaABhAHMAaAAgAGEAbABnAG8AcgBpAHQAaABtAEBVAG4AcwB1AHAAcABvAHIAdABlAGQAIABlAG4AYwByAHkAcAB0AGkAbwBuACAAYQBsAGcAbwByAGkAdABoAG0ANEEAcABwAGwAaQBjAGEAdABpAG8AbgAgAG4AbwB0ACAAcgBlAGcAaQBzAHQAZQByAGUAZABATgBvAHQAaQBmAGkAYwBhAHQAaQBvAG4AIAB0AHkAcABlACAAbgBvAHQAIAByAGUAZwBpAHMAdABlAHIAZQBkAE5GAGwAYQBzAGgALQBiAGEAcwBlAGQAIABjAG8AbgBuAGUAYwB0AGkAbwBuAHMAIABhAHIAZQAgAG4AbwB0ACAAYQBsAGwAbwB3AGUAZABQVABoAGkAcwAgAHMAZQByAHYAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAYQBsAGwAbwB3ACAAcwB1AGIAcwBjAHIAaQBwAHQAaQBvAG4AcwCBJFQAaABlACAAcgBlAHEAdQBlAHMAdAAgAHcAYQBzACAAYQBsAHIAZQBhAGQAeQAgAGgAYQBuAGQAbABlAGQAIABiAHkAIAB0AGgAaQBzACAAbQBhAGMAaABpAG4AZQAuACAAKABOAG8AcgBtAGEAbABsAHkALAAgAHQAaABpAHMAIABtAGUAYQBuAHMAIAB0AGgAZQAgAG0AZQBzAHMAYQBnAGUAIAB3AGEAcwAgAGYAbwByAHcAYQByAGQAZQBkACAAYgBhAGMAawAgAHQAbwAgAGEAIABtAGEAYwBoAGkAbgBlACAAdABoAGEAdAAgAGgAYQBkACAAYQBsAHIAZQBhAGQAeQAgAGYAbwByAHcAYQByAGQAZQBkACAAaQB0AC4AKQBQVABoAGUAIABkAGUAcwB0AGkAbgBhAHQAaQBvAG4AIABzAGUAcgB2AGUAcgAgAHcAYQBzACAAbgBvAHQAIAByAGUAYQBjAGgAYQBiAGwAZQCAiFQAaABlACAAcgBlAHEAdQBlAHMAdAAgAGYAYQBpAGwAZQBkACAAdABvACAAYgBlACAAcwBlAG4AdAAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACAAZAB1AGUAIAB0AG8AIABhACAAbgBlAHQAdwBvAHIAawAgAHAAcgBvAGIAbABlAG0ALgCAilQAaABlACAAcgBlAHMAcABvAG4AcwBlACAAZgBhAGkAbABlAGQAIAB0AG8AIABiAGUAIAByAGUAYQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABkAHUAZQAgAHQAbwAgAGEAIABuAGUAdAB3AG8AcgBrACAAcAByAG8AYgBsAGUAbQAuAAcAARJEEoCEBwABEkgSgIQIIAQBDg4SKQIHAAESTBKAhATIAAAABMkAAAAELAEAAAQtAQAABC4BAAAELwEAAASQAQAABJEBAAAEkgEAAASTAQAABPQBAAAEDVoAAAgNAAoADQAKAAYgAwEODggEIAASEAUgAgEOHAYgAgESIBwFIAECEiwJIAQBEiwSWAIc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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAQAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQABAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAASAAAAFjgAABQAwAAAAAAAAAAAABQAzQAAABWAFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAIAAQAEAAAAAgAAAAQAPwAAAAAAAAAEAAAAAgAAAAAAAAAAAAAAAAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEAbgBzAGwAYQB0AGkAbwBuAAAAAAAAALAEsAIAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAAjAIAAAEAMAAwADAAMAAwADQAYgAwAAAATAAVAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAAAABlAGwAZQBtAGUAbgB0ACAAYwBvAGQAZQAgAHAAcgBvAGoAZQBjAHQAAAAAAEgAEAABAEYAaQBsAGUARABlAHMAYwByAGkAcAB0AGkAbwBuAAAAAABHAHIAbwB3AGwALgBDAG8AbgBuAGUAYwB0AG8AcgAAADAACAABAEYAaQBsAGUAVgBlAHIAcwBpAG8AbgAAAAAAMgAuADAALgA0AC4AMQAAAEgAFAABAEkAbgB0AGUAcgBuAGEAbABOAGEAbQBlAAAARwByAG8AdwBsAC4AQwBvAG4AbgBlAGMAdABvAHIALgBkAGwAbAAAAHAAJgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAAqQAgAGUAbABlAG0AZQBuAHQAIABjAG8AZABlACAAcAByAG8AagBlAGMAdAAgADIAMAAwADkAAABQABQAAQBPAHIAaQBnAGkAbgBhAGwARgBpAGwAZQBuAGEAbQBlAAAARwByAG8AdwBsAC4AQwBvAG4AbgBlAGMAdABvAHIALgBkAGwAbAAAAEAAEAABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAARwByAG8AdwBsAC4AQwBvAG4AbgBlAGMAdABvAHIAAAAwAAYAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAyAC4AMAAuADQAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMgAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AAADAAAAAA7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}


$Script:resources | %{New-Object PSObject -Property $_} | Script:Write-EmbeddedResource | Script:Load-Assembly

<#[System.Reflection.Assembly]::GetAssembly("Growl.Connector.GrowlConnector")

$test_connector = Get-GrowlConnector -Computer "DESKTOP-BOJS2AA" -Password "123QWEasd"

$test_connector.AddCallbackHandler({
  Param($response, $context)
  Write-Host "Response:`n$response"
  Write-Host "`nContext:`n$($context|fl *)"
})#>

<#
$test_notification = New-GrowlNotification -ApplicationName "Test Application" `
                                           -ApplicationIcon "C:\Icons\Test_Application.png" `
                                           -NotificationType "TestMessage" `
                                           -NotificationTypeDescription "This is a friendly description of the test message notification type" `
                                           -NotificationTypeIcon "C:\Icons\TestMessage.png" `
                                           -Title "This is a test!" `
                                           -Message "You have received a test message!" `
                                           -NotificationID "TM1" `
                                           -MessageIcon "C:\Icons\Message_Icon.png" `
                                           -Priority VeryLow `
                                           -CallbackID "Generic_Callback" `
                                           -CallbackData "matthew.johnson" `
                                           -CallbackDataType "string" `
                                           -CallbackURL "" `
                                           -Sticky
# >
$test_notification = New-GrowlNotification -ApplicationName "Test Application" `
                                           -NotificationType "TestMessage" `
                                           -Title "This is a test!" `
                                           -Message "You have received a test message!" `
                                           -NotificationID "0" `
                                           -Priority VeryLow `
                                           -CallbackID "Generic_Callback" `
                                           -CallbackData "matthew.johnson" `
                                           -CallbackDataType "string" `
                                           -CallbackURL "" `
                                           -Sticky

$test_notification | fl *

$test_connector.Notify($test_notification)

Start-Sleep -Seconds 5

$test_connector.Notify((New-GrowlNotification -ApplicationName "Test Application" `
                                              -NotificationType "TestMessage" `
                                              -Title "This is a test!" `
                                              -Message "You have received a test message that has been updated!!" `
                                              -NotificationID "0" `
                                              -Priority Emergency `
                                              -Sticky))
#>

#-Identity "CN=ApplicationXtender BOE Complaints User,OU=Application,OU=User Role Groups,OU=Security Groups,DC=sec,DC=sos,DC=state,DC=nm,DC=us" `
#-Credentials (Get-Credential) `
#-SearchBase "OU=Application,OU=User Role Groups,OU=Security Groups,DC=sec,DC=sos,DC=state,DC=nm,DC=us" `
#-Port 636 `
#-Attributes "samaccountname","memberof" `
<#Get-ADLDAPGroupMember -Identity "S-1-5-21-4015811867-4186938304-2392806155-2408" `
                      -SearchBase "OU=Staff,OU=Personnel,DC=sec,DC=sos,DC=state,DC=nm,DC=us" `
                      -Attributes "samaccountname","memberof" `
                      -Server "sosdc1.sec.sos.state.nm.us" `
                      -Secure `
                      -Recursive#>

<#
$template = @"
  Alert: {{title}}
  This is sample text, priority {{priority}}
  {{@who_kicked_who {{source_user}} has kicked {{target_user}}!
     {{source_user}} needs his ass kicked
  }}
"@
$tokens = @{
  title = "People are getting kicked!";
  priority = "High";
  who_kicked_who = @(
    @{source_user = "Matt"; target_user = "Sam"}, @{source_user = "Mark"; target_user = "Tim"}
  );
}
Merge-Tokens -template $template -tokens $tokens
#>
$fake_splunk_alert = @{
  script_name = "C:\Scripts\Splunk_Alert.bat";
  event_count = 3;
  search_terms = "index=`"wineventlog`" eventtype=... | table ... | more ...";
  query_string = "index=`"wineventlog`" eventtype=... | table ... | more ...";
  alert_name = "Group membership changed (High)";
  trigger_reason = "Something cryptic and useless for now";
  report_url = "https://splunk:442/app/,,,,,,,";
  #not_used = (get-item Env:\SPLUNK_ARG_7).Value;
  results_gzip = "D:\Temp\tmp_0.csv.gz";
}

Process-SplunkAlert -AlertRepository "\\sosfilesrv2.sec.sos.state.nm.us\it\! Re-Organized IT Share\Records\Alerts" -Splunk $fake_splunk_alert | % {

  $notification = $_

  $growl_notification = New-GrowlNotification -ApplicationName "Splunk" `
                                 -NotificationType "Change Management" `
                                 -Title $notification.tokens['title'] `
                                 -Message $notification.GetNotification("standard","text") `
                                 -Priority $notification.tokens['priority'] `
                                 -NotificationID ($notification.tokens['title'] + "_" + $notification.tokens['priority']) `
                                 -CallbackID ($notification.tokens['title'] + "_" + $notification.tokens['priority']) `
                                 -Sticky

  $email_notification = New-EmailNotification -Originator "SOS.IT-Notification@state.nm.us" `
                                              -Subject $notification.tokens['title'] `
                                              -Message $notification.GetNotification("standard","text") `
                                              -Attachments $notification.tokens['raw_report'] `
                                              -Priority High


  $txt_notification = New-EmailNotification -Originator "SOS.IT-Notification@state.nm.us" `
                                            -Subject ("Splunk | " + $notification.tokens['priority']) `
                                            -Message $notification.GetNotification("brief","text")

  # S-1-5-21-4015811867-4186938304-2392806155-2477 => "Computer Alert"
  switch ($notification.tokens['priority']) {
    "Emergency" { }
    "High" { $groups = "S-1-5-21-4015811867-4186938304-2392806155-2477"; break }
    "Moderate" {}
    "Normal" {}
    "VeryLow" {}
    default { $groups = "S-1-5-21-4015811867-4186938304-2392806155-2477" }
  }

  #-SearchBase "OU=DA Computers,OU=Client Systems,DC=sec,DC=sos,DC=state,DC=nm,DC=us" `
  # It should be noted, that if the attribute is undefined for the object, it's not returned at all....
  $notification_targets = $groups | Get-ADLDAPGroupMember -Attributes "cn", "dNSHostName", "objectClass", "pager", "mail" `
                                                          -SearchBase "DC=sec,DC=sos,DC=state,DC=nm,DC=us" `
                                                          -Server "sosdc1.sec.sos.state.nm.us" `
                                                          -Recursive `
                                                          -Secure

  $email_connector = Get-EmailConnector -SmtpServer "webmail.state.nm.us" -Credential (Get-Credential)
  
  
  #$email_notification = New-EmailNotification


  $notification_targets | % {

    $target = $_

    switch ($target) {
      {"computer" -in $target["objectClass"]} {
        $target_connector = Get-GrowlConnector -Computer $target['cn'] -Password "123QWEasd"
        $target_connector.Notify($growl_notification)
        break
      }

      {"user" -in $target["objectClass"]} {
        $email_connector.Send($txt_notification, $target['pager'])
        $email_connector.Send($email_notification, $target['mail'])
        break
      }
    }
  }

}

<#
$splunk_notification = Process-SplunkAlert -Splunk $fake_splunk_alert

$text = $splunk_notification.GetNotification("medium","text")

$text
#>