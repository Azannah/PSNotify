#
# SecureCache.psm1
#

function Get-SecureCache {
  [CmdletBinding()]
  Param(
    <#[Parameter(
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
    $Name,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$true,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [psobject]
    # The name of the SMTP server that will proxy email notification
    $Value,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [ValidateSet("Function","Script")]
    [string]
    # The name of the SMTP server that will proxy email notification
    $Namespace = "Script",
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
    # The name of the SMTP server that will proxy email notification
    $Insecure,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$false,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]    
    [securestring]
    # The name of the SMTP server that will proxy email notification
    $SecureKey#>
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [string]
    # A path to the cache file that shuold be loaded
    $Path,
    [Parameter(
      #HelpMessage="Specify the name of a computer to send messages to a remote system",
      Mandatory=$false,
      #ParameterSetName="remote",
      #Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true,
      ValueFromRemainingArguments=$false)]
    #[Alias('Target')]
    [securestring]
    # A path to the cache file that shuold be loaded
    $Passphrase
  )

  Begin {


    function derive_file_path {
      if ($MyInvocation.PSCommandPath -ne $null) {
        #return ($MyInvocation.PSCommandPath.Name.Split('\')[-1] -replace "\.\w+$", ".clixml")
        return ($MyInvocation.PSCommandPath -replace "\.\w+$", ".clixml")
      }

      return "_.clixml"
    }

    [scriptblock] $cache_object_template = {

      Param (
        [string] $cache_path,
        <# 
        A passphrase or the thumbprint of a certificate in the certificate store that can be used to unlock the cache.
        If no value is given, the protector defaults to a certificate if the current context (user) has a published
        certificate. The Microsoft Data Protector API is used when no passphrase or certificate is available. 
        #>
        $protector
      )

      <#
      Exported (public) functions
      #>
      function getItem {
        Param (
          [string]$name,
          [string]$namespace
        )

        # 2do: check for $namespace == ::keys ???
        if ([string]::IsNullOrWhiteSpace($namespace)) {
          $namespace = "global"
        }

        # Check to see if the specified namespace and item exists. If not, return a null value
        if (($_CACHE.keys -notcontains $namespace) -or ($_CACHE[$namespace].keys -notcontains $name)) {
          return $null
        }

        # Attempt to load the required fields from the item requested
        try {
          $decrypted_serialized_object = decrypt_using_aesmanaged (
            [System.Convert]::FromBase64String($_CACHE[$namespace][$name].Data)
          ) (
            [System.Convert]::FromBase64String($_CACHE[$namespace][$name].IV)
          ) (get_key)

          return deserialize_psobject $decrypted_serialized_object
        } catch {
          # Some kind of data corruption is preventing the item from being decrypted
          throw [System.Security.Cryptography.CryptographicException] "Invalid data elements in cache. Unable to decrypt $name within the $namespace namespace."
        }

      }

      function getNamespaces {
        return $_CACHE.Keys
      }

      function getNamespaceValues {
        Param (
          [string]$namespace
        )

        return $_CACHE[$namespace].Keys
      }

      function persist {
        try {
          persist_cache_file $cache_path $_CACHE
        } catch {
          return $false
        }

        return $true
      }

      function setItem { 
        Param (
          [string]$name,
          [object]$value,
          [string]$namespace,
          [bool]$force = $false,
          [bool]$persist_on_set = $false
        )
        
        # 2do: check for $namespace == ::keys ???
        if ([string]::IsNullOrWhiteSpace($namespace)) {
          $namespace = "global"
        }
        
        <# 
        2do: decide on scheme to manage passphrase vs. cert vs. dpapi and validate inputs. The following assumes
        passphrase for testing.
        #>
        $master_key = get_key -passphrase_protector $protector

        if ($value.GetType().IsSerializable) {
          # Check if namespace and value already exist. If not, create it
          if ($_CACHE.keys -notcontains $namespace) {
            $_CACHE[$namespace] = @{}

          # Check if name/value pair exists within namespace. If it does and $force -ne $true, fail
          } elseif ($_CACHE[$namespace].Keys -contains $name) {
            if (-not $force) {
              # 2do: log
              return $false
            }
            
            $old_value = $_CACHE[$namespace][$name]
          }

          $data_iv = get_random_bytes 16

          try {
            $encrypted_serialized_object = encrypt_using_aesmanaged (
              serialize_psobject $value
            ) $data_iv $master_key
          } catch {
            # 2do: log
            throw $_
          }

          $_CACHE[$namespace][$name] = @{
            Data = [System.Convert]::ToBase64String($encrypted_serialized_object);
            IV = [System.Convert]::ToBase64String($data_iv);
            Timestamp = Get-Date
          }

          if ($persist_on_set) {
            try {
              persist_cache_file $cache_path $_CACHE
            } catch {
              $_CACHE[$namespace][$name] = $old_value
              return $false
            }

            return $true
          }

          return $true
        }

        # 2do: log as not serializable
        return $false
      }

      <#
      Private (not exported) functions
      #>
      function decrypt_using_aesmanaged {
        Param (
          [byte[]]$data_to_decrypt,
          [byte[]]$iv,
          [byte[]]$key
        )

        [System.Security.Cryptography.AesManaged] $aes_managed = New-Object System.Security.Cryptography.AesManaged
        $aes_managed.Key = $key
        $aes_managed.IV = $iv
        $aes_managed.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $decryptor = $aes_managed.CreateDecryptor()

        $memory_stream = New-Object System.IO.MemoryStream (,$data_to_decrypt)

        $crypto_stream = New-Object System.Security.Cryptography.CryptoStream $memory_stream, $decryptor, ([System.Security.Cryptography.CryptoStreamMode]::Read)

        $memory_stream_out = New-Object System.IO.MemoryStream
        #$crypto_stream.Read($data_to_decrypt, 0, $data_to_decrypt.Length)
        $crypto_stream.CopyTo($memory_stream_out)

        $crypto_stream.Dispose()

        $decrypted_data = $memory_stream_out.ToArray()

        #$crypto_stream.Dispose()
        $memory_stream.Dispose()
        $memory_stream_out.Dispose()

        return $decrypted_data

        <#
          try
          {
              $object = Import-Clixml -Path .\encryptionTest.xml

              $thumbprint = 'B210C54BF75E201BA77A55A0A023B3AE12CD26FA'
              $cert = Get-Item -Path Cert:\CurrentUser\My\$thumbprint -ErrorAction Stop

              $key = $cert.PrivateKey.Decrypt($object.Key, $true)

              $secureString = $object.Payload | ConvertTo-SecureString -Key $key
          }
          finally
          {
              if ($null -ne $key) { [array]::Clear($key, 0, $key.Length) }
          }
        #>
      }

      function decrypt_using_dpapi {
        Param (
          [byte[]]$data_to_decrypt,
          [byte[]]$iv,
          [System.Security.Cryptography.DataProtectionScope]$scope
        )

        [byte[]]$decrypted_data = [System.Security.Cryptography.ProtectedData]::Unprotect($data_to_decrypt, $iv, $scope)

        return $decrypted_data
      }

      function encrypt_using_aesmanaged {
        Param (
          [byte[]]$data_to_encrypt,
          [byte[]]$iv,
          [byte[]]$key
        )

        [System.Security.Cryptography.AesManaged] $aes_managed = New-Object System.Security.Cryptography.AesManaged
        $aes_managed.Key = $key
        $aes_managed.IV = $iv
        $aes_managed.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $encryptor = $aes_managed.CreateEncryptor()

        $memory_stream = New-Object System.IO.MemoryStream

        $crypto_stream = New-Object System.Security.Cryptography.CryptoStream $memory_stream, $encryptor, ([System.Security.Cryptography.CryptoStreamMode]::Write)
        $crypto_stream.Write(([byte[]] $data_to_encrypt), 0, $data_to_encrypt.Length)

        <#
        Reference: https://www.simple-talk.com/blogs/2012/02/28/oh-no-my-paddings-invalid/
        CryptoStream has a special method to flush the final block of data – FlushFinalBlock. Calling Stream.Flush() does not flush the 
        final block, as you might expect. Only by closing the stream or explicitly calling FlushFinalBlock is the final block, with any 
        padding, encrypted and written to the backing stream. Without this call, the encrypted data is 16 bytes shorter than it should be.

        Hence, $crypto_stream must be disposed (and closed) before the $memory_stream can be converted to an array.
        #>
        $crypto_stream.Dispose()

        $encrypted_data = $memory_stream.ToArray()

        $memory_stream.Dispose()

        return $encrypted_data

        <#
          try
          {
              $secureString = 'This is my password.  There are many like it, but this one is mine.' | 
                              ConvertTo-SecureString -AsPlainText -Force

              # Generate our new 32-byte AES key.  I don't recommend using Get-Random for this; the System.Security.Cryptography namespace
              # offers a much more secure random number generator.

              $key = New-Object byte[](32)
              $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()

              $rng.GetBytes($key)

              $encryptedString = ConvertFrom-SecureString -SecureString $secureString -Key $key

              # This is the thumbprint of a certificate on my test system where I have the private key installed.

              $thumbprint = 'B210C54BF75E201BA77A55A0A023B3AE12CD26FA'
              $cert = Get-Item -Path Cert:\CurrentUser\My\$thumbprint -ErrorAction Stop

              $encryptedKey = $cert.PublicKey.Key.Encrypt($key, $true)

              $object = New-Object psobject -Property @{
                  Key = $encryptedKey
                  Payload = $encryptedString
              }

              $object | Export-Clixml .\encryptionTest.xml

          }
          finally
          {
              if ($null -ne $key) { [array]::Clear($key, 0, $key.Length) }
          }
        #>
      }

      function encrypt_using_dpapi {
        Param (
          [byte[]]$data_to_encrypt,
          [byte[]]$iv,
          [System.Security.Cryptography.DataProtectionScope]$scope
        )

        [byte[]]$encrypted_data = [System.Security.Cryptography.ProtectedData]::Protect($data_to_encrypt, $iv, $scope)

        return $encrypted_data
      }

      function get_random_bytes {
        Param (
          [int]$byte_count
        )

        $buffer = New-Object byte[]($byte_count)

        # I've read several references to wanting to use the same RNG instance repeatedly
        #[System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($random_bytes)
        $RNG.GetBytes($buffer)

        return $buffer
      }

      function get_unsecured_byte_string {
        Param (
          [securestring]$secure_string
        )

        $byte_length = $secure_string.Length * 2
        $byte_string = New-Object byte[] $byte_length
        [System.IntPtr] $unmanaged_bytes = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure_string)

        try {
          for ($i = 0; $i -lt $byte_length; $i++ ) {
            $byte_string[$i] = [System.Runtime.InteropServices.Marshal]::ReadByte($unmanaged_bytes, $i)
          }
        } catch {

        } finally {
          [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($unmanaged_bytes)
        }

        return $byte_string
      }

      function get_derived_key {
        Param (
          [securestring]$password,
          [byte[]]$salt
        )

        $iterations = 1000
        $key_bytes = 32

        try {
          $generator = New-Object System.Security.Cryptography.Rfc2898DeriveBytes (get_unsecured_byte_string $password), $salt, $iterations
        } catch {
          # 2do Log
          throw $_
        }

        return $generator.GetBytes($key_bytes)
      }

      function get_key {
        Param (
          [securestring]$passphrase_protector = $null,
          [string]$cert_protector = $null
        )

        if ($_CACHE_KEY -ne $null) {
          return $_CACHE_KEY
        }

        $keys = "::keys"
        #$keys_master_salt = "master_salt"
        #$master = "cache_master"

        # Unless a master unlock key is provided, each user maintains keys under their own context
        $user_sid = (New-Object System.Security.Principal.NTAccount $Env:USERNAME).Translate([System.Security.Principal.SecurityIdentifier]).Value

        # Check to see if the cache already has keys defined. If not create a master key and encrypt within the current users context.
        if ($_CACHE.Keys -notcontains $keys) {
          # The cache must be new (or broken), so create a new master key which will be used to encrypt everything
          $master_key = get_derived_key (
            [System.Text.UnicodeEncoding]::ASCII.GetString((get_random_bytes 51)) | ConvertTo-SecureString -AsPlainText -Force
          ) (get_random_bytes 32)

          # Prime the cache with the appropriate hashtables - $keys namespace, and initial user
          $_CACHE[$keys] = @{}
        
          # Our current user will "own" the master key initially
          $_CACHE[$keys][$user_sid] = @{}

          # Find out how the user will be protecting their copy of the master_key initially
          # DPAPI
          if (($passphrase_protector -eq $null) -and ([string]::IsNullOrWhiteSpace($cert_protector))) {
            # Encrypt the cache master key using the Data Protection API and store under the user
            $data_iv = get_random_bytes 16
            [byte[]]$encrypted_master_key = encrypt_using_dpapi $master_key $data_iv ([System.Security.Cryptography.DataProtectionScope]::CurrentUser)
          
            $_CACHE[$keys][$user_sid]["dpapi"] = @{
              Data = [System.Convert]::ToBase64String($encrypted_master_key);
              IV = [System.Convert]::ToBase64String($data_iv);
              Timestamp = Get-Date;
            }

          # Certificate
          } elseif (-not [string]::IsNullOrWhiteSpace($cert_protector)) {
            # 2do

          # Passphrase
          } else {
            $passphrase_salt = get_random_bytes 32
            $data_iv = get_random_bytes 16
            $encrypted_master_key = encrypt_using_aesmanaged $master_key $data_iv (get_derived_key $passphrase_protector $passphrase_salt)

            $_CACHE[$keys][$user_sid]["passphrase"] = @{
              Data = [System.Convert]::ToBase64String($encrypted_master_key);
              IV = [System.Convert]::ToBase64String($data_iv);
              Salt = [System.Convert]::ToBase64String($passphrase_salt);
              Timestamp = Get-Date;
            }
          }

          [array]::Clear($encrypted_master_key, 0, $encrypted_master_key.Length)
          $_CACHE_KEY = [byte[]]$master_key
          return $master_key
        }

        # The cache already has some keys, which means it's pre-existing. Does the current user have access? In not, throw an exception.
        if ($_CACHE[$keys].Keys -notcontains $user_sid) {
          throw [System.UnauthorizedAccessException] "$Env:USERNAME with SID $user_sid does not keys registered with the cache, $cache_path"
        }

        # The current user has keys stored, so let's get the master key. If provided, a certificate takes presidence over a passphrase
        if ((-not [string]::IsNullOrWhiteSpace($cert_protector)) -and ($_CACHE[$keys][$user_sid].Keys -contains 'cert')) {
          # 2do

        # If no certificate is provided, a passphrase is the next preference
        } elseif ((-not [string]::IsNullOrWhiteSpace($passphrase_protector)) -and ($_CACHE[$keys][$user_sid].Keys -contains 'passphrase')) {
          # Attempt to load required passphrase protector elements. If we're unsuccessful, try to fallback on the DPAPI
          try {
            $salt = [System.Convert]::FromBase64String($_CACHE[$keys][$user_sid]['passphrase'].Salt)
            $iv = [System.Convert]::FromBase64String($_CACHE[$keys][$user_sid]['passphrase'].IV)
            $encrypted_master_key = [System.Convert]::FromBase64String($_CACHE[$keys][$user_sid]['passphrase'].Data)

            $master_key = decrypt_using_aesmanaged $encrypted_master_key $iv (get_derived_key $passphrase_protector $salt)
          } catch {
            # 2do: log
            # passphrase protector data elements incorrect, attempt to fall back on DPAPI
            return get_key
          }
        
        # If no certificate thumbprint or passphrase is provided, attempt to obtain the master key using DPAPI
        } else {
          # Attempt to load required passphrase protector elements.
          try {
            $iv = [System.Convert]::FromBase64String($_CACHE[$keys][$user_sid]['dpapi'].IV)
            $encrypted_master_key = [System.Convert]::FromBase64String($_CACHE[$keys][$user_sid]['dpapi'].Data)

            $master_key = decrypt_using_dpapi $encrypted_master_key $iv ([System.Security.Cryptography.DataProtectionScope]::CurrentUser)
          } catch {
            # 2do: log
            throw [System.Security.Cryptography.CryptographicException] "Invalid key protector elements in cache. Unable to decrypt the cache key."
          }
        }

        <#switch ($key_protector) {
          {$_.GetType() -eq [string]} {
            $key_protector = $key_protector | ConvertTo-SecureString -AsPlainText -Force
            $cipher_key = get_derived_key $key_protector $_CACHE[$keys][$keys_master_salt]
          }
          {$_.GetType() -eq [securestring]} {
            $cipher_key = get_derived_key $key_protector $_CACHE[$keys][$keys_master_salt]
          }
        }#>

        $_CACHE_KEY = [byte[]]$master_key
        return $master_key
      }

      function persist_cache_file {
        Param (
          [string]$cache_path, 
          [object]$cache_object
        )

        # Attempt to create lock file
        while ($true) {

          $total_wait_ms = 0

          try {

            "$ENV:COMPUTERNAME:$PID" | Out-File -FilePath "$_CACHE_PATH.lock" -NoClobber -ErrorAction Stop

            # Lock file created
            break

          # If the lock file can't be created, wait a randon interval and try again
          } catch {

            #We're not going to wait more than 3 seconds for the lock to be cleared
            if ($total_wait_ms -gt (3*1000)) {

              # Find out what process has the file locked
              try {

                $lock_owner = Get-Content "$_CACHE_PATH.lock" -Tail 1

              # We weren't able to read the lcok file for some reason...
              } catch {

                #2do: See if another exception makes sense
                throw [System.AccessViolationException] "The secure cache file $_CACHE_PATH is locked by 'unknown'"

              }

              #2do: See if another exception makes sense
              throw [System.AccessViolationException] "The secure cache file $_CACHE_PATH is locked by $lock_owner"
            }
            
            # A lock file already exists, so we're going to get a random number representing milliseconds...
            # 2do: figure out how to convert a byte array into an int
            $wait_ms = Get-Random -SetSeed (get_random_bytes -byte_count 1) -Minimum 100 -Maximum 300

            # ... and wait for that amount of time
            Start-Sleep -Milliseconds $wait_ms

            $total_wait_ms += $wait_ms

            # After our wait, we'll try to create the lock again
            continue

          }

          break

        }


        try {
          Export-Clixml -Path $cache_path -InputObject $cache_object -Depth 10 -ErrorAction Stop
        } catch {
          # 2do: log here, up higher up?
          throw $_
        }
      }

      function read_cache_file {
        Param (
          [string]$file_path
        )

        <#
        If the inputs are validated, this should never receive a null/empty string. However, the cache file
        might not yet exist.
        #>
        if (-not (Test-Path $file_path)) {
          return @{}
        }

        try {
          return Import-Clixml -Path $file_path -ErrorAction Stop
        } catch {
          #2do: log
          throw $_
        }
      }

      function deserialize_psobject {
        Param (
          #[string]$serialized_object
          [byte[]]$serialized_object
        )

        #[byte[]]$serialized_bytes = [System.Convert]::FromBase64String($serialized_object);
        #$memory_stream = New-Object System.IO.MemoryStream $serialized_bytes, 0, $serialized_bytes.Length
        $memory_stream = New-Object System.IO.MemoryStream $serialized_object, 0, $serialized_object.Length
        $binary_formatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter

      
        return $binary_formatter.Deserialize($memory_stream)
      }

      function serialize_psobject {
        Param (
          [psobject]$object
        )

        $memory_stream = New-Object System.IO.MemoryStream
        $binary_formatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter

        try {
          $binary_formatter.Serialize($memory_stream, $object)
          #$serialized_object = [System.Convert]::ToBase64String($memory_stream.ToArray())
          $serialized_object = $memory_stream.ToArray()
        } finally {
          $memory_stream.Close()
        }

        return $serialized_object
      }

      # 2do validate $protector input

      $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
      $_CACHE_PATH = $cache_path
      $_CACHE = read_cache_file $cache_path
      [byte[]]$_CACHE_KEY = $null # 2do: change all private object (class?) variables to follow the same format

      Export-ModuleMember -Function "setItem", "getItem", "Persist"
    }
  }

  Process {

    if ([string]::IsNullOrWhiteSpace($Path)) {
      $Path = derive_file_path
    }
    
    return New-Module $cache_object_template -AsCustomObject -ArgumentList $Path, $Passphrase

    #Test DPAPI key set
    <#$result = get_key
    Write-Host "DPAPI Protected Key Set As: $result"
    $result = get_key
    Write-Host "DPAPI Protected Key Retreived As: $result"# >

    #Test AESManaged encryption/decryption
    Write-Host "Begin Encryption:`n-----------------------------"
    $iv = get_random_bytes -byte_count 16
    Write-Host ("IV: " + [String]::Join(" ", $iv))
    $key = get_derived_key -password ("123QWEasd" | ConvertTo-SecureString -AsPlainText -Force) -salt (get_random_bytes -byte_count 32)
    Write-Host ("Key: " + [String]::Join(" ", $key))
    $serialized_object = serialize_psobject $test
    Write-Host ("Serialized Test Object: " + [String]::Join(" ", $key))
    $result = encrypt_using_aesmanaged  -data_to_encrypt $serialized_object -iv $iv -key $key
    Write-Host ("Encrypted Serialized Object: " + [String]::Join(" ", $result))
    $result = [System.Convert]::ToBase64String($result)
    Write-Host "Encrypted object as Base64 string: $result"

    Write-Host "`nBegin Decryption:`n-----------------------------"
    Write-Host ("IV: " + [String]::Join(" ", $iv))
    Write-Host ("Key: " + [String]::Join(" ", $key))
    Write-Host "Encrypted object as Base64 string: $result"
    $result = [System.Convert]::FromBase64String($result)
    Write-Host ("Encrypted Serialized Object: " + [String]::Join(" ", $result))
    $result = decrypt_using_aesmanaged -data_to_decrypt $result -iv $iv -key $key
    Write-Host ("Serialized Test Object: " + [String]::Join(" ", $key))
    $result = deserialize_psobject $result
    Write-Host "Decrypted object:"
    $result | Out-String | Write-Host

    break
    
    $cache = read_cache_file
    
    if ($cache.Keys -notcontains $Namespace) {
      $cache[$Namespace] = @{}
    }

    try {
      $Value = serialize_psobject $Value
    } catch {

    }

    if (-not $Insecure) {
      $Value = encrypt_string
    }

    $cache[$Namespace][$Name] = @{
      value = $Value;
      secure = (-not $Insecure);
    }
    
    return persist_cache_file $cache
    #>
  }

  End {

  }
}

Export-ModuleMember -Function "Get-SecureCache"