#Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#Import-Module Pester

@(
  "C:\Users\MatthewF\Source\Repos\PSNotify\PSNotify",            # Laptop (Zen)
  "C:\Users\matthew.johnson\Source\Repos\PSNotify\PSNotify"      # Desktop at work
  "D:\Users\Matthew Johnson\Source\GitHub\PSNotify\PSNotify"     # Desktop at home
) | ? { Test-Path -Path $_ } | Set-Location

#Import-Module .\EmbeddedResources.psm1
#Import-Module .\SecureCache.psm1

<#
  "Get-SecureCache",
  "New-Protector",
  #"New-DynamicVariable",
  "Get-RandomByteArray",
  "Get-UnsecuredBytes",
  "Get-DerivedKey"
#>

Describe "Import-Module SecureCache.psm1" {
  It "Imports the module, which checks for, and if necessary, loads dependencies" {
    # Import-Module .\EmbeddedResources.psm1 is a dependency, which should be in the same working folder for this test
    Import-Module .\SecureCache.psm1
  }
}

Describe "Get-RandomByteArray" {
  Context "Get random bytes given valid inputs" {
    It "Uses Get-RandomByteArray -Size 32 to get an array of 32 random bytes" {
      ## For some reason, when a Byte[] object is returned by a powershell script, it becomes Object[] object.
      ## Might be the use of 'return' ?
      $random_bytes = [Byte[]](Get-RandomByteArray -Size 32)

      $random_bytes.GetType().Name | Should be "Byte[]"
      $random_bytes.Count | Should be 32
    }

    It "Uses Get-RandomByteArray 99 to get an array of 99 random bytes" {
      ## For some reason, when a Byte[] object is returned by a powershell script, it becomes Object[] object.
      ## Might be the use of 'return' ?
      $random_bytes = [Byte[]](Get-RandomByteArray 99)

      $random_bytes.GetType().Name | Should be "Byte[]"
      $random_bytes.Count | Should be 99

    }

    It "Uses Get-RandomByteArray -Size 0 to get an empty array" {
      ## For some reason, when a Byte[] object is returned by a powershell script, it becomes Object[] object.
      ## Might be the use of 'return' ?
      $random_bytes = [Byte[]](Get-RandomByteArray -Size 0)

      $random_bytes.Count | Should be 0
    }
  }

  Context "Exceptions given invalid inputs" {
    <#
    ## When a required parameter is missing, the user is prompted for input
    ## 
    It "Throws an exception if the required 'Size' parameter is not specified" {
      [Byte[]](Get-RandomByteArray) | Should Throw
    }
    #>

    It "Throws an exception given an invalid type" {
      try {
        Get-RandomByteArray -Size "ten"
      } catch {
        Should Throw
      }
    }
  }

}

Describe "Get-UnsecuredBytes" {
  Context "Get bytes using valid inputs" {
    It "Returns bytes representations of SecureString objects" {
      $test_string = "This is a test"
      $test_string_bytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($test_string)
      $test_secure_string = $test_string | ConvertTo-SecureString -AsPlainText -Force

      $unsecured_bytes = Get-UnsecuredBytes -InputObject $test_secure_string

      #Write-Host ("Input  bytes: " + ($test_string_bytes -join " "))
      #Write-Host ("Output bytes: " + ($unsecured_bytes -join " "))

      $unsecured_bytes -join " " | Should match ($test_string_bytes -join " ")
    }
  }
}

Describe "Get-DerivedKey" {
  Context "Using valid inputs" {
    $test_passphrase = "This is a test" | ConvertTo-SecureString -AsPlainText -Force
    $test_salt = [Byte[]](Get-RandomByteArray -Size 100)
    $first_derived_key = $null

    It "Derives a strong cryptographic key given a passphrase and salt as named parameters" {

      ## The default size of an AES key will be 32 bytes
      $first_derived_key = Get-DerivedKey -Passphrase $test_passphrase -Salt $test_salt

      ## While thoretically possible a zero value byte array could be generated, it's really unlikely
      $has_non_zero_value = $true

      $first_derived_key | ? { 
        $_.GetType().Name -match "byte" 
      } | ? {
        $_ -gt 0
      } | % {
        $has_non_zero_value = $true
      }

      $has_non_zero_value | Should be $true
      $first_derived_key.Count | Should be 32
    
    }

    It "Derives the same key each time given the same inputs" {

      $second_derived_key = Get-DerivedKey -Passphrase $test_passphrase -Salt $test_salt

      ($second_derived_key -join " ") | Should match ($first_derived_key -join " ")
    }
  }
}

Describe "New-Protector" {
	Context "x509" {
		It "Returns a custom protector object where ProtectorType == 'AES'" {
      $aes_protector = (New-Protector -Passphrase ("Test Passphrase" | ConvertTo-SecureString -AsPlainText -Force))
      
      $aes_protector.GetProtectorType() | Should Be "AES"
		}
	}
}

Describe "Protect-Data" {
  Context "AES Protector, AES key generated using passphrase" {
    ## Set up tests using a passphrase and automatically generated salt
    $passphrase = 'This is a Str0ng Pa$$phrase!--' | ConvertTo-SecureString -AsPlainText -Force
    $aes_protector = New-Protector -Passphrase $passphrase

    ## Data to protect
    $clear_data = @{
      "array_of_data" = @(1,2,3,4);
      "simple_string" = "This is my simple string";
      "a_number" = 120312.123
      "a_datetime_object" = Get-Date
    }

    It "Outputs Base64 string with embedded initialization vector" {
      $encrypted_data_base64 = Protect-Data -Protector $aes_protector -InputObject $clear_data -OutputEncoding Base64String

      Write-Host "Encrypted Base64: " + $encrypted_data_base64

      $encrypted_data_base64.GetType().Name | Should be "string"
    }
  }
}