#
# EmbeddedResources.psm1
#

function Expand-GZipItem {
  Param(
    $InputObject,
    $Outfile = ($infile -replace '\.gz$','')
  )

  switch ($InputObject.GetType().Name) {
    {$_ -match "byte[]"} {
      $input_stream = New-Object System.IO.MemoryStream $InputObject
      break
    }

    {$_ -match "string"} {
      $input_stream = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
      break
    }

    default {
      throw [System.ArgumentException] "InputObject of type $_ not recognize"
    }
  }

  #$input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
  $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
  $gzipStream = New-Object System.IO.Compression.GzipStream $input_stream, ([IO.Compression.CompressionMode]::Decompress)

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


function Import-Assembly {
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

Script:Import-Assembly -Path "C:\Program Files\My Application\mylibrary.subnamespace.dll"

.EXAMPLE
This example accepts System.IO.FileInfo objects from the pipe and attempts to load them as assemblies:

Get-ChildItem -Filter *.dll | Script:Import-Assembly

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

function Write-EmbeddedResource {
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

Export-ModuleMember -Function @(
  "Import-Assembly",
  "Write-EmbeddedResource"
)