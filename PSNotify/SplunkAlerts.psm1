#
# SplunkAlerts.psm1
#


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

function Get-SplunkAlert {
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

Export-ModuleMember -Function @(
  "Get-SplunkAlert"
)