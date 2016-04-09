#
# Script.ps1
#
Set-StrictMode -Version Latest


Import-Module ($PSScriptRoot + "\ADLDAP.psm1")

Import-Module ($PSScriptRoot + "\Notification.psm1")

Import-Module ($PSScriptRoot + "\Tokens.psm1")

Import-Module ($PSScriptRoot + "\SecureCache.psm1")

Import-Module ($PSScriptRoot + "\SplunkAlerts.psm1")

$test = @{
  "Matthew" = "Tristan Arrington";
  "Aaron" = "Amelia Goldan"
}

$cache = Get-SecureCache #-Passphrase ("123QWEasd" | ConvertTo-SecureString -AsPlainText -Force)
$cache.setItem("Users", @("Matthew","Aubra","Adrian"), $null, $true, $false) | % { Write-Host "setItem('Users',...): $_ (should be true)" }
$cache.setItem("Wives", $test, $null, $true) | % { Write-Host "setItem('Wives',...): $_ (should be true)" }

$test['Driver'] = "Carla"

$cache.setItem("Wives", $test) | % { Write-Host "setItem('Wives',...) no overwrite: $_ (should be false)" }
$cache.setItem("Wives", $test, $null, $true, $true) | % { Write-Host "setItem('Wives',...) overwrite: $_ (should be true)" }

$cache.getItem("Users") | Out-String | %{ Write-Host "getItem('Users'): $_" }

#Get-CacheItem -Name "test"
break

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

Get-SplunkAlert -AlertRepository "\\sosfilesrv2.sec.sos.state.nm.us\it\! Re-Organized IT Share\Records\Alerts" -Splunk $fake_splunk_alert | % {

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