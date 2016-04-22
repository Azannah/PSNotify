Set-Location C:\Users\MatthewF\Source\Repos\PSNotify\PSNotify

Import-Module .\EmbeddedResources.psm1
Import-Module .\SecureCache.psm1

$protector = New-Protector -Passphrase ("Test Passphrase" | ConvertTo-SecureString -AsPlainText -Force)

$protector

break;

Describe "New-Protector" {
	Context "x509" {
		It "Returns a custom protector object where ProtectorType == 'Passphrase'" {
      $protector = New-Protector -Passphrase ("Test Passphrase" | ConvertTo-SecureString -AsPlainText -Force)
      
      $protector | Should Be "DPAPI"
		}
	}
}