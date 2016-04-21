Import-Module .\EmbeddedResources.psm1
Import-Module .\SecureCache.psm1

Describe "New-Protector" {
	Context "x509" {
		It "Returns a custom protector object where ProtectorType == 'DPAPI'" {
      $protector = New-Protector
      
      $protector | Should Be "DPAPI"
		}
	}
}