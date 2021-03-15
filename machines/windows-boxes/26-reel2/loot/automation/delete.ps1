if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {                                                                                              
    Add-Type -TypeDefinition  @"                                                                                                                                           
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustEverything
{
    private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }
    public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
    public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
}
"@
}
[TrustEverything]::SetCallback()
Import-Module "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll"
$s = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010)
$s.Credentials = New-Object Net.NetworkCredential('s.svensson', 'Summer2020', 'htb')
$s.Url = [system.URI]"https://localhost/ews/exchange.asmx"
[Microsoft.Exchange.WebServices.Data.Folder]::Bind($s,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox).FindItems(999).items    | foreach { $_.Delete('HardDelete') }
[Microsoft.Exchange.WebServices.Data.Folder]::Bind($s,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::SentItems).FindItems(999).items| foreach { $_.Delete('HardDelete') }
[Microsoft.Exchange.WebServices.Data.Folder]::Bind($s,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::DeletedItems).FindItems(999).items  | foreach { $_.Delete('HardDelete') }
#[Microsoft.Exchange.WebServices.Data.Folder]::Bind($s,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Drafts).FindItems(999).items  | foreach { $_.Delete('HardDelete') }