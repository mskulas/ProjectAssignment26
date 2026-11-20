class Scripts:
    def GetNetFirewallProfile(self):
        return """
        $profiles = Get-NetFirewallProfile
        $profiles | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction
                DefaultOutboundAction = $_.DefaultOutboundAction
                AllowInboundRules = $_.AllowInboundRules
                AllowLocalFirewallRules = $_.AllowLocalFirewallRules
                AllowLocalIPsecRules = $_.AllowLocalIPsecRules
                AllowUserApps = $_.AllowUserApps
                AllowUserPorts = $_.AllowUserPorts
            }
        } | ConvertTo-Json -Depth 3
        """
    def GetTPM(self):
        return """
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
        if ($tpm) {
            [PSCustomObject]@{
                IsEnabled = $tpm.IsEnabled()
                IsActivated = $tpm.IsActivated()
                IsOwned = $tpm.IsOwned()
                ManufacturerID = $tpm.ManufacturerID
                ManufacturerVersion = $tpm.ManufacturerVersion
                SpecVersion = $tpm.SpecVersion
            } | ConvertTo-Json -Depth 3
        } else {
            Write-Output "TPM not found"
        }
        """
    def CheckUserPrivileges(self):
        return """
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($user)
        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        [PSCustomObject]@{
            UserName = $user.Name
            IsAdmin = $isAdmin
        } | ConvertTo-Json -Depth 3
        """
    def CheckForMissingUpdates(self):
        return """
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        $updates = $searchResult.Updates | ForEach-Object {
            [PSCustomObject]@{
                Title = $_.Title
                Description = $_.Description
                KBArticleIDs = $_.KBArticleIDs -join ", "
                IsDownloaded = $_.IsDownloaded
                IsHidden = $_.IsHidden
            }
        }
        $updates | ConvertTo-Json -Depth 3
        """
    def GetLoggingConfig(self):
        return """
        $logConfig = Get-EventLog -LogName System -Newest 1
        [PSCustomObject]@{
            LogName = $logConfig.Log
            Source = $logConfig.Source
            EntryType = $logConfig.EntryType
            TimeGenerated = $logConfig.TimeGenerated
            Message = $logConfig.Message
        } | ConvertTo-Json -Depth 3
        """


    def RunScripts(self):
        self.GetNetFirewallProfile()
        self.GetTPM()
        self.CheckUserPrivileges()
        self.CheckForMissingUpdates()
        self.GetLoggingConfig()

    def __init__(self):
        