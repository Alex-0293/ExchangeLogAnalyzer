# Rename this file to Settings.ps1
#### Script params
    [string]$global:IPToFQDN                    = ""          # FQDN Resolver file.
    [string]$global:ExchangeServerFQDN          = ""          # Exchange server FQDN.
    [string]$global:APP_SCRIPT_ADMIN_Login      = ""          # AES Login.
    [string]$global:APP_SCRIPT_ADMIN_Pass       = ""          # AES Password.
    
######################### no replacement ########################   
    [string]$global:MessageLogFilePath          = "$ProjectRoot\$DATAFolder\ExchangeMessageLogs.csv"                 # Path to message log file.
    [string]$global:AgentLogFilePath            = "$ProjectRoot\$DATAFolder\ExchangeAgentLogs.csv"                   # Path to agent log file.
    [string]$global:MessageLogFilePath1         = "$ProjectRoot\$DATAFolder\ExchangeMessageLogsTrm.csv"              # Path to transformed message log file.
    [string]$global:ActiveSyncLogFilePath       = "$ProjectRoot\$DATAFolder\ActiveSyncLog.csv"                       # Path to active sync log file.
    [string]$global:AgentLogFilePath1           = "$ProjectRoot\$DATAFolder\ExchangeAgentLogsTrm.csv"                # Path to agent transformed log file.
    [string]$global:FilterConfig                = "$ProjectRoot\$DATAFolder\FilterConfig.xml"                        # Path to filter config XML file.
    [string]$global:FilterConfigPath1           = "$ProjectRoot\$DATAFolder\FilterConfig.csv"                        # Path to filter config CSV file.

    [string]$global:ActiveSyncLogDirPath        = "\\%ExchangeServerFQDN%\C$\InetPub\logs\LogFiles\".Replace("%ExchangeServerFQDN%",$global:ExchangeServerFQDN) #Logging directory UNC path.
    [string]$global:ConnectionFilterLogLocation = "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\FrontEnd\AgentLog"                        # Path to connection filter log file.
    [Int16] $global:HoursToLoad                 = 24                                                          # Load statistic for N hours.
    [Int32] $global:MaxResultSize               = 100000                                                      # Maximum result set size.
    

$global:LogParams = @{
    ExcludeIP                 = @("::1", "127.0.0.1", "fe80::f1cd:550b:c138:5c61%3", "fe80::f1cd:550b:c138:5c61%4") # Exclude those ip from data set.
    FileSplitHour             = 3                                                                                   # Your timezone.
    ActiveSyncLogFilePathTemp = $Global:ActiveSyncLogDirPath + "W3SVC1\u_ex%DateYYMMdd%.log"                        # Active sync log file template.
    LogName                   = "W3SVC1"                                                                            # Log channel name.
    Delimiter                 = " "                                                                                 # Log file delimiter.
    SkipLinesCount            = 4                                                                                   # Skip first line counter.
}

[bool] $Global:LocalSettingsSuccessfullyLoaded = $true

# Error trap
trap {
    $Global:LocalSettingsSuccessfullyLoaded = $False
    exit 1
}
