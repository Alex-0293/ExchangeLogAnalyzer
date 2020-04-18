[string]$global:MessageLogFilePath          = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\ExchangeMessageLogs.csv"
[string]$global:AgentLogFilePath            = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\ExchangeAgentLogs.csv"
[string]$global:MessageLogFilePath1         = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\ExchangeMessageLogsTrm.csv"
[string]$global:ActiveSyncLogFilePath       = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\ActiveSyncLog.csv"
[string]$global:AgentLogFilePath1           = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\ExchangeAgentLogsTrm.csv"
[string]$global:FilterConfig                = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\FilterConfig.xml"
[string]$global:FilterConfigPath1           = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\FilterConfig.csv"
[string]$global:IPArrayPath                 = ""#"C:\DATA\Projects\ExchangeLogAnalyzer\DATA\IPArray.csv"
[string]$global:ConnectionFilterLogLocation = ""#"C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\FrontEnd\AgentLog"
[string]$global:ExchangeServerFQDN          = ""#"exchange.company.local"
[string]$global:ActiveSyncLogDirPath        = ""#"\\%ExchangeServerFQDN%\C$\inetpub\logs\LogFiles\".Replace("%ExchangeServerFQDN%",$global:ExchangeServerFQDN)
[string]$global:GlobalKey1                  = ""#AesKey
[string]$global:APP_SCRIPT_ADMIN_Login      = ""#Enc. data
[string]$global:APP_SCRIPT_ADMIN_Pass       = ""#Enc. data
[Int16]$global:HoursToLoad                  = #24
[Int32]$global:MaxResultSize                = #100000

$global:Params = @{
    ExcludeIP                 = @("::1", "127.0.0.1", "fe80::f1cd:550b:c138:5c61%3", "fe80::f1cd:550b:c138:5c61%4")
    FileSplitHour             = 3
    ActiveSyncLogFilePathTemp = $Global:ActiveSyncLogDirPath + "W3SVC1\u_ex%DateYYMMdd%.log"
    LogName                   = "W3SVC1"
    Delimiter                 = " "    
    SkipLinesCount            = 4
}