<#
    .SYNOPSIS 
        .AUTOR
        .DATE
        .VER
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
#>
Param (
    [Parameter( Mandatory = $false, Position = 0, HelpMessage = "Initialize global settings." )]
    [bool] $InitGlobal = $true,
    [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Initialize local settings." )]
    [bool] $InitLocal = $true   
)

$Global:ScriptInvocation = $MyInvocation
$InitScript = "C:\DATA\Projects\GlobalSettings\SCRIPTS\Init.ps1"
. "$InitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal
if ($LastExitCode) { exit 1 }
# Error trap
trap {
    if (clear-host) {
        Get-ErrorReporting $_        
        . "$GlobalSettings\$SCRIPTSFolder\Finish.ps1" 
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand.path)] There is error before logging initialized. Error: $_" -ForegroundColor Red
    }  
    $Global:GlobalSettingsSuccessfullyLoaded = $false
    exit 1
}
################################# Script start here #################################

function SetAgentLog ($Log, $Recipient, $P2FromAddress) {
    $Res = [PSCustomObject]@{
        PSComputerName = $Log.PSComputerName
        RunspaceId     = $Log.RunspaceId
        Timestamp      = $Log.Timestamp
        SessionId      = $Log.SessionId
        IPAddress      = $Log.IPAddress
        MessageId      = $Log.MessageId
        P1FromAddress  = $Log.P1FromAddress
        P2FromAddress  = $P2FromAddress
        Recipient      = $Recipient
        Agent          = $Log.Agent
        Event          = $Log.Event
        Action         = $Log.Action
        SmtpResponse   = $Log.SmtpResponse
        Reason         = $Log.Reason
        ReasonData     = $Log.ReasonData
        Diagnostics    = $Log.Diagnostics
        NetworkMsgID   = $Log.NetworkMsgID
        TenantID       = $Log.TenantID
        Directionality = $Log.Directionality
    }
    $Global:AgentLogs1 += $Res
}
function SetMessageLog ($Log, $Recipient) {
    $Res = [PSCustomObject]@{
        PSComputerName          = $Log.PSComputerName
        RunspaceId              = $Log.RunspaceId
        Timestamp               = $Log.Timestamp
        ClientIp                = $Log.ClientIp
        ClientHostname          = $Log.ClientHostname
        ServerIp                = $Log.ServerIp
        ServerHostname          = $Log.ServerHostname
        SourceContext           = $Log.SourceContext
        ConnectorId             = $Log.ConnectorId
        Source                  = $Log.Source
        EventId                 = $Log.EventId
        InternalMessageId       = $Log.InternalMessageId
        MessageId               = $Log.MessageId
        NetworkMessageId        = $Log.NetworkMessageId
        Recipient               = $Recipient
        RecipientStatus         = $Log.RecipientStatus
        TotalBytes              = $Log.TotalBytes
        RecipientCount          = 1
        RelatedRecipientAddress = $Log.RelatedRecipientAddress
        #Reference               = $Log.Reference
        MessageSubject          = $Log.MessageSubject
        Sender                  = $Log.Sender
        ReturnPath              = $Log.ReturnPath
        Directionality          = $Log.Directionality
        TenantId                = $Log.TenantId
        OriginalClientIp        = $Log.OriginalClientIp
        MessageInfo             = $Log.MessageInfo
        MessageLatency          = $Log.MessageLatency
        MessageLatencyType      = $Log.MessageLatencyType
        EventData               = $Log.EventData
        TransportTrafficType    = $Log.TransportTrafficType
        SchemaVersion           = $Log.SchemaVersion
    }
    $Global:MessagesLog1 += $Res
}
function OpenArrays($PSO,$Arraylist) {
    $Res = @()
    $Cols = $PSO | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    Foreach ($Item in $PSO) {
        $Proceed = $false
        foreach ($Col in $Cols) {
            $Data = ($item | Select-Object $Col ).$Col        
            If ($null -ne $Data) {
                $DataType = $Data.gettype()
                $TypeName = $DataType.Name
                if ($Types -notcontains $TypeName) { 
                    $Types += $TypeName 
                }
                    
            }
            Else {
                $TypeName = "Null"
            }
            Write-host $Col $TypeName
            Switch ($TypeName) {
                "ArrayList" {
                    #write-host $Arraylist 
                    if ($Arraylist -notcontains $col) {
                        $Arraylist += $col
                        $CurVal = ($item | Select-Object $col ).$col
                        #write-host "$col $(@($CurVal.count))"
                        if (@($CurVal.count) -gt 0 -and ($col -notlike "*ports" )) {
                            $ExpCSVFilePath = $Global:MyScriptRoot + "\data\Filters\" + $col + ".csv"
                            $ArrayData = @()
                            foreach ($item1 in $CurVal) {
                                $Data1 = [pscustomobject]@{
                                    Data = $item1
                                }
                                $ArrayData += $Data1 
                            }   
                            $ArrayData | export-csv -Path $ExpCSVFilePath -Encoding UTF8 -NoTypeInformation -Force
                        }
                        # foreach ($item1 in $CurVal) {
                        #     #write-host $item1
                        #     $NewItem = $Item.psobject.copy()
                        #     $NewItem | Add-Member -MemberType NoteProperty -Name $col -Value $item1 -Force
                        #     #$Res += $NewItem
                        #     $Proceed = $True
                        #     $Res += (OpenArrays $NewItem $Arraylist)                            
                        #     #$Global:FilterConfig1|Select-Object name,BypassedRecipients,BypassedSenderDomains |Format-Table -AutoSize
                        #     #""
                        # } 
                    }
                    Else{$Proceed = $True}               
                } 
            }
        }
        If ($Proceed -eq $false) {
            $Res += $Item
        }
    }
    return $Res
}

[array]$Global:ColList       = @()
[array]$Global:AgentLogs1    = @()
[array]$Global:MessagesLog1  = @()
[array]$Global:FilterConfig1 = @()

& "$MyScriptRoot\ExchangeLogsExport.ps1" -InitGlobal $False -InitLocal $false

$MessagesLog   = Import-Csv $Global:MessageLogFilePath -Encoding UTF8
$AgentLogs     = Import-Csv $Global:AgentLogFilePath -Encoding UTF8

#P2FromAddresses,Recipients
foreach ($Log in $AgentLogs) {
    if ($Log.Recipients.count -ge 0) {
        $Recipients = $Log.Recipients.Split(" ")
        foreach ($recipient in $Recipients) {
            if ($Log.P2FromAddresses.count -ge 0) {
                $P2FromAddresses = $Log.P2FromAddresses.Split(" ")
                foreach ($P2FromAddress in $P2FromAddresses) {
                    SetAgentLog $Log $Recipient $P2FromAddress
                }
            } 
            else {
                SetAgentLog $Log $Recipient ""
            }  
        }
    }
    else {
        if ($Log.P2FromAddresses.count -ge 0) {
            $P2FromAddresses = $Log.P2FromAddresses.Split(" ")
            foreach ($P2FromAddress in $P2FromAddresses) {
                SetAgentLog $Log "" $P2FromAddress
            }
        } 
        else {
            SetAgentLog $Log "" ""
        } 
    }
}

#Recipients
foreach ($Log in $MessagesLog) {
    $Recipients = $Log.Recipients.Split(" ")
    foreach ($recipient in $Recipients) {
      
        SetMessageLog $Log $Recipient
             
    } 
}

$Global:AgentLogs1 | export-csv -Path $Global:AgentLogFilePath1 -Encoding UTF8 -NoTypeInformation
$Global:MessagesLog1 | export-csv -Path $Global:MessageLogFilePath1 -Encoding UTF8 -NoTypeInformation
$Global:FilterConfig1 | export-csv -Path $Global:FilterConfigPath1 -Encoding UTF8 -NoTypeInformation

################################# Script end here ###################################
. "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"