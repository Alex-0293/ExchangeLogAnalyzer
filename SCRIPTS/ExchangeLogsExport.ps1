﻿<#
    .SYNOPSIS 
        .AUTOR
        .DATE
        .VER
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
#>
$MyScriptRoot = "C:\DATA\Projects\ExchangeLogAnalyzer\SCRIPTS"
$InitScript   = "C:\DATA\Projects\GlobalSettings\SCRIPTS\Init.ps1"

. "$InitScript" -MyScriptRoot $MyScriptRoot
# Error trap
trap {
    if ($Global:Logger) {
        Get-ErrorReporting $_ 
    }
    Else {
        Write-Host "There is error before logging initialized." -ForegroundColor Red
    }   
    exit 1
}
################################# Script start here #################################
Clear-Host
function Format-PSO($Filter) {
     
    $Res = @()
    $Cols = $Filter | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    $Name = $Filter[0].Name1
    foreach ($item in $Filter) {
        $data = [PSCustomObject]@{ }
        foreach ($Col in $Cols) {
            $NewItem = $Item.psobject.copy()
            $Note = ($NewItem | Select-Object $col ).$col
            
            If ($null -ne $Note) {
                    $DataType = $Note.gettype()
                    $TypeName = $DataType.Name
                }
                Else { 
                    $TypeName = "Null" 
                }

            if ($Global:ColList -notcontains $Col) {
                
                $Global:ColList += $Col
                $Global:ColListData += [PSCustomObject]@{
                    Col  = $Col
                    Type = $TypeName
                }
            }

            if ($TypeName -eq "ArrayList"){
                $Array = @()
                foreach($item1 in $note){
                    $Array += [PSCustomObject]@{
                        $Col = $item1
                    } 
                }
                $ExpCSVFilePath = $Global:ProjectRoot + "\data\Filters\" + $Name + "." + $Col + ".csv"
                write-host $ExpCSVFilePath
                $Array | export-csv -Path $ExpCSVFilePath -Encoding UTF8 -NoTypeInformation -Append
            }
            else {
                $data | Add-Member -MemberType NoteProperty -Name $col -Value $Note -Force
            }

        }
        $Res += $data

    }
    $Cols = $Res | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    $ExpCSVFilePath = $Global:ProjectRoot + "\data\Filters\" + $Name + ".csv"
    write-host $ExpCSVFilePath
    $Res | export-csv -Path $ExpCSVFilePath -Encoding UTF8 -NoTypeInformation -Append
    Return $Res
}
function ExportData($PSO) {
    #$Res = @()

    $Cols = $PSO | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    $ArrayData = @()
    $StringData = @()
    $res = @()
    foreach ($Col in $Cols) {

        if (($col -ne "Name1") -and ($col -ne "name") -and ($col -ne "global")){

            Foreach ($Item in $PSO) {

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
                #Write-host $Col $TypeName
                Switch ($TypeName) {
                    "ArrayList" {
                        #write-host $Arraylist
                        if ($Arraylist -notcontains $col) {
                            $Arraylist    += $col
                            $CurVal        = ($item | Select-Object $col ).$col
                            $GlobalAction  = ($item | Select-Object Global).Global
                            $Name          = ($item | Select-Object Name1).Name1
                            $Enabled       = ($item | Select-Object Enabled).Enabled

                            If ($null -eq $GlobalAction){
                                If (($col -like "*block*") -or ($Name -like "*block*"))
                                {$GlobalAction = "Deny"}
                                ElseIf  (($col -like "*allow*") -or ($col -like "*bypassed*") -or ($Name -like "*allow*"))
                                {$GlobalAction = "Allow"}
                                Else {$GlobalAction = "na"}
                            }
                            #write-host "$col $(@($CurVal.count))"
                            if (@($CurVal.count) -gt 0 -and ($col -notlike "*ports" ) -and ($col -notlike "*class" )) {
                                foreach ($item1 in $CurVal) {
                                    $Data1      = [pscustomobject]@{
                                        Name    = $Name
                                        Col     = $Col
                                        Enabled = $Enabled
                                        Action  = $GlobalAction
                                        Type    = $TypeName
                                        Data    = $item1
                                    }
                                    $ArrayData += $Data1
                                }
                            }
                        }
                    }
                    "String" {
                        $CurVal       = ($item | Select-Object $col ).$col
                        $GlobalAction = ($item | Select-Object Global).Global
                        $Name         = ($item | Select-Object Name1).Name1
                        $Enabled      = ($item | Select-Object Enabled).Enabled

                        If ($null -eq $GlobalAction){
                            If (($col -like "*block*") -or ($Name -like "*block*"))
                            {$GlobalAction = "Deny"}
                            ElseIf  (($col -like "*allow*") -or ($col -like "*bypassed*") -or ($Name -like "*allow*"))
                            {$GlobalAction = "Allow"}
                            Else {$GlobalAction = "na"}
                        }
                        #write-host "$col $(@($CurVal.count))"
                        if ($CurVal -ne "") {
                            $Data1 = [pscustomobject]@{
                            Name    = $Name
                            Col     = $Col
                            Enabled = $Enabled
                            Action  = $GlobalAction
                            Type    = $TypeName
                            Data    = $CurVal
                            }
                            $StringData += $Data1
                        }

                    }
                }

            }

            if (@($ArrayData).count -gt 0){
                #$ArrayData | export-csv -Path $ExpCSVFilePath -Encoding UTF8 -NoTypeInformation -Force
            }
            if (@($StringData).count -gt 0){
                #$StringData | export-csv -Path $ExpCSVFilePath -Encoding UTF8 -NoTypeInformation -Force
            }
        }
    }

    $Res += $ArrayData
    $Res += $StringData

    #$Res | Select-Object * |Sort-Object name| Out-GridView
    return $Res
}
Function GetLogFilesDividedByDates($ExcludeIp,  $FileSplitHour, $ActiveSyncLogFilePathTemp, $LogName, $Delimiter, $SkipLinesCount )  {
    $Data1    = (get-date).AddHours(-1 * $Global:HoursToLoad)
    $Date2    = $Data1.AddHours(-1 *  $FileSplitHour)
    $Now      = get-date
    $DateDiff = $Now - $Date2
   
    if ($DateDiff.Hour -eq 0 -and $DateDiff.Minute -eq 0 -and $DateDiff.Second -eq 0){
        $DaysCount = ($Now - $Date2).days
    }
    else {
        $DaysCount = ($Now - $Date2).days + 1
    }
    
    for ($i=0;$i -ge ($DaysCount-1)*(-1);$i--){
        $DateYYMMdd = get-date -date $Now.AddDays($i) -Format yyMMdd
        Write-host "Analyzing logs " $(get-date -date $Now.AddDays($i) -Format dd.MM.yyyy)
        $ActiveSyncLogFilePath = $ActiveSyncLogFilePathTemp -replace "%DateYYMMdd%", $DateYYMMdd  
             Write-host "    - $LogName"
        if (Test-Path $ActiveSyncLogFilePath){
            $LogFile = Get-Content $ActiveSyncLogFilePath  | Select-Object -skip ($SkipLinesCount - 1)
            $Header = $LogFile | select-Object -first 1
            $Header = $Header -split " " |  Select-Object -skip 1
            $LogFile = $LogFile | Select-Object -skip 1
            $ActiveSyncLogRes += ConvertFrom-Csv $LogFile -Delimiter $Delimiter -header $Header
        }
    }
    return $ActiveSyncLogRes
}
function Update-CSVReferenceFile {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 10.04.2020
        .VER 1   
    .DESCRIPTION
     Update csv reference file with new data from array columns.
    .EXAMPLE
    Update-CSVReferenceFile -CSVFilePath "c:\1.csv" -Array $Array 
    #>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Reference CSV file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $CSVFilePath,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Data array." )]
        [ValidateNotNullOrEmpty()]
        [array] $Array
    )

    if (Test-Path $CSVFilePath) {
        $CSVFile = Import-Csv -Path $CSVFilePath -Encoding UTF8
        $Changes = $false
        foreach ($Item in $CSVFile) {
            foreach ($Item1 in $Array) {
                if ($Item.Ip -eq $Item1.Ip) {
                    if ($Item1.FQDN.contains(".") -or (!$Item.FQDN.contains("."))) {
                        $Item.FQDN = $item1.FQDN
                        $Item.LastSeen = $item1.LastSeen
                        $Item.Host = $item1.Host
                        $Item.Domen = $item1.Domen
                        $Changes = $true
                    }
                }
            }
        }
        foreach ($item1 in $Array) {
            if ($CSVFile.Ip -notcontains $item1.IP) {
                $CSVFile += $item1
                $Changes = $true
                Write-Host  "Add unique ip $item1"              
            }
        }
        if ($Changes) {
            $CSVFile | Sort-Object "Ip" | Export-Csv -Path $CSVFilePath -Encoding UTF8 -NoTypeInformation
        }  
    }
    else {
        #Write-Host "Reference CSV file path [$CSVFilePath] not found!" -ForegroundColor Red   
        $Array | Sort-Object "Ip" | Export-Csv -Path $CSVFilePath -Encoding UTF8 -NoTypeInformation
    }
}

[array]$Global:ColList     = @()
[array]$Global:ColListData = @()
[array]$Global:IPArray     = @()
[array]$ActiveSyncLog      = @()
[array]$UniqueIP           = @()

Get-Item ($ProjectRoot + "\data\Filters\*.*") | Remove-Item -force
$Params           = $global:LogParams
[datetime]$Data1  = (get-date).AddHours(-1 * $Global:HoursToLoad)
$ActiveSyncLog   += (GetLogFilesDividedByDates @Params) |  Select-Object *, @{name="DateTime";e={[datetime]([string]$_.date + " " + [string]$_.time)}}| Where-Object {$_.DateTime -ge $Data1 -and $Params.ExcludeIP -notcontains $_."s-ip"}

if (@($ActiveSyncLog).count -gt 0){
    Write-host "Saving logs"
    $ActiveSyncLog |select-Object * | export-csv -Path $Global:ActiveSyncLogFilePath -Encoding UTF8 -NoTypeInformation
    $UniqueIP = $ActiveSyncLog | Select-Object  @{name="IP";e={$_."c-ip"}} -Unique
    #CollectUniqIP $ActiveSyncLog "c-ip"
    $ActiveSyncLog = ""
}    

$Login          = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_Login
$Pass           = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_Pass
$UserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList (Get-VarToString $Login), $Pass
$Session        = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$($Global:ExchangeServerFQDN)/PowerShell/" -Authentication Kerberos -Credential $UserCredential   # -SessionOption (New-PSSessionOption -SkipCNCheck)
Import-PSSession $Session -AllowClobber

$Data1    = (get-date).AddHours(-1 * $Global:HoursToLoad)
$Messages = Get-MessageTrackingLog -Start $Data1 -ResultSize $Global:MaxResultSize
$Messages | Select-Object * | export-csv -Path $Global:MessageLogFilePath -Encoding UTF8
$UniqueIP += $Messages | Select-Object  @{name="IP";e={$_.ClientIp}} -Unique
#CollectUniqIP $Messages "ClientIp"
$Messages = ""

$AgentLogs  = Get-AgentLog -Start $Data1
$AgentLogs += Get-agentlog  -location $Global:ConnectionFilterLogLocation -StartDate $Data1 #Add connection filter
$AgentLogs | Select-Object * | export-csv -Path $Global:AgentLogFilePath -Encoding UTF8
$UniqueIP += $AgentLogs | Select-Object @{name="IP";e={$_.OriginalClientIp}} -Unique
#CollectUniqIP $AgentLogs "OriginalClientIp"
$AgentLogs = ""
$HashData = @()

$FilterName = "ContentFilterConfig"
$Filter     = get-ContentFilterConfig | Select-Object name, enabled, BypassedRecipients, BypassedSenderDomains, BypassedSenders, @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;name="";BypassedRecipients="";BypassedSenderDomains="";BypassedSenders=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "RecipientFilterConfig"
$Filter     = Get-RecipientFilterConfig | Select-Object identity, enabled, @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;identity=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "IPAllowListEntry"
$Filter     = Get-IPAllowListEntry | Select-Object Iprange, @{name="enabled";e={$true}}, @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;Iprange=""}}
$filter | Format-Table -AutoSize
$Res = Format-PSO $Filter
$HashData += $Res

$FilterName = "IPBlockListEntry"
$Filter     = Get-IPBlockListEntry | Select-Object Iprange, @{name="enabled";e={$true}}, @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;Iprange=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "SenderIdConfig"
$Filter     = Get-SenderIdConfig | Select-Object SpoofedDomainAction, Enabled, TempErrorAction, @{name="Name1";e={$FilterName}} 
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;spoofeddomainaction="";TempErrorAction=""}}
$filter | Format-Table -AutoSize
$Res = Format-PSO $Filter
$HashData += $Res

$FilterName = "SenderReputation"
$Filter     = GET-SenderReputationConfig | Select-Object enabled, identity , @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;identity=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO  $Filter
$HashData += $Res

$FilterName = "SenderFilterConfig"
$Filter     = get-SenderFilterConfig | Select-Object recipientblockedsenderaction, enabled, @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{enabled=$false;Name1=$FilterName;recipientblockedsenderaction=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "IPBlockListProvider"
$Filter     = Get-IPBlockListProvider| Select-Object @{name="IPBlockProvider";e={$_.name}}, @{name="enabled";e={$true}} , @{name="Global";e={"Deny"}}, @{name="Name1";e={ $FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{global="Deny";enabled=$false;Name1=$FilterName;name=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "IPAllowListProvider"
$Filter     = Get-IPAllowListProvider| Select-Object @{name="IPAllowProvider";e={$_.name}}, @{name="enabled";e={$true}}, @{name="Global";e={"Allow"}}, @{name="Name1";e={$FilterName}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{global="Allow";enabled=$false;Name1=$FilterName;name=""}} 
$filter | Format-Table -AutoSize   
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "ContentFilterPhrasBadWord"
$Filter     = Get-ContentFilterPhrase |Where-Object{$_.influence -eq "BadWord"}| Select-Object @{name="BadWord";e={$_.phrase}}, @{name="Global";e={"Deny"}}, @{name="Name1";e={ $FilterName}}, @{name="Enabled";e={$true}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{global="Deny";enabled=$false;Name1=$FilterName;phrase=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO $Filter
$HashData += $Res

$FilterName = "ContentFilterPhraseGoodWord"
$Filter     = Get-ContentFilterPhrase |Where-Object{$_.influence -eq "GoodWord"}| Select-Object @{name="GoodWord";e={$_.phrase}}, @{name="Global";e={"Allow"}}, @{name="Name1";e={ $FilterName}}, @{name="Enabled";e={$true}}
if($null -eq $Filter){$Filter = [PSCustomObject]@{global="Allow";enabled=$false;Name1=$FilterName;phrase=""}}
$filter | Format-Table -AutoSize
$Res       = Format-PSO  $Filter
$HashData += $Res

$Global:ColList
$Global:ColListData | Sort-Object Type, col  | Format-Table -AutoSize

$AllData = $HashData | Select-Object $Global:ColList #| Out-GridView
$AllData | Select-Object * | Export-Clixml $Global:FilterConfig
$Filter  = ExportData $AllData
$Filter | Select-Object Name, Col, Enabled, Action, Data  | export-csv -Path $Global:FilterConfigPath1 -Encoding UTF8 -NoTypeInformation
$Filter = ""

$UniqueIP = Get-UniqueArrayMembers -Array $UniqueIP -ColumnName "IP"
$UniqueIP = Resolve-IPtoFQDNinArray $UniqueIP 
Update-CSVReferenceFile -CSVFilePath $global:IPToFQDN -Array $UniqueIP

Remove-PSSession -Session $Session
"Export completed!"

################################# Script end here ###################################
. "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"