#requires -version 3

<#
.SYNOPSIS
    ������������ ���� KES ��� ��������� ���������� ��������� ������.
.DESCRIPTION
    ������ ���������� ������������ ��������� � ������� $SitesNameStr �������� �� ���������� URL � ����� Kaspersky Endpoint Security.  
    �������������� ����� �������� ������� �����: ��������� - ����� ��������� - ��������� - ����������� (���������) - ������ �� ���-����� - ������ ���������� - ��������� � ��������� �������.
    ����� ��������� ����� � ����� �������� ������� 361.
    1. ������ �� ����� � ���������� ����� ���������� ������� �������. ���� ����� ��� ��� ���� �� ��������  ������ ������� ����.
    2. ��������������� �� � ������� "%Y-%m-%d %H:%M:%S"
    3. �������� ������� ���� � ������� "dd.MM.yyyy" � ��������������� �� � ������� "%Y-%m-%d %H:%M:%S" ��������� ���-�� ���� 2021-01-27 0:00:00. ��� ����� ����� � ����� �� ����� ���� ������� �������.
    4. ������ ���� � �������� ��������� ���������.
    5. ����� �������� ������� � ���������� Google Chrome.
    6. � ��������� ������� ��������� ���������� �� ������� ������ �� �������: $SitesNameStr. ���� ���� �� ����� ���� ����� ������ ������ � ������ $SiteVisitedObject � �������� ���� �������. ������������� ����� ���� ������� ������� ���������� ������������� ���������� � ��������. ������ ���������, ���������� �� ������� ����� 20 ����� ����� ����� ��������.
    7. ��� ��������������� ������ ���������� �� ���� � ������ � ������ $ObjEvent.
    8. ��� ��������� ������� ������������ � ������ ��� ������������ ������ � HTML � �������� �� �����.
    9. ����� ���������� ������� ������ � ���� ������� ���� � ������� "dd.MM.yyyy".
.EXAMPLE
    PS C:\> get-SitesCount.ps1 -SMTPPass "SuperPassword" -MailTo "mail1@mail.ru", "mail2@ya.ru"
.INPUTS
    ���� �� ����� ����� �����������, ������ ��� �������� �����, ����� ���� ��������� �����.
.OUTPUTS
    ������ � �������.
.NOTES
    General notes
#>
[cmdletbinding()]
Param(
    [string]$SMTPPass = "igausmhpjplthlht",
    $MailTo = "dgurev@galex.ru"
)
Start-Transcript
function Send-MailReport {
    param (
        $ReportBody,
        [string]$MailSubject,
        [string]$SMTPPass,
        $MailTo
    )
    $MailFrom = 'nso-site@yandex.ru'
    $SMTPServer = "smtp.yandex.ru"
    $SMTPPort = 587
    $encoding = [System.Text.Encoding]::UTF8
    $SMTPUser = "nso-site"
    $PassSMTP = convertto-securestring $SMTPPass -asplaintext -force
    $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SMTPUser, $PassSMTP

    Send-MailMessage -To $MailTo -From $MailFrom -subject $MailSubject -body $ReportBody -BodyAsHtml -smtpserver $SMTPServer -port $SMTPPort -UseSsl -Credential $Cred -Encoding $encoding

}

function findinarr {
    param (
        $array, 
        $value
    )
    for ($i = 0; $i -lt $array.count; $i++) {
        if ($array[$i] -eq $value) { 		
            $Res = $i 
            break
        }
    }
    if ($Res) {
        Return($Res)
    }
    else {
        Return("Err")
    }
}
$head = @'
<style>
body { background-color:#ffffff;
           font-family:Tahoma;
	   font-size:12pt; }
td, th { border:1px solid black;
           border-collapse:collapse; }
th { color:black;
           background-color:black; }
           table, tr, td, th { padding: 2px; margin: 0px }
table {
font-family: "Lucida Sans Unicode", "Lucida Grande", Sans-Serif;
font-size: 14px;
border-radius: 10px;
border-spacing: 0;
text-align: center;
}
th {
background: #BCEBDD;
color: black;
text-shadow: 0 1px 1px #2D2020;
padding: 10px 20px;
}
th, td {
border-style: solid;
border-width: 0 1px 1px 0;
border-color: black;
}
th:first-child, td:first-child {
text-align: left;
}
th:first-child {
border-top-left-radius: 10px;
}
th:last-child {
border-top-right-radius: 10px;
border-right: none;
}
td {
padding: 10px 20px;
background: #F8E391;
}
tr:last-child td:first-child {
border-radius: 0 0 0 10px;
}
tr:last-child td:last-child {
border-radius: 0 0 10px 0;
}
tr td:last-child {
border-right: none;
}
</style>
'@
$HostName = $Env:Computername
$FilePath = "sites.html"
# �������� ���� ������� �� ��������� ����� � ���� ��� �������
Write-Output "�������� ���� ������� �� ��������� ����� � ���� ��� �������"
$DefaultLogPath = "C:\Windows\System32\winevt\Logs\Kaspersky Endpoint Security.evtx"
$LogPath = "Kaspersky Endpoint Security.evtx"
$WorkFolder = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location -Path $WorkFolder
Copy-Item -Path $DefaultLogPath -Destination $WorkFolder -Force
# $FullPathLog = Join-Path $WorkFolder $LogPath

if (!(Test-Path $LogPath)) {
    Write-Host -ForegroundColor Red "������ ��� ���� �� ������!"
    exit 1
}

# ������ �������������� �����
$template = @'
{Name*:��� �������}:     {Value:������ ����������}
{Name*:���������}:     {Value:Host Process for Windows Services}
{Name*:���������\��������}:     {Value:svchost.exe}
'@

$SitesNameStr = @("�������������", "https://www.gosuslugi.ru/category/health/", "https://www.gosuslugi.ru/", "https://www.mfc-nso.ru/favicon.ico", "https://shkola.nso.ru/favicon.ico", 'https://redesign.trudvsem.ru')
$SiteNames = @('������ � �����', '���������', '���', '�����', '������ ������')

[DateTime]$LastActivityTime = "2022-01-01 00:00:00"
# ������� ������� ����� ������� ��������� ��� �������� ������ ��������.
$TimeFromLastClisk = 20
$UsersByDate = @{}
# �������� ����� �������
Write-Output "�������� ����� �������"
$LastReportDateFile = "LastReportDate.txt"
[string]$CurrentDate = Get-Date -Format "dd.MM.yyyy"
# [string]$CurrentDate = "09.12.2021"
$EndTime = Get-Date $CurrentDate -UFormat "%Y-%m-%d %H:%M:%S"

if (Test-Path $LastReportDateFile) {
    $StringDateFromFile = Get-Content $LastReportDateFile
    $DayTimeFromFile = [datetime]::ParseExact($StringDateFromFile, 'dd.MM.yyyy', $null)
    $StartTime = Get-Date $DayTimeFromFile -UFormat "%Y-%m-%d %H:%M:%S"
    if ($StartTime -gt $EndTime) {
        # StartTime � �������, ���� ������ ���� �����
        $FilterEvents = @{
            ID      = 751
            Path    = $LogPath
            EndTime = $EndTime    
        }
    }
    else {
        # ���� ���� ������ � �����.
        $FilterEvents = @{
            ID        = 751
            Path      = $LogPath
            StartTime = $StartTime
            EndTime   = $EndTime    
        }
    }
}
else {
    # ����� ���, ��������� ����� � ������ �����
    $FilterEvents = @{
        ID      = 751
        Path    = $LogPath
        EndTime = $EndTime    
    }
}
Write-Output "FilterEvents" $FilterEvents 
$AllEvents = Get-WinEvent -Oldest -FilterHashtable $FilterEvents
#Write-Output "C����� �������" $AllEvents 
#Write-Output "���������� �������" $AllEvents.Count
Write-Output "����� ������ �������"
$EventData = ''
$SiteVisited = @()
foreach ($Events in $AllEvents) {
    $Ev = [xml]$Events.ToXml()
    $test = $Ev.Event.EventData.Data | ConvertFrom-String
    #Write-Output $test
    $EventData = $Ev.Event.EventData.Data | ConvertFrom-String -TemplateContent $template
    [DateTime]$EventTime = Get-Date $Ev.Event.System.TimeCreated.SystemTime -UFormat "%Y-%m-%d %H:%M:%S"
    $TimeDiff = $EventTime - $LastActivityTime
    $LastActivityTime = $EventTime
    if ($TimeDiff.TotalMinutes -gt $TimeFromLastClisk ) {
	Write-Output "check new date"
        $NewDate = Get-Date $EventTime -Format "dd.MM.yyyy"
        if ($UsersByDate.$NewDate) {
            Write-Output "old date!"
            $UsersByDate.$NewDate += 1		
        }
        else {
	   Write-Output "new date!"
           $UsersByDate.Add($NewDate, 1)
        }
		
        # ������� ���� �� URL � ������� ������ URL��, ���� �� ���������� ��� ����� � ������� � ����� ���������.
        #Write-Output "EventData[6].Value" $EventData[6]
        $SiteAlive = findinarr $SitesNameStr $EventData[6].Value
	#------------------------------
	Write-Output "______________________"
	Write-Output "site alive" $SiteAlive
	Write-Output "event data" $EventData
	Write-Output "end event data" 
	Write-Output "______________________"
	#------------------------------

        if ($SiteAlive -ne "Err") {
	    Write-Output "������ URL"
            $SiteVisitedObject = New-Object -type psobject -Property @{
                ResPosition = $SiteAlive
                VisitTime   = Get-Date $EventTime -Format "dd.MM.yyyy"                    
            }
            $SiteVisited += $SiteVisitedObject
	    Write-Output "SiteVisited " $SiteVisited
        }
            
    }
}

# �������� ��� �������, ��������� ����������� ����� �� ����
Write-Output "�������� ��� �������, ��������� ����������� ����� �� ����"
$AllVisits = @()
foreach ($key in $UsersByDate.Keys) {
    $VisitByDate = $SiteVisited | Where-Object { $_.VisitTime -eq $key }
    $CountVisitByDate = @()
    for ($i = 0; $i -lt $SiteNames.Count; $i++) {
        $CountVisitByDate += $($VisitByDate.ResPosition -eq $i).Count
    }
    $EventProps = [ordered]@{
        '����'           = $key
        # '��������� ���������� �������������' = $UsersByDate.$key
        '���������'      = $CountVisitByDate[1]
        '���'            = $CountVisitByDate[2]
        '�����'          = $CountVisitByDate[3]
        '������ � �����' = $CountVisitByDate[0]
        '������ ������'  = $CountVisitByDate[4]
    }
    $ObjEvent = New-Object -TypeName PSObject -Property $EventProps
    $AllVisits += $ObjEvent
    Write-Output "all visits " $AllVisits 
}
        
Write-Output "��������� ����� � ���� � �� �����"
$message = $AllVisits | sort-object { $_."����" -as [datetime] } | ConvertTo-Html  -Fragment | Out-String
$ReportBody = ConvertTo-HTML -head $head -PostContent $message -PreContent "<h1>��������� �������� �� ����� � $StringDateFromFile �� $CurrentDate</h1>"  | Out-String
$ReportBody | Out-File -FilePath $FilePath
$MailSubject = "$HostName ����� �� ������ �� $CurrentDate"
Send-MailReport -ReportBody $ReportBody -MailSubject $MailSubject -SMTPPass $SMTPPass -MailTo $MailTo
Write-Output $CurrentDate > $LastReportDateFile
Stop-Transcript