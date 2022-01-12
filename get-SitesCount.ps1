#requires -version 3

<#
.SYNOPSIS
    Обрабатываем логи KES для получения статистики посещения сайтов.
.DESCRIPTION
    Скрипт определяет посещяемость указанных в массиве $SitesNameStr ресурсов по совпадению URL в логах Kaspersky Endpoint Security.  
    Предварительно нужно включить ведение логов: Настройки - Общие параметры - Интерфейс - Уведомления (настройка) - Защита от Веб-угроз - Сыслка обработана - Сохранять в локальном журнале.
    После включения опции в логах появится событие 361.
    1. Читаем из файла в переменную время последнего запуска скрипта. Если файла нет или дата из будущего  читаем сначала лога.
    2. Преобразовываем ее к формату "%Y-%m-%d %H:%M:%S"
    3. Получаем текущую дату в формате "dd.MM.yyyy" и преобразовываем ее к формату "%Y-%m-%d %H:%M:%S" получится что-то типа 2021-01-27 0:00:00. Это нужно чтобы в отчет не попал день запуска скрипта.
    4. Читаем логи в заданном временном интервале.
    5. Далее выбираем строчки с источником Google Chrome.
    6. В выбранных строках проверяем совпадения на наличие строки из массива: $SitesNameStr. Если одна из строк есть пишем индекс строки в объект $SiteVisitedObject с указание даты доступа. Дополнительно ведем цикл который считает количество пользователей работавших с системой. Оценка примерная, базируется на разнице более 20 минут между двумя ссылками.
    7. Все отфильтрованные строки агрегируем по дням и вносим в объект $ObjEvent.
    8. Все собранные объекты объединяются в массив для формирования отчета в HTML и отправки на почту.
    9. После выполнения скрипта вносим в файл текущую дату в формате "dd.MM.yyyy".
.EXAMPLE
    PS C:\> get-SitesCount.ps1 -SMTPPass "SuperPassword" -MailTo "mail1@mail.ru", "mail2@ya.ru"
.INPUTS
    Путь до файла логов Касперского, пароль для отправки почты, ящики куда отправить отчет.
.OUTPUTS
    Письмо с отчетом.
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
# Копируем логи каспера из системной папки к себе для анализа
Write-Output "Копируем логи каспера из системной папки к себе для анализа"
$DefaultLogPath = "C:\Windows\System32\winevt\Logs\Kaspersky Endpoint Security.evtx"
$LogPath = "Kaspersky Endpoint Security.evtx"
$WorkFolder = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location -Path $WorkFolder
Copy-Item -Path $DefaultLogPath -Destination $WorkFolder -Force
# $FullPathLog = Join-Path $WorkFolder $LogPath

if (!(Test-Path $LogPath)) {
    Write-Host -ForegroundColor Red "Ошибка лог файл не найден!"
    exit 1
}

# шаблон преобразования логов
$template = @'
{Name*:Тип события}:     {Value:Ссылка обработана}
{Name*:Программа}:     {Value:Host Process for Windows Services}
{Name*:Программа\Название}:     {Value:svchost.exe}
'@

$SitesNameStr = @("Запрашиваемый", "https://www.gosuslugi.ru/category/health/", "https://www.gosuslugi.ru/", "https://www.mfc-nso.ru/favicon.ico", "https://shkola.nso.ru/favicon.ico", 'https://redesign.trudvsem.ru')
$SiteNames = @('Запись к врачу', 'ГосУслуги', 'МФЦ', 'Школа', 'Работа России')

[DateTime]$LastActivityTime = "2022-01-01 00:00:00"
# Разница времени после которой считается что рабоатет другой челоевек.
$TimeFromLastClisk = 20
$UsersByDate = @{}
# Загрузка логов каспера
Write-Output "Загрузка логов каспера"
$LastReportDateFile = "LastReportDate.txt"
[string]$CurrentDate = Get-Date -Format "dd.MM.yyyy"
# [string]$CurrentDate = "09.12.2021"
$EndTime = Get-Date $CurrentDate -UFormat "%Y-%m-%d %H:%M:%S"

if (Test-Path $LastReportDateFile) {
    $StringDateFromFile = Get-Content $LastReportDateFile
    $DayTimeFromFile = [datetime]::ParseExact($StringDateFromFile, 'dd.MM.yyyy', $null)
    $StartTime = Get-Date $DayTimeFromFile -UFormat "%Y-%m-%d %H:%M:%S"
    if ($StartTime -gt $EndTime) {
        # StartTime в будущем, есть только дата конца
        $FilterEvents = @{
            ID      = 751
            Path    = $LogPath
            EndTime = $EndTime    
        }
    }
    else {
        # Есть дата начала и конца.
        $FilterEvents = @{
            ID        = 751
            Path      = $LogPath
            StartTime = $StartTime
            EndTime   = $EndTime    
        }
    }
}
else {
    # Файла нет, формируем отчет с начала файла
    $FilterEvents = @{
        ID      = 751
        Path    = $LogPath
        EndTime = $EndTime    
    }
}
Write-Output "FilterEvents" $FilterEvents 
$AllEvents = Get-WinEvent -Oldest -FilterHashtable $FilterEvents
#Write-Output "Cписок событий" $AllEvents 
#Write-Output "Количество событий" $AllEvents.Count
Write-Output "Поиск нужных событий"
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
		
        # Смотрим есть ли URL в массиве нужных URLов, если да запоминаем его номер в массиве и время посещения.
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
	    Write-Output "нужный URL"
            $SiteVisitedObject = New-Object -type psobject -Property @{
                ResPosition = $SiteAlive
                VisitTime   = Get-Date $EventTime -Format "dd.MM.yyyy"                    
            }
            $SiteVisited += $SiteVisitedObject
	    Write-Output "SiteVisited " $SiteVisited
        }
            
    }
}

# Получили все события, начиначем формировать отчет по дням
Write-Output "Получили все события, начиначем формировать отчет по дням"
$AllVisits = @()
foreach ($key in $UsersByDate.Keys) {
    $VisitByDate = $SiteVisited | Where-Object { $_.VisitTime -eq $key }
    $CountVisitByDate = @()
    for ($i = 0; $i -lt $SiteNames.Count; $i++) {
        $CountVisitByDate += $($VisitByDate.ResPosition -eq $i).Count
    }
    $EventProps = [ordered]@{
        'Дата'           = $key
        # 'Оценочное количество пользователей' = $UsersByDate.$key
        'ГосУслуги'      = $CountVisitByDate[1]
        'МФЦ'            = $CountVisitByDate[2]
        'Школа'          = $CountVisitByDate[3]
        'Запись к врачу' = $CountVisitByDate[0]
        'Работа России'  = $CountVisitByDate[4]
    }
    $ObjEvent = New-Object -TypeName PSObject -Property $EventProps
    $AllVisits += $ObjEvent
    Write-Output "all visits " $AllVisits 
}
        
Write-Output "Формируем отчет в файл и на почту"
$message = $AllVisits | sort-object { $_."дата" -as [datetime] } | ConvertTo-Html  -Fragment | Out-String
$ReportBody = ConvertTo-HTML -head $head -PostContent $message -PreContent "<h1>Посещения ресурсов по датам с $StringDateFromFile по $CurrentDate</h1>"  | Out-String
$ReportBody | Out-File -FilePath $FilePath
$MailSubject = "$HostName отчет по сайтам на $CurrentDate"
Send-MailReport -ReportBody $ReportBody -MailSubject $MailSubject -SMTPPass $SMTPPass -MailTo $MailTo
Write-Output $CurrentDate > $LastReportDateFile
Stop-Transcript