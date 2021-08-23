$sqlusername = "PEMservice"
$sqlpassword = "<enter your password here>"
$sqlconnectionstring = "Data Source=<enter database server here>;Initial Catalog=PSPEM;User ID = $sqlusername; Password = $sqlpassword;"
$VTApiKey = "<enter your Virustotal API Key here>"
$smtpserver = "<enter your smtp server here>"
$fromaddress = "<enter your from email address here>"
$toaddress = "<enter your to email address here>"
$autowhitelistedthreshold = 2
$sleep = 10
$unknownfolder = "<enter folder path to copy unknown executables>"
$malwarefolder = "<enter folder path to copy malware executables>"
$logging_on = 0
$logfolder = "<enter folder path to log folder>"

$computer = $env:COMPUTERNAME
$username = $env:USERNAME
[System.Collections.ArrayList]$IgnoreListMemory = @()
[System.Collections.ArrayList]$WhiteListMemory = @()
$Anonpass = ConvertTo-SecureString –String “anonymous” –AsPlainText -Force
$Anon = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList "anonymous”, $Anonpass 

Get-EventSubscriber | Unregister-Event

Function Load_IgnoreList()
{
    $IgnoreListMemory.Clear()

    $sqlconnection = New-Object System.Data.SqlClient.SqlConnection
    $sqlconnection.ConnectionString = $sqlconnectionstring
    $sqlconnection.Open()

    $query = “SELECT * FROM IGNORELIST”
    $command = $sqlconnection.CreateCommand()
    $command.CommandText = $query

    $Reader = $command.ExecuteReader()
    While ($Reader.Read()) { $wl_add = $IgnoreListMemory.Add($Reader.GetValue(1))}
    $sqlconnection.Close()
    $IgnoreListMemory
}

Function Load_WhiteList()
{
    $WhiteListMemory.Clear()

    $sqlconnection = New-Object System.Data.SqlClient.SqlConnection
    $sqlconnection.ConnectionString = $sqlconnectionstring
    $sqlconnection.Open()

    $query = “SELECT * FROM WHITELIST”
    $command = $sqlconnection.CreateCommand()
    $command.CommandText = $query

    $Reader = $command.ExecuteReader()
    While ($Reader.Read()) { $wl_add = $WhiteListMemory.Add($Reader.GetValue(2))}
    $sqlconnection.Close()
}

Function Write_WhiteList ([string]$datetime,[string]$process,[string]$hash)
{
    Try {Load_WhiteList} Catch {Write-Host "Whitelist load error"}
    If ($WhiteListMemory -contains $hash) { Write-Host "** Already WhiteListed **"; Return 1}
    Else
    {
        Write-Host "** Adding to WhiteList **"
        $wl_add = $WhiteListMemory.Add($hash)
        $sqlconnection = New-Object System.Data.SqlClient.SqlConnection
        $sqlconnection.ConnectionString = $sqlconnectionstring
        $sqlconnection.Open()
        $sqlcmd = New-Object System.Data.SqlClient.SqlCommand
        $sqlcmd.connection = $sqlconnection
        Try { $sqlcmd.commandtext = "INSERT INTO WHITELIST (DateAdded,Process,Hash) VALUES('{0}','{1}','{2}')" -f $datetime,$process,$hash }
        Catch { Write-Host "SQL insert error" }
        $insert = $sqlcmd.ExecuteNonQuery()
        $sqlconnection.Close()
        Return 0
    }
}

Function Write_Log ([string]$datetime,[string]$process,[string]$path,[string]$commandline,[string]$owner,[string]$hash,[string]$parent,$vtresult)
{
    $sqlconnection = New-Object System.Data.SqlClient.SqlConnection
    $sqlconnection.ConnectionString = $sqlconnectionstring
    $sqlconnection.Open()

    $sqlcmd = New-Object System.Data.SqlClient.SqlCommand
    $sqlcmd.connection = $sqlconnection
    Try {
        $sqlcmd.commandtext = "INSERT INTO PEM (DateTime,Computer,Process,Path,CommandLine,Owner,Hash,ParentProcess,VTResult) VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}')" `
        -f $datetime,$computer,$process,$path,$commandline,$owner,$hash,$parent,$vtresult
    }
    Catch { Write-Host "SQL insert error" }
    $insert = $sqlcmd.ExecuteNonQuery()
    $sqlconnection.Close()
}

Function Query-VirusTotal ([string]$hash)
{
    $body = @{ resource = $hash; apikey = $VTApiKey }
    $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
    While ($VTReport -eq "") {
        Write-Host "No Response...waiting for $sleep seconds and trying again"
        Start-Sleep -Seconds $sleep
        $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
    }
    if ($VTReport.response_code -eq 0) { Return -1 }
    Return $VTReport.positives
}

Function Upload-to-VirusTotal ($path)
{
    Write-Host "Uploading file to VirusTotal..."
    [System.IO.FileInfo] $file = $path
    function Get-AsciiBytes([String] $str) { return [System.Text.Encoding]::ASCII.GetBytes($str)}
    $body = New-Object System.IO.MemoryStream
    [byte[]]$CRLF = 13, 10
    $boundary = [Guid]::NewGuid().ToString().Replace('-','')
    $ContentType = 'multipart/form-data; boundary=' + $boundary
    $b2 = Get-AsciiBytes ('--' + $boundary)
    $body.Write($b2, 0, $b2.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="apikey"'))
    $body.Write($b, 0, $b.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $b = (Get-AsciiBytes $VTApiKey)
    $body.Write($b, 0, $b.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $body.Write($b2, 0, $b2.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="file"; filename="' + $file.Name + '";'))
    $body.Write($b, 0, $b.Length)
    $body.Write($CRLF, 0, $CRLF.Length)            
    $b = (Get-AsciiBytes 'Content-Type:application/octet-stream')
    $body.Write($b, 0, $b.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $b = [System.IO.File]::ReadAllBytes($file.FullName)
    $body.Write($b, 0, $b.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $body.Write($b2, 0, $b2.Length)
    $b = (Get-AsciiBytes '--')
    $body.Write($b, 0, $b.Length)
    $body.Write($CRLF, 0, $CRLF.Length)
    $fileinfo = Get-ItemProperty -Path $File
    If ($fileinfo.length -gt 32mb){ Write-Error 'VirusTotal has a limit of 32MB per file submited' }
    Else { Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/scan' -ContentType $ContentType -Body $body.ToArray() }
}

Function CheckProcess ($id)
{
    $datetime = (get-date).tostring()
    Write-Host "$datetime  -------------------------------------------------------------------------------------------------------------------------"
    Try { $process = Get-Process -Id $id } Catch { Write-Host "ALERT: Process match error!"; Return }
    If ($process -eq $null) { Write-Host "!! NULL-PROCESS !!"; Return }
    $processname = $process.name
    Write-Host "Process:" $processname
    Try { $path = $process.path } Catch { Write-Host "ALERT: Path variable error!"; Return }
    If ($path -eq $null) { Write-Host "!! NULL-PATH !!"; Return }
    Write-Host "Path: $path"
    Try { $commandline = Get-WmiObject Win32_Process -Filter "ProcessId = '$id' " | select -expand commandline } Catch { Write-Host "ALERT: Commandline variable error!"; Return }
    Try { $owner = (Get-WmiObject Win32_Process -Filter "ProcessId = '$id' ").getowner() | select -expand User } Catch { Write-Host "ALERT: Owner variable error!"; Return }
    Try { $hash = (Get-FileHash $path).hash } Catch { Write-Host "ALERT: Hash variable error!"; Write-Host $processname " :: " $path ; Return }
    If ($hash -eq $null) { Write-Host "!! NULL-HASH !!"; Return }
    Write-Host "Hash: $hash"
    Try { $parentid = Get-WmiObject Win32_Process -Filter "ProcessId = '$id' " | select -expand ParentProcessId } Catch { Write-Host "ALERT: ParentId variable error!" }
    Try { $parentprocess = Get-Process -Id $parentid -ErrorAction SilentlyContinue } Catch { Write-Host "ALERT: Parent process match error!" }
    Try { $parent = $parentprocess.name } Catch { Write-Host "ALERT: Parent variable error!" }
    If ($parent -eq $null) { $parent = "Unknown" }
    If ($IgnoreListMemory -contains $hash) { Write-Host "--> Ignored."; Return}
    If ($WhiteListMemory -contains $hash) { Write-Host "--> Whitelisted."}
    Else { 
        Write-Host "** Unknown process - checking VirusTotal **"
        Write-Output "$datetime,$process,$hash" | Out-File -Append "$logfolder\$computer-VT-Checks.txt"
        Try { $vtresult = Query-VirusTotal $hash } Catch { Write-Host "ALERT: VT error on query"; Write-Host $process " :: " $path; Return }
        Write-Host "VTScore: $vtresult"
        If ($vtresult -eq -1)
        {
                Write-Output "$datetime,$process,$hash" | Out-File -Append "$logfolder\$computer-VT-Uploads.txt"
                Upload-to-VirusTotal ($path)
                Send-MailMessage -smtpserver $smtpserver -to $toaddress -from $fromaddress -subject "PEM - Unknown Process - $computer - $owner - $processname" -Credential $Anon `
                -body "Unknown process detected & Uploaded to VirusTotal:`nProcess: $processname`nPath: $path`nCommandline: $Commandline`nComputer: $computer`nOwner: $owner`nHash: $hash`nVTScore: $vtresult"
                Copy-Item $path $unknownfolder
        }
        Else
        {
            If ($vtresult -le $autowhitelistedthreshold) 
            {
                Write-Output "$datetime,$process,$hash" | Out-File -Append "$logfolder\$computer-Whitelist-Additions.txt"
                $ww = Write_WhiteList $datetime $process.name $hash
                #If ($ww -eq 0) { Send-MailMessage -smtpserver $smtpserver -to $toaddress -from $fromaddress -subject "PEM - Process Whitelisted - $computer - $owner - $processname" -Credential $Anon `
                #-body "New process whitelisted:`nProcess: $processname`nPath: $path`nCommandline: $Commandline`nComputer: $computer`nOwner: $owner`nHash: $hash`nVTScore: $vtresult" }
            }
            Else
            {
                Send-MailMessage -smtpserver $smtpserver -to $toaddress -from $fromaddress -subject "PEM - Malware Detection - $computer - $owner - $processname" -Credential $Anon `
                -body "Malware process detected:`nProcess: $processname`nPath: $path`nCommandline: $Commandline`nComputer: $computer`nOwner: $owner`nHash: $hash`nVTScore: $vtresult"
                Copy-Item $path $malwarefolder
            }
        }
    }
    Try { Write_Log $datetime $process.name $path $commandline $owner $hash $parent $vtresult} Catch { Write-Host "ALERT: SQL Write error: $datetime $process.name $path $commandline $owner $hash $parent $vtresult" }
    Write-Host -Object "-----------------------------------------------------------------------------------------------------------------------------------------------"
}

$action = {

    Try {
        If ($logging_on -eq 1) { Start-Transcript -Path "$logfolder\$computer-log.txt" -Append }
        $id = $event.SourceEventArgs.NewEvent.ProcessId
        CheckProcess $id
        If ($logging_on -eq 1) { Stop-Transcript }
        }
    Catch { 
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Host -Object "Action Error! - $ErrorMessage; $FailedItem"
        If ($logging_on -eq 1) { Stop-Transcript }
        }
}

If ($logging_on -eq 1) { Start-Transcript -Path "$logfolder\$computer.txt" }
Write-Host "Version: 1.2"
Try {Load_IgnoreList} Catch {Write-Host "Ignorelist load error"}
Try {Load_WhiteList} Catch {Write-Host "Whitelist load error"}
Get-Process | foreach-object { CheckProcess $_.id }

Write-Host ""
Write-Host "Waiting on new processes:"

Register-CimIndicationEvent -ClassName 'Win32_ProcessStartTrace' -SourceIdentifier "ProcessStarted" -Action $action

If ($logging_on -eq 1) { Stop-Transcript }
