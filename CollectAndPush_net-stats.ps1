<#
#Extracts Metrics by sshing to an ESX host, running net-stats and pushes the selected data into vRops as a custom metric on the HostSystem resource kind.
#Requires posh-ssh module --> Find-Module Posh-SSH | Install-Module
#v1.0 vMan.ch, 08.09.2018 - Initial Version

    SSH to each server in Nodes using posh-ssh and run command "net-stats -A -t WwQqihVvh | grep vmnic3-pollWorldNetpollTx" and then regex to extract usage,ready,cstp metrics for vmnic3-pollWorldNetpollTx[00]

    Script requires Powershell v3 and above.

    Run the command below to store user and pass in secure credential XML for each environment

        $cred = Get-Credential
        $cred | Export-Clixml -Path "D:\vRops\config\vRops.xml"

#>

param
(
    [array]$nodes = @('192.168.88.55','192.168.88.56'),
    [String]$creds = 'esxi',
    [String]$vRopsCreds = 'vrops',
    [String]$vRopsAddress = 'vrops.vman.ch'

)

#Take all certs.
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls

#Logging Function
Function Log([String]$message, [String]$LogType, [String]$LogFile){
    $date = Get-Date -UFormat '%m-%d-%Y %H:%M:%S'
    $message = $date + "`t" + $LogType + "`t" + $message
    $message >> $LogFile
}

#Log rotation function
function Reset-Log 
{ 
    #function checks to see if file in question is larger than the paramater specified if it is it will roll a log and delete the oldes log if there are more than x logs. 
    param([string]$fileName, [int64]$filesize = 1mb , [int] $logcount = 5) 
     
    $logRollStatus = $true 
    if(test-path $filename) 
    { 
        $file = Get-ChildItem $filename 
        if((($file).length) -ige $filesize) #this starts the log roll 
        { 
            $fileDir = $file.Directory 
            $fn = $file.name #this gets the name of the file we started with 
            $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
            $filefullname = $file.fullname #this gets the fullname of the file we started with 
            #$logcount +=1 #add one to the count as the base file is one more than the count 
            for ($i = ($files.count); $i -gt 0; $i--) 
            {  
                #[int]$fileNumber = ($f).name.Trim($file.name) #gets the current number of the file we are on 
                $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
                $operatingFile = $files | ?{($_.name).trim($fn) -eq $i} 
                if ($operatingfile) 
                 {$operatingFilenumber = ($files | ?{($_.name).trim($fn) -eq $i}).name.trim($fn)} 
                else 
                {$operatingFilenumber = $null} 
 
                if(($operatingFilenumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount)) 
                { 
                    $operatingFilenumber = $i 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force 
                } 
                elseif($i -ge $logcount) 
                { 
                    if($operatingFilenumber -eq $null) 
                    {  
                        $operatingFilenumber = $i - 1 
                        $operatingFile = $files | ?{($_.name).trim($fn) -eq $operatingFilenumber} 
                        
                    } 
                    write-host "deleting " ($operatingFile.FullName) 
                    remove-item ($operatingFile.FullName) -Force 
                } 
                elseif($i -eq 1) 
                { 
                    $operatingFilenumber = 1 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    write-host "moving to $newfilename" 
                    move-item $filefullname -Destination $newfilename -Force 
                } 
                else 
                { 
                    $operatingFilenumber = $i +1  
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force    
                } 
                     
            } 
 
                     
          } 
         else 
         { $logRollStatus = $false} 
    } 
    else 
    { 
        $logrollStatus = $false 
    } 
    $LogRollStatus 
} 

Function GetObject([String]$vRopsObjName, [String]$resourceKindKey, [String]$vRopsServer, $vRopsCredentials){

    $vRopsObjName = $vRopsObjName -replace ' ','%20'

    [xml]$Checker = Invoke-RestMethod -Method Get -Uri "https://$vRopsServer/suite-api/api/resources?resourceKind=$resourceKindKey&name=$vRopsObjName" -Credential $vRopsCredentials -Headers $header -ContentType $ContentType

#Check if we get 0

    if ([Int]$Checker.resources.pageInfo.totalCount -eq '0'){

    Return $CheckerOutput = ''

    }

    else {

        # Check if we get more than 1 result and apply some logic
            If ([Int]$Checker.resources.pageInfo.totalCount -gt '1') {

                $DataReceivingCount = $Checker.resources.resource.resourceStatusStates.resourceStatusState.resourceStatus -eq 'DATA_RECEIVING'

                    If ($DataReceivingCount.count -gt 1){

                     If ($Checker.resources.resource.ResourceKey.name -eq $vRopsObjName){

                        ForEach ($Result in $Checker.resources.resource){

                            IF ($Result.resourceStatusStates.resourceStatusState.resourceStatus -eq 'DATA_RECEIVING'){

                            $CheckerOutput = New-Object PsObject -Property @{Name=$vRopsObjName; resourceId=$Result.identifier; resourceKindKey=$Result.resourceKey.resourceKindKey}

                            Return $CheckerOutput
                    
                            }   
                        }

                      }
                    }
            
                    Else 
                    {

                    ForEach ($Result in $Checker.resources.resource){

                        IF ($Result.resourceStatusStates.resourceStatusState.resourceStatus -eq 'DATA_RECEIVING'){

                            $CheckerOutput = New-Object PsObject -Property @{Name=$vRopsObjName; resourceId=$Result.identifier; resourceKindKey=$Result.resourceKey.resourceKindKey}

                            Return $CheckerOutput
                    
                        }   
                    }
            }  
         }

        else {
    
            $CheckerOutput = New-Object PsObject -Property @{Name=$vRopsObjName; resourceId=$Checker.resources.resource.identifier; resourceKindKey=$Checker.resources.resource.resourceKey.resourceKindKey}

            Return $CheckerOutput

            }
        }
}



#Get Stored Credentials

$ScriptPath = (Get-Item -Path ".\" -Verbose).FullName

#cleanupLogFile
$LogFilePath = $ScriptPath + '\log\Logfile.log'
Reset-Log -fileName $LogFilePath -filesize 10mb -logcount 5

if($creds -gt ""){

    $cred = Import-Clixml -Path "$ScriptPath\config\$creds.xml"
    }
    else
    {
    echo "No Credentials Selected"
    Exit
    }

if($vRopsCreds -gt ""){

    $vRopsCred = Import-Clixml -Path "$ScriptPath\config\$vRopsCreds.xml"

    }
    else
    {
    echo "vRops Credentials not specified, stop hammer time!"
    Exit
    }

#vars
$RunDateTime = (Get-date)
$RunDateTime = $RunDateTime.tostring("yyyyMMddHHmmss")
$LogFileLoc = $ScriptPath + '\Log\Logfile.log'

#Concurrent jobs to run
$maxJobCount = 14
$sleepTimer = 3
$jobQueue = New-Object System.Collections.ArrayList

$ResourceLookupTable = @{}

#Get and store Resource ID for all hosts in nodes variable.
ForEach ($node in $nodes) {

$resource = GetObject $node 'HostSystem' $vRopsAddress $vRopsCred

$ResourceLookupTable.Add($node,$resource.resourceId)



}

$scriptBlock = {

param
(
    $node,
    $cred,
    $vRopsAddress,
    $vRopsCred,
    $resourceId,
    $LFPath,
    $LFDateTime
)

#Logging Function
Function Log([String]$message, [String]$LogType, [String]$LogFile){
    $date = Get-Date -UFormat '%m-%d-%Y %H:%M:%S'
    $message = $date + "`t" + $LogType + "`t" + $message
    $message >> $LogFile
}

Function Start-CountDown{
[CmdLetBinding()]
Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true,ParameterSetName='Date')]
    [datetime]$Date,

    [Parameter(Mandatory=$false,Position=1,ParameterSetName='Time')]
    [int]$Hours,

    [Parameter(Mandatory=$false,Position=2,ParameterSetName='Time')]
    [int]$Minutes,

    [Parameter(Mandatory=$false,Position=3,ParameterSetName='Time')]
    [int]$Seconds
)
    if($PSCmdlet.ParameterSetName -eq 'Date'){
        $Seconds = ((Get-Date $Date) - (Get-Date)).TotalSeconds
    } elseif($PSCmdlet.ParameterSetName -eq 'Time'){
        switch($PSBoundParameters.Keys){
            (!'Seconds'){
                $Seconds = 0
            }
            ('Minutes'){
                $Seconds = $Seconds + ($Minutes * 60)
            }
            ('Hours'){
                $Seconds = $Seconds + ($Hours * 3600)
            }
        }
    }

    $i = 0
    while($i -lt $Seconds){
        Write-Progress -Activity 'Waiting' -SecondsRemaining $Seconds
        Start-Sleep -Seconds 1
        $Seconds--
    }
}

#Take all certs.
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls

#Stuff for Invoke-RestMethod
$ContentType = "application/xml"
$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$header.Add("Accept", 'application/xml')
$header.Add("User-Agent", 'vRopsPowershellMetricExtractor/1.0')

  #$Collections = 0
  New-SSHSession -ComputerName $node -Credential $cred -AcceptKey -Force

  do{

    $StopWatch = New-Object System.Diagnostics.Stopwatch
    $StopWatch.Start()
    [DateTime]$NowDate = (Get-date)
    $NowDate = $NowDate.AddSeconds(–$NowDate.Second)
    [int64]$NowDateEpoc = (([DateTimeOffset](Get-Date)).ToUniversalTime().ToUnixTimeMilliseconds())

    Log -Message "Running net-stats for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath

    $commandOutput = Invoke-SSHCommand -SessionId 0 -Command "net-stats -A -t WwQqihVvh | grep vmnic3-pollWorldNetpollTx"

    Log -Message "Finished net-stats for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath

    Log -Message "Start Regex for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath

   $usage = $commandOutput.Output | Select-String -Pattern '(?:"used": )(\d{0,3}\.\d{1,2}), (?:"ready": )(\d{0,3}\.\d{1,2}), (?:"cstp": )(\d{0,3}\.\d{1,2}), "name": "vmnic3-pollWorldNetpollTx\[00\]"' | % {"$($_.matches.groups[1])"}
   $ready = $commandOutput.Output | Select-String -Pattern '(?:"used": )(\d{0,3}\.\d{1,2}), (?:"ready": )(\d{0,3}\.\d{1,2}), (?:"cstp": )(\d{0,3}\.\d{1,2}), "name": "vmnic3-pollWorldNetpollTx\[00\]"' | % {"$($_.matches.groups[2])"}
   $cstp = $commandOutput.Output | Select-String -Pattern '(?:"used": )(\d{0,3}\.\d{1,2}), (?:"ready": )(\d{0,3}\.\d{1,2}), (?:"cstp": )(\d{0,3}\.\d{1,2}), "name": "vmnic3-pollWorldNetpollTx\[00\]"' | % {"$($_.matches.groups[3])"}

    Log -Message "Finished Regex for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath

        [xml]$MetricXML = @('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <ops:stat-contents xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ops="http://webservice.vmware.com/vRealizeOpsMgr/1.0/">
                <ops:stat-content statKey="vMan|net|vmnic3|pollWorldNetpollTx[00]|Usage">
                  <ops:timestamps>'+$NowDateEpoc+'</ops:timestamps>
                    <ops:data>'+$usage+'</ops:data>
                    <ops:unit>num</ops:unit>
                </ops:stat-content>
                <ops:stat-content statKey="vMan|net|vmnic3|pollWorldNetpollTx[00]|Ready">
                  <ops:timestamps>'+$NowDateEpoc+'</ops:timestamps>
                    <ops:data>'+$ready+'</ops:data>
                    <ops:unit>num</ops:unit>
                </ops:stat-content>
                <ops:stat-content statKey="vMan|net|vmnic3|pollWorldNetpollTx[00]|Costop">
                  <ops:timestamps>'+$NowDateEpoc+'</ops:timestamps>
                    <ops:data>'+$cstp+'</ops:data>
                    <ops:unit>num</ops:unit>
                </ops:stat-content>
            </ops:stat-contents>'
            )

        $vRopsMetricURL = 'https://' + $vRopsAddress + '/suite-api/api/resources/'+$resourceid+'/stats'

        Log -Message "Running invoke for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath
         
        Invoke-RestMethod -Method POST -uri $vRopsMetricURL -Body $MetricXML -Credential $vRopsCred -ContentType "application/xml;charset=utf-8" -TimeoutSec 120

        Log -Message "Finished invoke for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath

    $StopWatch.Stop()
    $runtime = ($StopWatch.ElapsedMilliseconds / 1000)
    Log -Message "$node took $runtime to run the collection" -LogType "JOB-$LFDateTime" -LogFile $LFPath
    $CountDownSeconds = 180 - $runtime
    Log -Message "$node sleeping for  $CountDownSeconds seconds" -LogType "JOB-$LFDateTime" -LogFile $LFPath
    Start-CountDown -Seconds $CountDownSeconds


    Clear-Variable commandOutput,MetricXML,usage,ready,cstp,CountDownSeconds,StopWatch,runtime


}until($ForEVA)

#Terminate SSH session
Log -Message "Terminating SSH session for $node" -LogType "JOB-$LFDateTime" -LogFile $LFPath
Remove-SSHSession -SessionId 0

}


#######START JOBS#######


Foreach ($node in $nodes){

              # Wait until job queue has a slot available.
              while ($jobQueue.count -ge $maxJobCount) {
                echo "jobQueue count is $($jobQueue.count): Waiting for jobs to finish before adding more."
                foreach ($jobObject in $jobQueue.toArray()) {
            	    if ($jobObject.job.state -eq 'Completed') { 
            	      echo "jobQueue count is $($jobQueue.count): Removing job"
            	      $jobQueue.remove($jobObject) 		
            	    }
            	  }
            	sleep $sleepTimer
              }  
  
              echo "jobQueue count is $($jobQueue.count): Adding new job: $($node)"
              
              Log -Message "Executing job for $node, check individual files" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc

              $LF = ($ScriptPath + '\Log\' + $node + '.log')

              $job = Start-Job -name $node -ScriptBlock $scriptBlock -ArgumentList $node, $cred, $vRopsAddress, $vRopsCred, $ResourceLookupTable.Item($node), $LF, $RunDateTime

              $jobObject          = "" | select Element, job
              $jobObject.Element  = $Element
              $jobObject.job      = $job
              $jobQueue.add($jobObject) | Out-Null
            }

Get-Job #| Wait-Job | Out-Null
