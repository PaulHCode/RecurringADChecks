#Monthly AD Health Checks
#Requires -Modules grouppolicy
#Requires -Modules dhcpserver
#Requires -Modules activedirectory

<#
.SYNOPSIS
    Runs some simple checks against AD and generates a report that should be reviewed on a regular basis
.DESCRIPTION
    This script is designed to be used as a framework for others to modify as they see fit for their environments, not as a one-size-fits-all solution.
    If you would like a more in-depth and sophisticated scan pleast contact Microsoft for an AD assessment.
    This is intended to run as a scheduled task or as part of a SCORCH runbook and has a hardcoded value.
.NOTES
    Author:  Paul Harrison
#>

$LogFile = "C:\temp\adreport.html" #"\\servername\share\path\ADReport.html"

#Values to define if you want it to email automatically - also uncomment the last line of this file
<#
$Body = "Please review the attached file for AD recommendations. The attached report has shortcuts to each section that are not in the body of the email.`n$HTMLReport"
$SubjectLine = "Recurring AD Report"
$ToAddress = @("Alice@contoso.com","Bob@contoso.com","Carmet@contoso.com","David@contoso.com")
$FromAddress = "DoNotReply@contoso.com"
$SMTPServer = 'mail.contoso.com'
#>

Function New-HTMLReport {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Title
    )
    "<H1 id=$('"'+$($Title.Replace(' ',''))+'"')>$($title)</H1><br>`n"
}

Function New-HTMLReportSection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SectionTitle,
        [Parameter()]
        [array]
        $SectionContents = $Null
    )
    $emptyNote = [PSCustomObject]@{message = "[empty]" }
    $MyOut = @()
    $MyOut += "<br><H2 id=$('"'+$($SectionTitle.Replace(' ',''))+'"')>$SectionTitle</H2>`n"
    If ($SectionContents -eq "" -or $SectionContents -eq $Null) {
        $MyOut += "<br>$($emptyNote | Select-Object message | ConvertTo-HTML -Fragment)`n"
    }
    Else {
        $MyOut += "<br>$($SectionContents | ConvertTo-Html -Fragment)`n"
    }
    $MyOut
}

#Find domains to run this report against
$Trusts = Get-ADTrust -Filter * | Where{$_.Direction -in @([Microsoft.ActiveDirectory.Management.ADTrustDirection]::BiDirectional, [Microsoft.ActiveDirectory.Management.ADTrustDirection]::Inbound)}
$FoundForestToRunAgainst = $Trusts | %{try{Get-ADForest $_.name;if($?){$_.Name}}catch{}}
$AdditionalDomainsToRunAgainst = ForEach($Forest in $FoundForestToRunAgainst){
    ForEach($domain in $Forest.Domains){
        try{$Null = Get-ADDomain $domain;if($?){domain}}catch{}
    }
}
$TargetDomains = [array]$AdditionalDomainsToRunAgainst + (Get-ADDomain).DNSRoot | select -Unique

[string]$HTMLReport = ""

ForEach($domain in $TargetDomains){

    $HTMLReport += New-HTMLReport -Title "AD Report for $domain on $((Get-Date).ToShortDateString()) at $((Get-Date).ToLongTimeString())"

    $DomainDN = (Get-ADDomain -Server $domain).distinguishedName

    #get objects in the computers container
    $ObjectInComputerContainer = Get-ADObject -SearchBase $("CN=Computers," + $DomainDN) -Filter { ObjectClass -ne 'container' } -Server $domain
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Objects in the Computers container" -SectionContents $($ObjectInComputerContainer | select name,objectclass,objectguid)

    #Get objects in the users container
    $NormalObjectsInUsers = @() #This can be populated with exceptions like built in objects
    $ExtraObjectsInUsersContainer = Get-ADObject -SearchBase $("CN=Users," + $DomainDN) -Filter { ObjectClass -ne 'container' } -Server $domain | Where-Object { $($_.Name) -notin $NormalObjectsInUsers }
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Extra objects in the Users container" -SectionContents $($ExtraObjectsInUsersContainer | select name,objectclass)

    #Find all empty groups
    $emptyGroups = Get-ADGroup -Filter * -Properties members -Server $domain | Where-Object { $($_.members.count) -eq 0 }
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Empty groups" -SectionContents $($emptyGroups | select samaccountname,distinguishedName)

    #Find DCs not protected from accidental deletion
    $DCsUnprotectedFromAccidentalDeletion = ((get-addomaincontroller -filter * -Server $domain).computerObjectDN | Get-ADObject -Server $domain -properties ProtectedFromAccidentalDeletion | Where-Object { -not $_.ProtectedFromAccidentalDeletion })
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - DCs not protected from accidental deletion" -SectionContents $($DCsUnprotectedFromAccidentalDeletion | select name)

    #OUs not protected from accidental deletion
    $OUsUnprotectedFromAccidentalDeletion = ((Get-ADOrganizationalUnit -Filter * -Server $domain).DistinguishedName | Get-ADObject -properties ProtectedFromAccidentalDeletion -Server $domain | Where-Object { -not $_.ProtectedFromAccidentalDeletion })
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - OUs not protected from accidental deletion" -SectionContents $($OUsUnprotectedFromAccidentalDeletion | select distinguishedName)

    #Find computers with the DHCP server naming convention that are not authorized - comment out this section if you don't want to run against DHCP servers - don't forget to remove the #Requires for DHCPserrver at the top too
    If($domain -eq (Get-ADDomain).dnsroot){ #only works against the domain this machine is on
        $AuthorizedDHCPServers = get-dhcpServerInDC
        $UnauthorizedDHCPServers = (get-adcomputer -filter { samaccountname -like "*pattern*" }).HostName | Where-Object { $_.dnsHostName -notin $AuthorizedDHCPServers.dnsName }
        $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Servers with the name of a DHCP server that are not authorized DHCP servers" -SectionContents $($UnauthorizedDHCPServers | select name)
    }

    #Disabled computer objects
    $DisabledComputerObjects = Get-ADComputer -filter * -Properties whencreated, LastLogonDate -Server $domain | Where-Object { -not $_.Enabled }
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Disabled computer objects" -SectionContents $($DisabledComputerObjects | select name,distinguishedname,whencreated,lastlogondate)

    #disabled users
    $DisabledUserObjects = Get-ADUser -filter { Name -notlike "SystemMailbox*" } -properties whencreated, lastlogondate, memberof -Server $domain | Where-Object { -not $_.enabled }
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Disabled user objects" -SectionContents $($DisabledUserObjects | select samaccountname,enabled,lastlogondate)

    #Tombstone info
    $TombstoneLifetime = (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=services,$((Get-ADRootDSE -Server $domain).configurationNamingContext)" -properties tombstoneLifetime -Server $domain).tombstoneLifetime
    $TombstoneDate = (get-Date).AddDays(-1 * $TombstoneLifetime)

    #Computer objects with lastlogondate older than tombstone
    $oldComputers = Get-ADComputer -filter { LastLogonDate -lt $TombstoneDate } -properties LastLogonDate -Server $domain
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Computers with lastLogonDate older than the tombstone - $TombstoneLifetime days ago - $($TombstoneDate.ToShortDateString())" -SectionContents $($oldComputers | select name,lastlogondate,distinguishedname)

    #Disabled user objects with group membership
    $DisabledUsersWithGroupMembership = $DisabledUserObjects | Where-Object { $_.memberof.count -eq 0 }
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Disabled users with group membership" -SectionContents $($DisabledUsersWithGroupMembership | select name,givenname,surname,enabled,whencreated,lastlogondate,distinguishedname)
    
    #summary of computers by OS
    $ComputersByOS = get-adcomputer -filter * -properties operatingsystem -Server $domain| Group-Object operatingsystem | Sort-Object count -descending | Select-Object count, name
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Summary of computers by OS" -SectionContents $ComputersByOS

    #users with admincount = 1
    $UsersWithAdminCount1 = Get-ADUser -filter { admincount -eq 1 } -Server $domain
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Users with admincount = 1" -SectionContents $($UsersWithAdminCount1 | select name,givenname,surname)

    #Find unlinked GPOs
    $UnlinkedGPOs = Get-GPO -All -Domain $domain | Where-Object { $_ | Get-GPOReport -ReportType XML -Domain $domain| Select-String -NotMatch "<LinksTo>" }
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Unlinked GPOs" -SectionContents $($UnlinkedGPOs | select displayname,creationtime,modificationtime,wmifilter)

    #Users without a password required
    $UsersWithoutAPasswordRequired = Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties passwordNotRequired -Server $domain
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Users without a password required (passwordNotRequired = true)" -SectionContents $($UsersWithoutAPasswordRequired | select samaccountname)

    #User objects with PasswordNeverExpires = true that are not in a service accounts OU
    $PwdNeverExpires = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and samaccountname -notlike "HealthMailbox*"} -Properties PasswordNeverExpires -Server $domain | Where{$_.distinguishedName -notlike "*CN=Service Accounts*,$DomainDN"}
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Users with PasswordNeverExpires = true that are not in a service accounts OU" -SectionContents $($PwdNeverExpires | select samaccountname,enabled,name,passwordneverexpires,distinguishedname)

    #Users with a passwordLastSet over 1 year old
    $old = (Get-Date).AddDays(-365)
    $OldUserObjects = Get-ADUser -Filter {passwordLastSet -lt $old -and samaccountname -notlike "HealthMailbox*" -and Enabled -eq $true} -Properties PasswordLastSet -Server $domain
    $HTMLReport += New-HTMLReportSection -SectionTitle "$domain - Enabled User Objects with a password over 1 year old" -SectionContents $($OldUserObjects | select samaccountname,enabled,name,passwordneverexpires,distinguishedname)


} #finished collecting data

#generate a table of contents with links to each item
$HTMLObject = New-Object -ComObject "HTMLFile"
$HTMLObject.write([System.Text.Encoding]::Unicode.GetBytes($HTMLReport))
$AllIDLines = $HTMLObject.all.tags("H2")
$AllIDs = forEach($line in $AllIDLines){
    $start = $line.outerHTML.IndexOf("id=") + 3
    $end = $line.outerHTML.IndexOf(">",$start) - 1
    $end2 = $line.outerHTML.IndexOf("<",$($end+2))
    [pscustomobject]@{
        ID = $line.outerHTML[$start..$end] -join('')
        Title = $line.outerHTML[$($end+2)..$($end2-1)] -join('')
    }
}
$TableOfContents = forEach($ID in $AllIDs){
    '<a href=#' + $($ID.id) + '>' + $($ID.Title) + '</a><br>'
}

$HTMLReportWithTOC = $TableOfContents + $HTMLReport

#output 
If(Test-Path $LogFile){
    Remove-Item $LogFile -Force
}
$HTMLReportWithTOC | Out-File $LogFile -Force



#Send-MailMessage -Attachments $LogFile -BodyAsHtml $Body -Subject $SubjectLine -To $ToAddress -From $FromAddress -SmtpServer $SMTPServer