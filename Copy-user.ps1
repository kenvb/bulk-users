#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
A simple bulk user import script which reads users from a .csv file and imports them into AD, based on a template user. Requires domain admin or delegated rights. Can be run on client with RSAT-tools installed
.DESCRIPTION
A simple bulk user import script which reads users from a .csv file and imports them into AD, based on a template user. Requires domain admin or delegated rights. Can be run on client with RSAT-tools installed
.PARAMETER CSVLocation
location of your .csv with usernames (string)
.PARAMETER password
Provide a password for all your users in the .csv file (string)
.PARAMETER IsDisabled 
Is a switch and doesn't require input. Disables the user account on creation (or more correctly: doesn't enable it) 
.EXAMPLE
./createuser.ps1
Reads users from a file named "users.csv", located in the working directory. It also provides the users with a default password of "Shazzamdepus1234" and ENABLES the account
.EXAMPLE
./createuser.ps1 $CSVLocation c:\scripts\bulkimport.csv -password "Test1234" -IsDisabled
Reads users from a file named "bulkimport.csv", located in the c:\scripts directory. It also provides the users with a custom password of "Test1234" and DISABLES the account
.NOTES
Author: Ken Vanden Branden
#>
#Allows extra parameters to be activated eg: -verbose
[CmdletBinding()]
#Either provide the parameters with values when executing the script or they will use the defaults below.
Param (
        [Parameter(Mandatory=$false, position=0)][string]$CSVlocation = ".\users.csv", # users.csv in same dir as the script
        [Parameter(Mandatory=$false, position=1)][string]$Password = "Vdab1234",
        [Parameter(Mandatory=$true, position=2)][Validateset("PHP","DotNet","ICTSupport","Java","TNI","SysBeheer")][string]$Course,
        [switch]$IsDisabled
        )

if(Test-Path $CSVlocation -PathType Leaf)
{
#Don't change the variables below.
$Domain= Get-ADDomain
$AlreadyExists = $false
$i = 0
$Datum = Get-Date
$Secpass = ConvertTo-SecureString $password -AsPlainText -Force
$Users = Import-Csv $CSVlocation | ForEach-Object {
$i++
        #if($_.Givenname.Length -GT 0 -and $_.surname.Length -GT 0 -and $_.Department.Length -GT 0 -and $_.title.length -GT 0)
        #{
            try
            {
            $CreateTemplate = $Course + "Cursist"
            #Important: specify the properties to be copied.
            $Template = Get-ADUser -Identity $CreateTemplate -Properties office, department, title, physicaldeliveryofficename -ErrorAction Stop

            }
                catch
                {
                $ErrorWarn = $_.exception.message
                Write-Warning $ErrorWarn
                }
            try
            {
            #$_ gets lost between try and catch. Redefining.
            $Erroruser = $_          
            #Copy OU of template account. The regular expression gets rid of unwanted information.
            $ou = $Template.DistinguishedName -replace '^cn=.+?(?!\\),'
            #User account has to be created as disabled
            new-aduser -GivenName $_.GivenName -Surname $_.Surname -Department $_.Department -Title $_.title -Name "$($_.GivenName) $($_.Surname)" -SamAccountName "$($_.GivenName).$($_.Surname)" -UserPrincipalName "$($_.GivenName).$($_.Surname)@$($domain.Forest)" -Instance $($Template) -Path $ou -Description $datum -Enabled:$false -ErrorAction Stop
            Write-Verbose "$($_.GivenName) $($_..Surname) created"
            "$datum : $($_.GivenName) $($_.Surname) created" | Out-File c:\Create-user-log.txt -Append
            }
                catch
                {
                Write-Warning "$($Erroruser.GivenName) $($Erroruser.Surname) Skipping creation: user already exists or OU/rights problem"
                "$($Erroruser.GivenName) $($Erroruser.Surname) Skipping creation: user already exists or OU/rights problem"| Out-File c:\Create-user-errors.txt -Append
                #Set a flag to prevent changing an existing user's password.
                $AlreadyExists = $true
                }
            try
            {
            #Make new account also member of template user's groups.
            get-aduser -Identity $Template -Properties memberof | Select-Object -ExpandProperty memberof | Add-ADGroupMember -Members "$($_.GivenName).$($_.Surname)" -PassThru -ErrorAction stop
            }
                catch
                {
                $ErrorWarn = $_.exception.message
                Write-Warning $ErrorWarn + "Can't get groups from template user"
                }
                #Set users' password. Unless user already exists
                    if (-not($AlreadyExists))
                    {
                    try
                    {
                    Set-ADAccountPassword -Identity "$($_.GivenName).$($_.Surname)" -NewPassword $secpass -Reset
                    Write-Verbose "$($Erroruser.GivenName) $($Erroruser.Surname) password set"
                    }
                        catch
                        {
                        $ErrorWarn = $_.exception.message
                        Write-Warning $ErrorWarn + "Can't set AD PW"
                        }
                Set-ADUser -ChangePasswordAtLogon:$true -Identity "$($_.GivenName).$($_.Surname)" -SmartcardLogonRequired:$false
                }
#Enable users' account unless the Isdisabled switch is used
            if(-Not ($Isdisabled))
            {
            Enable-ADAccount -Identity "$($_.GivenName).$($_.Surname)"
            Write-Verbose "$($Erroruser.GivenName) $($Erroruser.Surname) account enabled"
            }
            Set-ADAccountControl -AccountNotDelegated:$false -AllowReversiblePasswordEncryption:$false -CannotChangePassword:$false -DoesNotRequirePreAuth:$false `
            -Identity "$($_.GivenName).$($_.Surname)" -PasswordNeverExpires:$false -UseDESKeyOnly:$false
            Write-Verbose "$($Erroruser.GivenName) $($Erroruser.Surname) default security values set"
        
        }
        <# else
        {
        Write-warning "Info missing, some or all at line $i : Givenname, surname, department and title are required"
        "Info missing, some or all at line $i : Givenname, surname, department and title are required" | Out-File c:\Create-user-errors.txt -Append
        } #> 
       } 
    #}
else
    {
    "$Datum : $Csvlocation does not exist" | Out-File c:\Create-user-errors.txt -Append
    Write-warning "$Csvlocation does not exist"
    }