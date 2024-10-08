# Function to extract the executable path from service PathName
function PathFromServicePathName($pathName) {
  # input can have quotes, spaces, and args like any of these:
  #   C:\WINDOWS\system32\lsass.exe
  #   "C:\Program Files\Realtek\Audio\HDA\RtkAudioService64.exe"
  #   C:\WINDOWS\system32\svchost.exe -k netsvcs -p
  #   "C:\Program Files\Websense\Websense Endpoint\wepsvc.exe" -k ss

  # if it starts with quote, return what's between first and second quotes
  if ($pathName.StartsWith("`"")) {
    $pathName = $pathName.Substring(1)
    $index = $pathName.IndexOf("`"")
    if ($index -gt -1) {
      return $pathName.Substring(0, $index)
    }
    else {
      # this should never happen... but whatever, return something
      return $pathName
    }
  }
  
  # else if it contains spaces, return what's before the first space
  if ($pathName.Contains(" ")) {
    $index = $pathName.IndexOf(" ")
    return $pathName.Substring(0, $index)
  }
  
  # else it's a simple path
  return $pathName
}


# Function to check service permissions
function Get-ServiceRegPermissions {
    param (
        [string]$ServiceName,
        [string]$servicepathp
    )

    $results = @()
    try {
        $sd = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        foreach ($access in $sd.Access) 
        {
            # write-host "Access identity is " $access.IdentityReference 
            # write-host "Access permissions are " $access.RegistryRights

            if (($access.IdentityReference -ne "BUILTIN\Administrators" -and $access.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $access.IdentityReference -ne "NT SERVICE\Dhcp" -and $access.IdentityReference -ne "CREATOR OWNER" -and $access.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"  -and $access.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES" -and $access.IdentityReference -ne "NT SERVICE\TrustedInstaller" -and $access.IdentityReference -ne "NT SERVICE\SecurityHealthService" -and $access.IdentityReference -ne "NT SERVICE\autotimesvc")) 
            {   
                
                if ($access.RegistryRights -match "WriteKey|FullControl|SetValue|CreateSubKey|ChangePermissions") {
                    $results += [pscustomobject]@{
                        ServiceName = $ServiceName
                        Identity    = $access.IdentityReference
                        Access      = $access.RegistryRights
                    }
                    #write-host "Access identity is " $access.IdentityReference 
                    #write-host "Access permissions are " $access.RegistryRights
                }
            }
        }
    }
    catch {
        Write-Output "Failed to query permissions for service $ServiceName $_"
    }

    return $results
}

# Function to check file and folder permissions
function Get-FileAndFolderPermissions {
    param (
        [string]$ServiceName,
        [string]$servicepathp
    )

    $executablePath = PathFromServicePathName -pathName $servicepathp
    #write-host "The clean folder path is " $executablePath

    $folderPath = Split-Path $executablePath
    #write-host "The further split folder path is now " $folderPath

    $fileIssues = @()
    $folderIssues = @()

    if (Test-Path $executablePath) {
        try {
            $fileAcl = Get-Acl $executablePath
            foreach ($access in $fileAcl.Access) {

            # write-host "The folder identity is " $access.IdentityReference
            # write-host "The folder rights are " $access.FileSystemRights

                if (($access.IdentityReference -ne "BUILTIN\Administrators" -and $access.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $access.IdentityReference -ne "NT SERVICE\Dhcp" -and $access.IdentityReference -ne "CREATOR OWNER" -and $access.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and $access.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES" -and $access.IdentityReference -ne "NT SERVICE\TrustedInstaller" -and $access.IdentityReference -ne "NT SERVICE\SecurityHealthService" -and $access.IdentityReference -ne "NT SERVICE\autotimesvc"))  
                {
                   # write-host "The folder identity is " $access.IdentityReference
                   # write-host "The folder rights are " $access.FileSystemRights
                    if ($access.FileSystemRights -match "Write|FullControl") {
                        $fileIssues += [pscustomobject]@{
                            ServiceName = $ServiceName
                            PathType    = "Executable"
                            Path        = $executablePath
                            Identity    = $access.IdentityReference
                            Access      = $access.FileSystemRights
                        }
                    }
                }
            }
        }
        catch {
            Write-Output "Failed to get ACL for file: $executablePath - $_"
        }
    }

    if (Test-Path $folderPath) {
        try {
            $folderAcl = Get-Acl $folderPath
            foreach ($access in $folderAcl.Access) {
                if (($access.IdentityReference -ne "BUILTIN\Administrators" -and $access.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $access.IdentityReference -ne "NT SERVICE\Dhcp" -and $access.IdentityReference -ne "CREATOR OWNER" -and $access.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and $access.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES" -and $access.IdentityReference -ne "NT SERVICE\TrustedInstaller" -and $access.IdentityReference -ne "NT SERVICE\SecurityHealthService" -and $access.IdentityReference -ne "NT SERVICE\autotimesvc"))  
                {
                    if ($access.FileSystemRights -match "Write|FullControl") {
                        $folderIssues += [pscustomobject]@{
                            ServiceName = $ServiceName
                            PathType    = "Folder"
                            Path        = $folderPath
                            Identity    = $access.IdentityReference
                            Access      = $access.FileSystemRights
                        }
                    }
                }
            }
        }
        catch {
            Write-Output "Failed to get ACL for folder: $folderPath - $_"
        }
    }

    return $fileIssues + $folderIssues
}

# Main script logic
$allServices = Get-Service | Select-Object -ExpandProperty Name
$results = @()

foreach ($serviceName in $allServices) {
    $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    if ($serviceInfo) {
        $binaryPathName = $serviceInfo.PathName
        # write-host "Binary Path in Main Logic is" $binaryPathName
        $permissions = Get-ServiceRegPermissions -ServiceName $serviceName -servicepathp $binaryPathName
       
        if ($permissions) {
            $results += $permissions
        }

        $fileFolderIssues = Get-FileAndFolderPermissions -ServiceName $serviceName -servicepathp $binaryPathName
        if ($fileFolderIssues) {
            $results += $fileFolderIssues
            
        }
    }
}

# Logging
$logPath = "c:\Logs\WeakServicePermissions.txt" # Change this to your network share location
if (-not (Test-Path $logPath)) {
    $logPath = "C:\Logs\WeakServicePermissions.txt"
}

# Create directory if it doesn't exist
$logDirectory = Split-Path $logPath
if (-not (Test-Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory -Force
}

# Export results to log
if ($results.Count -gt 0) {
    $results | Out-File -FilePath $logPath -Append -Encoding UTF8
} else {
    "No weak permissions found on services." | Out-File -FilePath $logPath -Append -Encoding UTF8
}
