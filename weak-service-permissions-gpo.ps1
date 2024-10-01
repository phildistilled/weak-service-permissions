# Proof of concept code - draft - not ready for production

# Function to extract the executable path from service PathName
function PathFromServicePathName($pathName) {
    if ($pathName.StartsWith('"')) {
        $pathName = $pathName.Substring(1)
        $index = $pathName.IndexOf('"')
        if ($index -gt -1) {
            return $pathName.Substring(0, $index)
        }
        else {
            return $pathName
        }
    }
    
    if ($pathName.Contains(" ")) {
        $index = $pathName.IndexOf(" ")
        return $pathName.Substring(0, $index)
    }
    
    return $pathName
}

# Function to check service permissions
function Get-ServicePermissions {
    param (
        [string]$ServiceName,
        [string]$servicepathp
    )

    $results = @()
    try {
        $sd = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        foreach ($access in $sd.Access) {
            if ($access.IdentityReference -match "Authenticated Users|Everyone" -or $access.IdentityReference -match "User") {
                if ($access.RegistryRights -match "WriteKey|FullControl") {
                    $results += [pscustomobject]@{
                        ServiceName = $ServiceName
                        Identity    = $access.IdentityReference
                        Access      = $access.RegistryRights
                    }
                }
            }
        }
    }
    catch {
        Write-Output "Failed to query permissions for service $ServiceName: $_"
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
    $folderPath = Split-Path $executablePath

    $fileIssues = @()
    $folderIssues = @()

    if (Test-Path $executablePath) {
        try {
            $fileAcl = Get-Acl $executablePath
            foreach ($access in $fileAcl.Access) {
                if ($access.IdentityReference -match "Authenticated Users|Everyone" -or $access.IdentityReference -match "User") {
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
                if ($access.IdentityReference -match "Authenticated Users|Everyone" -or $access.IdentityReference -match "User") {
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
        $permissions = Get-ServicePermissions -ServiceName $serviceName -servicepathp $binaryPathName
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
$logPath = "\\NetworkShare\Logs\WeakServicePermissions.txt" # Change this to your network share location
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
