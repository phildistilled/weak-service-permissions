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

Get-WmiObject win32_service | select Name, DisplayName, @{Name="Path"; Expression={PathFromServicePathName $_.PathName}} | Format-List
