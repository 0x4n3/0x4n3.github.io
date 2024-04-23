$outputdir = 'D:\Geoff Chappell\msvc'
$url       = 'https://www.geoffchappell.com/studies/msvc/toc.htm'

# enable TLS 1.2 and TLS 1.1 protocols
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11

$WebResponse = Invoke-WebRequest -Uri $url
# get the list of links, skip the first one ("../") and download the files
$WebResponse.Links | Select-Object -ExpandProperty href -Skip 1 | ForEach-Object {
    Write-Host "Downloading file '$_'"
    $filePath = Join-Path -Path $outputdir -ChildPath $_
    $fileName = $filePath.split('\')[-1] 
    $dirPath = $filePath -replace $fileName
    $dirPath = $dirPath.Replace('$','_dollarsign_')
    New-Item -ItemType "directory" -Path $dirPath
    $fileUrl  = 'https://www.geoffchappell.com/studies/msvc/{1}' -f $url.TrimEnd('/'), $_
    Write-Output $fileUrl
    Invoke-WebRequest -Uri $fileUrl -OutFile $filePath
    Start-Sleep -Seconds 1
}