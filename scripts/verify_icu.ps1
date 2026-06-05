param (
    [string]$ChecksumFile,
    [string]$ArtifactDir,
    [string]$MappingFile
)

function Get-FileSHA512($file) {
    $sha = [System.Security.Cryptography.SHA512]::Create()
    $stream = [System.IO.File]::OpenRead($file)
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLower()
    }
    finally {
        $stream.Close()
    }
}

# --- Load checksum map ---
$checksumMap = @{}

Get-Content $ChecksumFile | ForEach-Object {
    if ($_ -match '^([a-fA-F0-9]{128})\s+\*?(.+)$') {
        $checksumMap[$matches[2]] = $matches[1].ToLower()
    }
}

# --- Load filename mapping ---
$localMap = @{}

Get-Content $MappingFile | ForEach-Object {
    if ($_ -match '(.+?)=(.+)') {
        $localMap[$matches[1]] = $matches[2]
    }
}

foreach ($canonical in $localMap.Keys) {

    $localFile = $localMap[$canonical]
    $fullPath = Join-Path $ArtifactDir $localFile

    if (!(Test-Path $fullPath)) {
        throw "Missing file: $fullPath"
    }

    if (-not $checksumMap.ContainsKey($canonical)) {
        throw "No checksum entry for: $canonical"
    }

    $expected = $checksumMap[$canonical]
    $actual = Get-FileSHA512 $fullPath

    Write-Host "Checking $canonical -> $localFile"

    if ($expected -ne $actual) {
        throw "SHA512 mismatch: $canonical"
    }

    Write-Host "OK: $canonical"
}

Write-Host "All ICU artifacts verified successfully."
