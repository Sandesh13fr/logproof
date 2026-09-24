param(
  [string]$BundleDirectory = (Join-Path $PSScriptRoot "..\dist\offline"),
  [ValidateRange(1, 65535)][int]$WebPort = 3000,
  [ValidateRange(1, 65535)][int]$ApiPort = 8000
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputPath = if ([System.IO.Path]::IsPathRooted($BundleDirectory)) {
  [System.IO.Path]::GetFullPath($BundleDirectory)
} else {
  [System.IO.Path]::GetFullPath((Join-Path $repoRoot $BundleDirectory))
}
if (Test-Path -LiteralPath $outputPath) {
  if ((Get-ChildItem -LiteralPath $outputPath -Force | Measure-Object).Count -gt 0) {
    throw "Bundle output directory is not empty: $outputPath"
  }
} else {
  New-Item -ItemType Directory -Path $outputPath | Out-Null
}

$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCommand) {
  $dockerExe = $dockerCommand.Source
} else {
  $candidate = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe"
  if (-not (Test-Path -LiteralPath $candidate)) { throw "Docker CLI was not found. Install Docker Desktop or add docker.exe to PATH." }
  $dockerExe = $candidate
  $env:PATH = "$(Split-Path $candidate);$env:PATH"
}

function Invoke-Docker([string[]]$Arguments) {
  & $dockerExe @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Docker command failed ($LASTEXITCODE): docker $($Arguments -join ' ')" }
}

$oldWebPort = $env:LOGPROOF_WEB_PORT
$oldApiPort = $env:LOGPROOF_API_PORT
$oldDataDir = $env:LOGPROOF_DATA_DIR
try {
  $env:LOGPROOF_WEB_PORT = "$WebPort"
  $env:LOGPROOF_API_PORT = "$ApiPort"
  $env:LOGPROOF_DATA_DIR = "./data"
  Push-Location $repoRoot
  Invoke-Docker @("compose", "build")

  $imageRefs = @("logproof-prototype-api:local", "logproof-prototype-web:local")
  $archive = Join-Path $outputPath "logproof-images.tar"
  Invoke-Docker (@("save", "--output", $archive) + $imageRefs)
  Copy-Item -LiteralPath (Join-Path $repoRoot "docker-compose.yml") -Destination (Join-Path $outputPath "docker-compose.yml")
  $environmentLines = @(
    "LOGPROOF_WEB_PORT=$WebPort",
    "LOGPROOF_API_PORT=$ApiPort",
    "LOGPROOF_DATA_DIR=./data"
  )
  [System.IO.File]::WriteAllLines((Join-Path $outputPath ".env"), $environmentLines, [System.Text.UTF8Encoding]::new($false))

  $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  $manifest = [ordered]@{
    bundle = "LogProof offline container bundle"
    created_utc = [DateTime]::UtcNow.ToString("o")
    images = $imageRefs
    image_archive = "logproof-images.tar"
    image_archive_bytes = (Get-Item -LiteralPath $archive).Length
    image_archive_sha256 = $hash
    web_port = $WebPort
    api_port = $ApiPort
    data_path = "./data (created beside this bundle on first start)"
    air_gap_start = "docker compose --env-file .env up --no-build --pull never -d"
    notes = "Transfer this folder to the target host. The images include the app, API, parsers, and runtime dependencies. Keep the data folder separate and protected."
  }
  $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputPath "manifest.json") -Encoding utf8
  @(
    "SHA-256  $hash  logproof-images.tar",
    "Verify on the receiving system with Get-FileHash .\logproof-images.tar -Algorithm SHA256"
  ) | Set-Content -LiteralPath (Join-Path $outputPath "SHA256.txt") -Encoding utf8
  @"
LogProof offline container transfer

1. Copy this complete folder to the air-gapped host.
2. Verify logproof-images.tar against SHA256.txt.
3. Load and start without building or pulling:
   docker load --input .\logproof-images.tar
   docker compose --env-file .env up --no-build --pull never -d
4. Open http://127.0.0.1:$WebPort and check http://127.0.0.1:$ApiPort/api/health.
5. Stop with: docker compose --env-file .env down

The persistent ./data folder contains raw events and SQLite receipts. Back it up separately.
"@ | Set-Content -LiteralPath (Join-Path $outputPath "OFFLINE-README.txt") -Encoding utf8
  Write-Output "Offline bundle created: $outputPath"
  Write-Output "Images: $($imageRefs -join ', ')"
  Write-Output "Archive SHA-256: $hash"
} finally {
  if ((Get-Location).Path -eq $repoRoot) { Pop-Location }
  if ($null -eq $oldWebPort) { Remove-Item Env:LOGPROOF_WEB_PORT -ErrorAction SilentlyContinue } else { $env:LOGPROOF_WEB_PORT = $oldWebPort }
  if ($null -eq $oldApiPort) { Remove-Item Env:LOGPROOF_API_PORT -ErrorAction SilentlyContinue } else { $env:LOGPROOF_API_PORT = $oldApiPort }
  if ($null -eq $oldDataDir) { Remove-Item Env:LOGPROOF_DATA_DIR -ErrorAction SilentlyContinue } else { $env:LOGPROOF_DATA_DIR = $oldDataDir }
}
