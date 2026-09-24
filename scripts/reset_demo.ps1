$ErrorActionPreference = 'Stop'
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/simulator/scenario/reset' | Out-Null
Write-Host 'LogProof demo reset with five baseline events.'
