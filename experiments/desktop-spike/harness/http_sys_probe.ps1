param(
  [Parameter(Mandatory = $true)][string]$Out,
  [Parameter(Mandatory = $true)][string]$StopFile,
  [Parameter(Mandatory = $true)][string]$ReadyFile,
  [int]$Duration = 400
)

$listener = New-Object System.Net.HttpListener
foreach ($prefix in @("http://tauri.localhost:80/", "http://ipc.localhost:80/", "http://localhost:80/")) {
  $listener.Prefixes.Add($prefix)
}
$result = [ordered]@{ prefixes = @($listener.Prefixes); started = $false; requests = @() }
try {
  $listener.Start()
  $result.started = $true
} catch {
  $result.error = $_.Exception.Message
}
Set-Content -Path $ReadyFile -Value "ready"

$deadline = (Get-Date).AddSeconds($Duration)
while ($result.started -and (Get-Date) -lt $deadline -and -not (Test-Path $StopFile)) {
  $task = $listener.GetContextAsync()
  while (-not $task.Wait(500)) {
    if ((Get-Date) -gt $deadline -or (Test-Path $StopFile)) { break }
  }
  if (-not $task.IsCompleted) { break }
  $context = $task.Result
  $buffer = New-Object System.IO.MemoryStream
  $context.Request.InputStream.CopyTo($buffer)
  $bytes = $buffer.ToArray()
  $text = [System.Text.Encoding]::Latin1.GetString($bytes) + $context.Request.Url.ToString()
  $result.requests += [ordered]@{
    url = $context.Request.Url.ToString()
    method = $context.Request.HttpMethod
    body_bytes = $bytes.Length
    master_password = $text.Contains("Canary-Master-7Qx-ciphermoth")
    attachment_canary = $text.Contains("CANARY-ATTACHMENT-91c4")
  }
  $context.Response.StatusCode = 404
  $context.Response.Close()
}
if ($result.started) { $listener.Stop() }
$result | ConvertTo-Json -Depth 5 | Out-File -FilePath $Out -Encoding utf8
