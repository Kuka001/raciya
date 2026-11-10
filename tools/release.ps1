# Выпуск новой версии: сборка, тег, выпуск на GitHub и файл Raciya-Setup.exe.
# После этого у всех участников в окне программы появится «Новое обновление!».
#
#   1. Поднимите version в client\Cargo.toml и закоммитьте изменения.
#   2. .\tools\release.ps1 -Notes "Что изменилось"
#
# Вход в GitHub берётся из сохранённых данных Git (Диспетчер учётных данных Windows).
param(
    [string]$Notes = '',
    [string]$Repo = 'Kuka001/raciya',
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:ProgramFiles\CMake\bin;" + $env:Path

$version = (Select-String -Path "$root\client\Cargo.toml" -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$tag = "v$version"
"version: $version"

if (-not $SkipBuild) {
    Push-Location "$root\client"
    cargo test
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'tests failed' }
    cargo build --release
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'build failed' }
    Pop-Location
}
New-Item -ItemType Directory -Force "$root\dist" | Out-Null
$asset = "$root\dist\Raciya-Setup.exe"
Copy-Item "$root\client\target\release\raciya.exe" $asset -Force
$built = (Get-Item $asset).VersionInfo.FileVersion
"built file version: $built"
if ($built -notlike "$version*") { throw "the built file is version $built, expected $version - rebuild without -SkipBuild" }

Push-Location $root
if (git status --porcelain) { Pop-Location; throw 'there are uncommitted changes - commit them first' }
if (-not (git tag --list $tag)) { git tag $tag }
git push origin HEAD
git push origin $tag
Pop-Location

# Токен из сохранённых данных Git; на экран не выводится.
# Запрос передаётся через файл: PowerShell при передаче по конвейеру меняет переводы строк,
# и Git перестаёт узнавать адрес.
$query = Join-Path $env:TEMP "raciya-cred-$PID.txt"
[IO.File]::WriteAllText($query, "protocol=https`nhost=github.com`n`n", (New-Object Text.ASCIIEncoding))
$env:GIT_TERMINAL_PROMPT = '0'
$cred = cmd /c "git credential fill < `"$query`" 2>nul"
Remove-Item $query -ErrorAction SilentlyContinue
$token = (($cred | Where-Object { $_ -like 'password=*' }) -replace '^password=', '')
if (-not $token) { throw 'no saved GitHub login found (git credential fill returned nothing)' }
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json'; 'User-Agent' = 'raciya-release' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$release = $null
try { $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/tags/$tag" -Headers $headers } catch { }
if (-not $release) {
    $body = @{ tag_name = $tag; name = "Raciya $version"; body = $Notes } | ConvertTo-Json
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases" -Method Post -Headers $headers `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
}
foreach ($a in $release.assets) {
    if ($a.name -eq 'Raciya-Setup.exe') {
        Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/assets/$($a.id)" -Method Delete -Headers $headers | Out-Null
    }
}
$upload = "https://uploads.github.com/repos/$Repo/releases/$($release.id)/assets?name=Raciya-Setup.exe"
$r = Invoke-RestMethod $upload -Method Post -Headers $headers -ContentType 'application/octet-stream' -InFile $asset
"uploaded: $($r.name), $([math]::Round($r.size / 1MB, 2)) MB"
"release: $($release.html_url)"
