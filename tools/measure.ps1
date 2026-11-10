# Замер нагрузки процессов: средний CPU и память за указанное время.
#   .\tools\measure.ps1 -Ids 1234,5678 -Seconds 30 -Label "idle"
# CPU показывается в двух видах: в процентах одного ядра и в процентах всего процессора
# (как в Диспетчере задач).
param(
    [Parameter(Mandatory = $true)][int[]]$Ids,
    [int]$Seconds = 30,
    [string]$Label = ''
)
$cores = [Environment]::ProcessorCount
$start = @{}
foreach ($id in $Ids) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($p) { $start[$id] = $p.TotalProcessorTime.TotalMilliseconds }
}
$sw = [Diagnostics.Stopwatch]::StartNew()
$peak = @{}
while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
    Start-Sleep -Milliseconds 1000
    foreach ($id in $Ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p) {
            $ws = $p.WorkingSet64 / 1MB
            if (-not $peak.ContainsKey($id) -or $ws -gt $peak[$id]) { $peak[$id] = $ws }
        }
    }
}
$elapsed = $sw.Elapsed.TotalMilliseconds
foreach ($id in $Ids) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $p -or -not $start.ContainsKey($id)) { "$Label pid=$id : process not found"; continue }
    $cpuMs = $p.TotalProcessorTime.TotalMilliseconds - $start[$id]
    $oneCore = 100.0 * $cpuMs / $elapsed
    "{0} {1} pid={2}: CPU {3:N2}% of one core = {4:N3}% of whole CPU ({5} threads) | RAM working set {6:N1} MB (peak {7:N1}), private {8:N1} MB | priority {9}" -f `
        $Label, $p.ProcessName, $id, $oneCore, ($oneCore / $cores), $cores, ($p.WorkingSet64 / 1MB), $peak[$id], ($p.PrivateMemorySize64 / 1MB), $p.PriorityClass
}
