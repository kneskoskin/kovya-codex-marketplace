$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$windows = $desktop = $view = $application = $inputStream = $null
$dispatchStarted = $false
$accepted = $false
try {
    # Read a single bounded UTF-8 value, never command text or an environment value.
    $inputStream = [Console]::OpenStandardInput()
    $bytes = [byte[]]::new(8193)
    $count = 0
    while ($count -lt $bytes.Length) {
        $read = $inputStream.Read($bytes, $count, $bytes.Length - $count)
        if ($read -eq 0) { break }
        $count += $read
    }
    if ($count -lt 1 -or $count -gt 8192) { throw 'input_refused' }
    $url = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $count)
    if ($url.IndexOfAny([char[]]@(0, 10, 13)) -ge 0) { throw 'input_refused' }
    $uri = $null
    if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or $uri.UserInfo -ne '' -or $uri.Fragment -ne '' -or
        $uri.AbsolutePath -cne '/device-authorization') { throw 'url_refused' }
    $transactionCount = 0
    $attemptCount = 0
    foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
        $parts = $pair.Split('=', 2)
        if ($parts.Length -ne 2) { throw 'url_refused' }
        $key = [Uri]::UnescapeDataString($parts[0])
        $value = [Uri]::UnescapeDataString($parts[1])
        if ($key -ceq 'transaction' -and $value -cmatch '^kbat_[A-Za-z0-9_-]{43}\z') { $transactionCount++ }
        elseif ($key -ceq 'attempt' -and $value -cmatch '^[a-f0-9]{160}\z') { $attemptCount++ }
        else { throw 'url_refused' }
    }
    if ($transactionCount -ne 1 -or $attemptCount -gt 1) { throw 'url_refused' }
    # Resolve the existing desktop only. No enumeration or direct-launch fallback.
    $windows = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39'))
    $location = [object][int]0
    $reserved = $null
    $desktopHwnd = [int]0
    $desktop = $windows.FindWindowSW([ref]$location, [ref]$reserved, 8, [ref]$desktopHwnd, 1)
    if ($null -eq $desktop -or $desktopHwnd -eq 0) { throw 'desktop_absent' }
    $view = $desktop.Document
    $application = $view.Application
    if ($null -eq $application -or $null -eq $application.PSObject.Methods['ShellExecute']) { throw 'desktop_absent' }
    # This object resides in Explorer. Explorer owns browser environment/lifetime.
    $dispatchStarted = $true
    $null = $application.ShellExecute($url, '', '', 'open', 1)
    $accepted = $true
} catch {
    # Do not print COM errors, input, URLs, environment values or exception text.
} finally {
    foreach ($value in @($application, $view, $desktop, $windows)) {
        try {
            if ($null -ne $value -and [Runtime.InteropServices.Marshal]::IsComObject($value)) {
                $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($value)
            }
        } catch { $accepted = $false }
    }
    try { if ($null -ne $inputStream) { $inputStream.Dispose() } } catch { $accepted = $false }
    if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    $url = $null
}
if ($accepted) { [Console]::Out.WriteLine('{"ok":true,"dispatch":"accepted"}'); exit 0 }
if ($dispatchStarted) { [Console]::Out.WriteLine('{"ok":false,"dispatch":"unknown"}'); exit 1 }
[Console]::Out.WriteLine('{"ok":false,"dispatch":"refused"}')
exit 1
