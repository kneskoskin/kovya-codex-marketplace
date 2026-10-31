[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$PipeName,
  [Parameter(Mandatory = $true)][string]$ExpectedOwnerSidHash
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$pipeMatch = [regex]::Match($PipeName, '^\\\\\.\\pipe\\(?<leaf>[A-Za-z0-9._-]{16,120})$')
if (-not $pipeMatch.Success -or $ExpectedOwnerSidHash -notmatch '^[a-f0-9]{64}$') { throw "pipe_acl_input_refused" }
$pipeLeaf = $pipeMatch.Groups['leaf'].Value

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ownerSid = [Security.Principal.SecurityIdentifier]::new($currentSid)
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$pipeRights = [IO.Pipes.PipeAccessRights]::ReadWrite -bor
  [IO.Pipes.PipeAccessRights]::ReadPermissions -bor
  [IO.Pipes.PipeAccessRights]::ChangePermissions
$pipe = [IO.Pipes.NamedPipeClientStream]::new(
  '.', $pipeLeaf, $pipeRights, [IO.Pipes.PipeOptions]::None,
  [Security.Principal.TokenImpersonationLevel]::Identification,
  [IO.HandleInheritability]::None
)
try {
  $pipe.Connect(500)
  $restricted = [IO.Pipes.PipeSecurity]::new()
  $restricted.SetAccessRuleProtection($true, $false)
  foreach ($principal in @($ownerSid, $systemSid, $administratorsSid)) {
    [void]$restricted.AddAccessRule([IO.Pipes.PipeAccessRule]::new(
      $principal, [IO.Pipes.PipeAccessRights]::FullControl,
      [Security.AccessControl.AccessControlType]::Allow
    ))
  }
  $pipe.SetAccessControl($restricted)
  $verified = $pipe.GetAccessControl()
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $sidHash = ([BitConverter]::ToString(
      $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($currentSid))
    )).Replace('-', '').ToLowerInvariant()
  } finally { $sha.Dispose() }
  if ($sidHash -ne $ExpectedOwnerSidHash -or $verified.GetOwner(
      [Security.Principal.SecurityIdentifier]
    ).Value -ne $currentSid) { throw "pipe_acl_owner_refused" }
  $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  [void]$allowed.Add($currentSid)
  [void]$allowed.Add("S-1-5-18")
  [void]$allowed.Add("S-1-5-32-544")
  foreach ($rule in $verified.GetAccessRules(
      $true, $false, [Security.Principal.SecurityIdentifier]
    )) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        -not $allowed.Contains($rule.IdentityReference.Value)) { throw "pipe_acl_principal_refused" }
  }
  [ordered]@{ ok = $true; owner_sid_hash = $sidHash } | ConvertTo-Json -Compress
} finally {
  $pipe.Dispose()
}
