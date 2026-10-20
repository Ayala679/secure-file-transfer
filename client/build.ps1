param(
    [ValidateSet("Debug", "Release")] [string]$Configuration = "Debug",
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1

& $msbuild "$PSScriptRoot\client.sln" /p:Configuration=$Configuration /p:Platform=x64 /v:minimal /nologo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Test) {
    & "$PSScriptRoot\bin\x64\$Configuration\ClientTests.exe"
    exit $LASTEXITCODE
}
