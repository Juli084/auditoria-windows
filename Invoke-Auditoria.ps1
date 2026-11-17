<#
.SYNOPSIS
Audita a configuração de segurança deste computador Windows, sem alterar nada.

.DESCRIPTION
Executa as verificações do módulo AuditoriaWindows, mostra o resultado na tela
e grava os relatórios em JSON e HTML. Sem privilégio de administrador, as
verificações que dependem dele aparecem como "requer administrador".

.PARAMETER Pasta
Pasta onde os relatórios são gravados. O padrão é a pasta "relatorios" ao lado
deste script.

.PARAMETER SemHtml
Grava só o JSON.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Auditoria.ps1

.EXAMPLE
.\Invoke-Auditoria.ps1 -Pasta C:\Auditorias -SemHtml
#>
[CmdletBinding()]
param(
    [string] $Pasta = (Join-Path -Path $PSScriptRoot -ChildPath 'relatorios'),
    [switch] $SemHtml
)

$ErrorActionPreference = 'Stop'
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'AuditoriaWindows/AuditoriaWindows.psd1') -Force

$auditoria = Invoke-AuditoriaWindows
$arquivos = $auditoria | Export-RelatorioAuditoria -Pasta $Pasta -SemHtml:$SemHtml

$ordem = @{ FALHA = 0; REQUER_ADMIN = 1; NAO_VERIFICADO = 2; OK = 3 }
$auditoria.Verificacoes |
    Sort-Object -Property @{ Expression = { $ordem[$_.Estado] } }, Id |
    Format-Table -Property Id, Estado, Severidade, Titulo, Encontrado -AutoSize -Wrap |
    Out-String -Width 200

$resumo = $auditoria.Resumo
'Falhas: {0} | Requer administrador: {1} | Não verificado: {2} | OK: {3}' -f $resumo.FALHA, $resumo.REQUER_ADMIN, $resumo.NAO_VERIFICADO, $resumo.OK
'JSON: {0}' -f $arquivos.Json
if ($arquivos.Html) {
    'HTML: {0}' -f $arquivos.Html
}
if ($resumo.REQUER_ADMIN -gt 0) {
    Write-Warning 'Execute num PowerShell aberto como administrador para ler todas as verificações.'
}
