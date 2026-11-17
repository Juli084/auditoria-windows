Set-StrictMode -Version 3.0

foreach ($arquivo in 'Leitura', 'Resultado', 'Verificacoes', 'Auditoria') {
    . (Join-Path -Path $PSScriptRoot -ChildPath "Funcoes/$arquivo.ps1")
}

Export-ModuleMember -Function 'Invoke-AuditoriaWindows'
