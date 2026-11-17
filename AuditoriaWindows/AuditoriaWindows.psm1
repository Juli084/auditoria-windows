Set-StrictMode -Version 3.0

foreach ($arquivo in 'Leitura', 'Resultado', 'Verificacoes', 'Auditoria', 'Relatorio') {
    . (Join-Path -Path $PSScriptRoot -ChildPath "Funcoes/$arquivo.ps1")
}

Export-ModuleMember -Function 'Invoke-AuditoriaWindows', 'Export-RelatorioAuditoria', 'ConvertTo-HtmlAuditoria'
