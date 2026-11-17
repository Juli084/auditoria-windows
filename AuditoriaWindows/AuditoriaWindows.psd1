@{
    RootModule           = 'AuditoriaWindows.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '42bf409d-e9ee-4192-908c-d67bad7753f7'
    Author               = 'Juli084'
    Copyright            = '(c) 2026 Juli084. Licença MIT.'
    Description          = 'Auditoria somente leitura da configuração de segurança de computadores Windows, com relatório em JSON e HTML.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-AuditoriaWindows', 'Export-RelatorioAuditoria', 'ConvertTo-HtmlAuditoria')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags = @('Windows', 'Security', 'Audit', 'Hardening')
        }
    }
}
