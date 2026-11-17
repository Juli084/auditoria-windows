@{
    Severity = @('Error', 'Warning')
    Rules    = @{
        # O mesmo código precisa rodar no Windows PowerShell 5.1 e no PowerShell 7.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
