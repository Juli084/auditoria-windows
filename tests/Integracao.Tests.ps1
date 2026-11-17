# Execução real, sem dublês. Só roda no Windows.

BeforeDiscovery {
    $noWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
    $elevado = $false
    if ($noWindows) {
        $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
        $elevado = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

Describe 'Execução real no Windows' -Tag 'Windows' -Skip:(-not $noWindows) {
    BeforeAll {
        $raiz = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name (Join-Path -Path $raiz -ChildPath 'AuditoriaWindows/AuditoriaWindows.psd1') -Force
        $auditoria = Invoke-AuditoriaWindows
    }

    It 'avalia as 20 verificações com estados válidos' {
        $auditoria.Verificacoes.Count | Should -Be 20
        foreach ($item in $auditoria.Verificacoes) {
            $item.Estado | Should -BeIn @('OK', 'FALHA', 'NAO_VERIFICADO', 'REQUER_ADMIN')
        }
    }

    It 'lê sem erro o que não depende de serviço opcional: <_>' -ForEach @(
        'CONTA-01', 'CONTA-02', 'CONTA-03', 'CONTA-04', 'CONTA-05', 'CONTA-06', 'CONTA-07', 'CONTA-08',
        'REDE-01', 'REDE-04', 'REDE-05', 'SIS-04', 'LOG-01'
    ) {
        $id = $_
        $item = $auditoria.Verificacoes | Where-Object { $_.Id -eq $id }
        $item.Encontrado | Should -Not -BeLike 'Erro na leitura*'
    }

    It 'como administrador, nenhuma verificação fica pendente de elevação' -Skip:(-not $elevado) {
        $auditoria.Resumo.REQUER_ADMIN | Should -Be 0
    }

    It 'gera JSON e HTML válidos' {
        $arquivos = $auditoria | Export-RelatorioAuditoria -Pasta (Join-Path -Path $TestDrive -ChildPath 'real')
        $lido = [System.IO.File]::ReadAllText($arquivos.Json) | ConvertFrom-Json
        @($lido.Verificacoes).Count | Should -Be 20
        [System.IO.File]::ReadAllText($arquivos.Html) | Should -Match '</html>\s*$'
    }
}
