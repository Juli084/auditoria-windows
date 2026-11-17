BeforeAll {
    $raiz = Split-Path -Path $PSScriptRoot -Parent
    Import-Module -Name (Join-Path -Path $raiz -ChildPath 'AuditoriaWindows/AuditoriaWindows.psd1') -Force

    function New-AuditoriaFicticia {
        $verificacoes = @(
            [pscustomobject]@{
                Id = 'CONTA-05'; Categoria = 'Contas e autenticação'; Titulo = 'UAC ativo'; Severidade = 'alta'
                Estado = 'OK'; Encontrado = 'Ativo'; Esperado = 'EnableLUA = 1'; Motivo = 'm'; Recomendacao = 'r'
                Attack = @('T1548.002'); Referencias = @('https://learn.microsoft.com/')
            }
            [pscustomobject]@{
                Id = 'REDE-04'; Categoria = 'Rede'; Titulo = 'LLMNR & NBT-NS'; Severidade = 'media'
                Estado = 'FALHA'; Encontrado = '<script>alert(1)</script>'; Esperado = 'EnableMulticast = 0'
                Motivo = 'Texto com "aspas" e <b>tags</b>'; Recomendacao = 'r'
                Attack = @('T1557.001'); Referencias = @('https://attack.mitre.org/techniques/T1557/001/')
            }
        )
        [pscustomobject]@{
            Ferramenta = 'auditoria-windows'; Versao = '1.0.0'; GeradoEm = '2026-11-17T13:00:00.0000000Z'
            Computador = 'PC TESTE'; Sistema = [pscustomobject]@{ Nome = 'Windows'; Versao = '10.0'; Build = '19045' }
            ExecutadoComoAdministrador = $false
            Resumo = [pscustomobject]@{ OK = 1; FALHA = 1; NAO_VERIFICADO = 0; REQUER_ADMIN = 0 }
            Verificacoes = $verificacoes
        }
    }
}

Describe 'ConvertTo-HtmlAuditoria' {
    BeforeAll {
        $html = ConvertTo-HtmlAuditoria -Auditoria (New-AuditoriaFicticia)
    }

    It 'codifica todo texto vindo da auditoria' {
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '<b>tags'
        $html | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
        $html | Should -Match ([regex]::Escape('LLMNR &amp; NBT-NS'))
    }

    It 'não carrega scripts nem recursos externos' {
        $html | Should -Match ([regex]::Escape("default-src 'none'"))
        $html | Should -Not -Match '\ssrc='
        $html | Should -Not -Match '<link'
    }

    It 'mostra as falhas antes dos itens OK' {
        $html.IndexOf('REDE-04') | Should -BeLessThan $html.IndexOf('CONTA-05')
    }

    It 'monta o link do ATT&CK a partir do identificador' {
        $html | Should -Match ([regex]::Escape('https://attack.mitre.org/techniques/T1548/002/'))
    }

    It 'mostra a data em UTC' {
        $html | Should -Match '2026-11-17 13:00 UTC'
    }
}

Describe 'Export-RelatorioAuditoria' {
    It 'grava JSON em UTF-8 sem BOM, legível de volta, e o HTML' {
        $arquivos = New-AuditoriaFicticia | Export-RelatorioAuditoria -Pasta (Join-Path -Path $TestDrive -ChildPath 'a')

        Split-Path -Path $arquivos.Json -Leaf | Should -Be 'auditoria-PC_TESTE-20261117T130000Z.json'
        $bytes = [System.IO.File]::ReadAllBytes($arquivos.Json)
        $bytes[0] | Should -Not -Be 0xEF
        $lido = [System.IO.File]::ReadAllText($arquivos.Json) | ConvertFrom-Json
        @($lido.Verificacoes).Count | Should -Be 2
        @($lido.Verificacoes[0].Attack).Count | Should -Be 1
        $arquivos.Html | Should -Exist
    }

    It 'resolve pasta relativa pela pasta atual do PowerShell' {
        Push-Location -Path $TestDrive
        try {
            $arquivos = New-AuditoriaFicticia | Export-RelatorioAuditoria -Pasta 'relativa'
        } finally {
            Pop-Location
        }
        $arquivos.Json | Should -BeLike (Join-Path -Path $TestDrive -ChildPath 'relativa*')
        $arquivos.Json | Should -Exist
    }

    It 'com -SemHtml grava só o JSON' {
        $pasta = Join-Path -Path $TestDrive -ChildPath 'sem-html'
        $arquivos = New-AuditoriaFicticia | Export-RelatorioAuditoria -Pasta $pasta -SemHtml
        $arquivos.Html | Should -BeNullOrEmpty
        @(Get-ChildItem -Path $pasta -Filter '*.html').Count | Should -Be 0
    }

    It 'o HTML pode ser gerado de novo a partir do JSON salvo' {
        $arquivos = New-AuditoriaFicticia | Export-RelatorioAuditoria -Pasta (Join-Path -Path $TestDrive -ChildPath 'b') -SemHtml
        $html = [System.IO.File]::ReadAllText($arquivos.Json) | ConvertFrom-Json | ConvertTo-HtmlAuditoria
        $html | Should -Match 'REDE-04'
        $html | Should -Match '2026-11-17 13:00 UTC'
    }
}
