# Invoke-AuditoriaWindows com todas as leituras substituídas por um computador
# fictício bem configurado. Cada teste muda só o que precisa.

BeforeAll {
    $raiz = Split-Path -Path $PSScriptRoot -Parent
    Import-Module -Name (Join-Path -Path $raiz -ChildPath 'AuditoriaWindows/AuditoriaWindows.psd1') -Force

    $script:registroConfigurado = @{
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA'                     = 1
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorAdmin'    = 2
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs'         = 600
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient|EnableMulticast'                        = 0
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections'                     = 1
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging' = 1
    }
}

Describe 'Invoke-AuditoriaWindows' {
    BeforeEach {
        Mock -ModuleName AuditoriaWindows Test-Administrador { $true }
        Mock -ModuleName AuditoriaWindows Get-DataAtual { [datetime]::new(2026, 11, 17, 13, 0, 0, [DateTimeKind]::Utc) }
        Mock -ModuleName AuditoriaWindows Get-InformacaoSistema { [pscustomobject]@{ Nome = 'Windows de teste'; Versao = '10.0.26100'; Build = '26100' } }
        Mock -ModuleName AuditoriaWindows Get-ValorRegistro { $script:registroConfigurado["$Caminho|$Nome"] }
        Mock -ModuleName AuditoriaWindows Get-ContaInterna { [pscustomobject]@{ Nome = "conta $Rid"; Ativa = $false } }
        Mock -ModuleName AuditoriaWindows Get-PoliticaContaLocal { [pscustomobject]@{ ComprimentoMinimoSenha = 12; LimiteBloqueio = 10 } }
        Mock -ModuleName AuditoriaWindows Get-PerfilFirewall {
            foreach ($nome in 'Domain', 'Private', 'Public') { [pscustomobject]@{ Nome = $nome; Ativo = $true } }
        }
        Mock -ModuleName AuditoriaWindows Get-ConfiguracaoSmbServidor { [pscustomobject]@{ Smb1Ativo = $false; AssinaturaExigida = $true } }
        Mock -ModuleName AuditoriaWindows Get-ProtecaoBitLocker { [pscustomobject]@{ Unidade = 'C:'; Protegido = $true; Situacao = 'FullyEncrypted' } }
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = 'Normal'; TempoReal = $true; IdadeAssinaturaDias = 0 } }
        Mock -ModuleName AuditoriaWindows Get-UltimaAtualizacao { [pscustomobject]@{ Id = 'KB5000001'; Data = [datetime]'2026-11-11' } }
        Mock -ModuleName AuditoriaWindows Get-EstadoRecursoOpcional { $null }
        Mock -ModuleName AuditoriaWindows Get-TamanhoLogEvento { [long]256MB }
    }

    It 'num computador bem configurado, as 20 verificações passam' {
        $auditoria = Invoke-AuditoriaWindows
        $falhas = @($auditoria.Verificacoes | Where-Object { $_.Estado -ne 'OK' } | ForEach-Object { '{0}: {1}' -f $_.Id, $_.Encontrado })
        $falhas | Should -BeNullOrEmpty
        $auditoria.Resumo.OK | Should -Be 20
    }

    It 'registra data em UTC, versão do módulo e dados do sistema' {
        $auditoria = Invoke-AuditoriaWindows
        $auditoria.GeradoEm | Should -Be '2026-11-17T13:00:00.0000000Z'
        $auditoria.Versao | Should -Be '1.0.0'
        $auditoria.Sistema.Build | Should -Be '26100'
        $auditoria.ExecutadoComoAdministrador | Should -BeTrue
    }

    It 'sem administrador, não executa as leituras que exigem elevação' {
        Mock -ModuleName AuditoriaWindows Test-Administrador { $false }
        $auditoria = Invoke-AuditoriaWindows

        $pendentes = @($auditoria.Verificacoes | Where-Object { $_.Estado -eq 'REQUER_ADMIN' })
        $pendentes.Id | Should -Be @('SIS-01', 'SIS-05', 'LOG-02')
        $auditoria.Resumo.REQUER_ADMIN | Should -Be 3
        $auditoria.ExecutadoComoAdministrador | Should -BeFalse
        Should -Invoke -ModuleName AuditoriaWindows Get-ProtecaoBitLocker -Times 0 -Exactly
        Should -Invoke -ModuleName AuditoriaWindows Get-EstadoRecursoOpcional -Times 0 -Exactly
        Should -Invoke -ModuleName AuditoriaWindows Get-TamanhoLogEvento -Times 0 -Exactly
    }

    It 'um erro de leitura vira NAO_VERIFICADO sem interromper as outras verificações' {
        Mock -ModuleName AuditoriaWindows Get-PerfilFirewall { throw 'Acesso negado' }
        $auditoria = Invoke-AuditoriaWindows

        $firewall = $auditoria.Verificacoes | Where-Object { $_.Id -eq 'REDE-01' }
        $firewall.Estado | Should -Be 'NAO_VERIFICADO'
        $firewall.Encontrado | Should -Be 'Erro na leitura: Acesso negado'
        $auditoria.Verificacoes.Count | Should -Be 20
        $auditoria.Resumo.OK | Should -Be 19
    }

    It 'continua quando não consegue identificar o sistema' {
        Mock -ModuleName AuditoriaWindows Get-InformacaoSistema { throw 'CIM indisponível' }
        $auditoria = Invoke-AuditoriaWindows
        $auditoria.Sistema | Should -BeNullOrEmpty
        $auditoria.Verificacoes.Count | Should -Be 20
    }

    It 'o resumo soma o total de verificações' {
        Mock -ModuleName AuditoriaWindows Test-Administrador { $false }
        Mock -ModuleName AuditoriaWindows Get-PoliticaContaLocal { [pscustomobject]@{ ComprimentoMinimoSenha = 0; LimiteBloqueio = 0 } }
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { $null }
        $auditoria = Invoke-AuditoriaWindows
        $r = $auditoria.Resumo
        ($r.OK + $r.FALHA + $r.NAO_VERIFICADO + $r.REQUER_ADMIN) | Should -Be $auditoria.Verificacoes.Count
        $r.FALHA | Should -Be 2
        $r.NAO_VERIFICADO | Should -Be 2
    }
}
