# Cada verificação contra dublês das funções de leitura: pelo menos um caso
# que passa e um que falha, mais os valores ausentes e os limites.

BeforeDiscovery {
    $modulo = Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'AuditoriaWindows/AuditoriaWindows.psd1') -Force -PassThru
    $definicoes = & $modulo { Get-DefinicaoVerificacao }

    $sistema ='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $dns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $tsPolitica = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $scriptBlock = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

    $casosRegistro = @(
        @{ Id = 'CONTA-05'; Caso = 'UAC ativo'; Registro = @{ "$sistema|EnableLUA" = 1 }; Estado = 'OK' }
        @{ Id = 'CONTA-05'; Caso = 'UAC desativado'; Registro = @{ "$sistema|EnableLUA" = 0 }; Estado = 'FALHA' }
        @{ Id = 'CONTA-05'; Caso = 'valor ausente segue o padrão do Windows'; Registro = @{}; Estado = 'OK' }
        @{ Id = 'CONTA-06'; Caso = 'padrão 5'; Registro = @{ "$sistema|ConsentPromptBehaviorAdmin" = 5 }; Estado = 'OK' }
        @{ Id = 'CONTA-06'; Caso = 'consentimento na área de trabalho segura'; Registro = @{ "$sistema|ConsentPromptBehaviorAdmin" = 2 }; Estado = 'OK' }
        @{ Id = 'CONTA-06'; Caso = 'eleva sem perguntar'; Registro = @{ "$sistema|ConsentPromptBehaviorAdmin" = 0 }; Estado = 'FALHA' }
        @{ Id = 'CONTA-06'; Caso = 'valor ausente segue o padrão do Windows'; Registro = @{}; Estado = 'OK' }
        @{ Id = 'CONTA-07'; Caso = 'não configurado'; Registro = @{}; Estado = 'OK' }
        @{ Id = 'CONTA-07'; Caso = 'UseLogonCredential = 0'; Registro = @{ "$wdigest|UseLogonCredential" = 0 }; Estado = 'OK' }
        @{ Id = 'CONTA-07'; Caso = 'UseLogonCredential = 1'; Registro = @{ "$wdigest|UseLogonCredential" = 1 }; Estado = 'FALHA' }
        @{ Id = 'CONTA-08'; Caso = '600 segundos'; Registro = @{ "$sistema|InactivityTimeoutSecs" = 600 }; Estado = 'OK' }
        @{ Id = 'CONTA-08'; Caso = '900 segundos, no limite'; Registro = @{ "$sistema|InactivityTimeoutSecs" = 900 }; Estado = 'OK' }
        @{ Id = 'CONTA-08'; Caso = '901 segundos'; Registro = @{ "$sistema|InactivityTimeoutSecs" = 901 }; Estado = 'FALHA' }
        @{ Id = 'CONTA-08'; Caso = 'zero desliga o bloqueio'; Registro = @{ "$sistema|InactivityTimeoutSecs" = 0 }; Estado = 'FALHA' }
        @{ Id = 'CONTA-08'; Caso = 'não configurado'; Registro = @{}; Estado = 'FALHA' }
        @{ Id = 'REDE-04'; Caso = 'desativado por política'; Registro = @{ "$dns|EnableMulticast" = 0 }; Estado = 'OK' }
        @{ Id = 'REDE-04'; Caso = 'sem política'; Registro = @{}; Estado = 'FALHA' }
        @{ Id = 'REDE-04'; Caso = 'política com valor 1'; Registro = @{ "$dns|EnableMulticast" = 1 }; Estado = 'FALHA' }
        @{ Id = 'REDE-05'; Caso = 'RDP desativado'; Registro = @{ "$ts|fDenyTSConnections" = 1 }; Estado = 'OK' }
        @{ Id = 'REDE-05'; Caso = 'sem valor, o Windows nega conexões'; Registro = @{}; Estado = 'OK' }
        @{ Id = 'REDE-05'; Caso = 'RDP ativo com NLA'; Registro = @{ "$ts|fDenyTSConnections" = 0; "$rdpTcp|UserAuthentication" = 1 }; Estado = 'OK' }
        @{ Id = 'REDE-05'; Caso = 'RDP ativo sem NLA'; Registro = @{ "$ts|fDenyTSConnections" = 0; "$rdpTcp|UserAuthentication" = 0 }; Estado = 'FALHA' }
        @{ Id = 'REDE-05'; Caso = 'política liga o RDP por cima do valor local'; Registro = @{ "$tsPolitica|fDenyTSConnections" = 0; "$ts|fDenyTSConnections" = 1; "$rdpTcp|UserAuthentication" = 0 }; Estado = 'FALHA' }
        @{ Id = 'REDE-05'; Caso = 'política exige NLA por cima do valor local'; Registro = @{ "$ts|fDenyTSConnections" = 0; "$tsPolitica|UserAuthentication" = 1; "$rdpTcp|UserAuthentication" = 0 }; Estado = 'OK' }
        @{ Id = 'LOG-01'; Caso = 'ativo por política'; Registro = @{ "$scriptBlock|EnableScriptBlockLogging" = 1 }; Estado = 'OK' }
        @{ Id = 'LOG-01'; Caso = 'não configurado'; Registro = @{}; Estado = 'FALHA' }
        @{ Id = 'LOG-01'; Caso = 'política com valor 0'; Registro = @{ "$scriptBlock|EnableScriptBlockLogging" = 0 }; Estado = 'FALHA' }
    )

    $casosPolitica = @(
        @{ Id = 'CONTA-03'; Comprimento = 0; Limite = 10; Estado = 'FALHA'; Encontrado = '0 (senha em branco permitida)' }
        @{ Id = 'CONTA-03'; Comprimento = 7; Limite = 10; Estado = 'FALHA'; Encontrado = '7 caracteres' }
        @{ Id = 'CONTA-03'; Comprimento = 8; Limite = 10; Estado = 'OK'; Encontrado = '8 caracteres' }
        @{ Id = 'CONTA-03'; Comprimento = 14; Limite = 10; Estado = 'OK'; Encontrado = '14 caracteres' }
        @{ Id = 'CONTA-04'; Comprimento = 8; Limite = 0; Estado = 'FALHA'; Encontrado = 'Sem bloqueio (0)' }
        @{ Id = 'CONTA-04'; Comprimento = 8; Limite = 5; Estado = 'OK'; Encontrado = '5 tentativas' }
        @{ Id = 'CONTA-04'; Comprimento = 8; Limite = 10; Estado = 'OK'; Encontrado = '10 tentativas' }
        @{ Id = 'CONTA-04'; Comprimento = 8; Limite = 11; Estado = 'FALHA'; Encontrado = '11 tentativas' }
    )
}

BeforeAll {
    $raiz = Split-Path -Path $PSScriptRoot -Parent
    Import-Module -Name (Join-Path -Path $raiz -ChildPath 'AuditoriaWindows/AuditoriaWindows.psd1') -Force

    function Invoke-Verificacao {
        param([string] $Id)
        InModuleScope -ModuleName AuditoriaWindows -Parameters @{ Id = $Id } -ScriptBlock {
            param($Id)
            $definicao = Get-DefinicaoVerificacao | Where-Object { $_.Id -eq $Id }
            & $definicao.Avaliar
        }
    }
}

Describe 'Catálogo de verificações' {
    BeforeAll {
        $definicoes = InModuleScope -ModuleName AuditoriaWindows -ScriptBlock { Get-DefinicaoVerificacao }
    }

    It 'tem 20 verificações com identificadores únicos' {
        $definicoes.Count | Should -Be 20
        @($definicoes.Id | Sort-Object -Unique).Count | Should -Be 20
    }

    It '<_.Id> tem todos os campos preenchidos' -ForEach $definicoes {
        $_.Id | Should -Match '^(CONTA|REDE|SIS|LOG)-\d{2}$'
        $_.Severidade | Should -BeIn @('alta', 'media', 'baixa')
        foreach ($campo in 'Categoria', 'Titulo', 'Esperado', 'Motivo', 'Recomendacao') {
            $_.$campo | Should -Not -BeNullOrEmpty -Because "o campo $campo aparece no relatório"
        }
        $_.Avaliar | Should -BeOfType [scriptblock]
        @($_.Referencias).Count | Should -BeGreaterThan 0
        foreach ($referencia in $_.Referencias) {
            $referencia | Should -Match '^https://'
        }
        foreach ($tecnica in $_.Attack) {
            $tecnica | Should -Match '^T\d{4}(\.\d{3})?$'
        }
    }
}

Describe 'Verificações baseadas no registro' {
    BeforeEach {
        $script:registro = @{}
        Mock -ModuleName AuditoriaWindows -CommandName Get-ValorRegistro -MockWith {
            $script:registro["$Caminho|$Nome"]
        }
    }

    It '<Id>: <Caso>' -ForEach $casosRegistro {
        $script:registro = $Registro
        (Invoke-Verificacao -Id $Id).Estado | Should -Be $Estado
    }
}

Describe 'CONTA-01 e CONTA-02: contas internas' {
    It 'CONTA-01 passa com o Convidado desativado e consulta o RID 501' {
        Mock -ModuleName AuditoriaWindows Get-ContaInterna { [pscustomobject]@{ Nome = 'Convidado'; Ativa = $false } }
        $resultado = Invoke-Verificacao -Id 'CONTA-01'
        $resultado.Estado | Should -Be 'OK'
        $resultado.Encontrado | Should -Be 'Desativada (Convidado)'
        Should -Invoke -ModuleName AuditoriaWindows Get-ContaInterna -Times 1 -Exactly -ParameterFilter { $Rid -eq 501 }
    }

    It 'CONTA-01 falha com o Convidado ativo' {
        Mock -ModuleName AuditoriaWindows Get-ContaInterna { [pscustomobject]@{ Nome = 'Guest'; Ativa = $true } }
        (Invoke-Verificacao -Id 'CONTA-01').Estado | Should -Be 'FALHA'
    }

    It 'CONTA-02 falha com o Administrador interno ativo e consulta o RID 500' {
        Mock -ModuleName AuditoriaWindows Get-ContaInterna { [pscustomobject]@{ Nome = 'Administrador'; Ativa = $true } }
        $resultado = Invoke-Verificacao -Id 'CONTA-02'
        $resultado.Estado | Should -Be 'FALHA'
        $resultado.Encontrado | Should -Be 'Ativa (Administrador)'
        Should -Invoke -ModuleName AuditoriaWindows Get-ContaInterna -Times 1 -Exactly -ParameterFilter { $Rid -eq 500 }
    }

    It 'CONTA-02 passa com o Administrador interno desativado' {
        Mock -ModuleName AuditoriaWindows Get-ContaInterna { [pscustomobject]@{ Nome = 'Administrador'; Ativa = $false } }
        (Invoke-Verificacao -Id 'CONTA-02').Estado | Should -Be 'OK'
    }

    It '<_> não conclui quando a conta não existe' -ForEach 'CONTA-01', 'CONTA-02' {
        Mock -ModuleName AuditoriaWindows Get-ContaInterna { $null }
        (Invoke-Verificacao -Id $_).Estado | Should -Be 'NAO_VERIFICADO'
    }
}

Describe 'CONTA-03 e CONTA-04: política de senha local' {
    It '<Id> com comprimento <Comprimento> e limite <Limite>: <Estado>' -ForEach $casosPolitica {
        $script:politica = [pscustomobject]@{ ComprimentoMinimoSenha = $Comprimento; LimiteBloqueio = $Limite }
        Mock -ModuleName AuditoriaWindows Get-PoliticaContaLocal { $script:politica }
        $resultado = Invoke-Verificacao -Id $Id
        $resultado.Estado | Should -Be $Estado
        $resultado.Encontrado | Should -Be $Encontrado
    }
}

Describe 'REDE-01: firewall' {
    It 'passa com os três perfis ativos' {
        Mock -ModuleName AuditoriaWindows Get-PerfilFirewall {
            foreach ($nome in 'Domain', 'Private', 'Public') { [pscustomobject]@{ Nome = $nome; Ativo = $true } }
        }
        $resultado = Invoke-Verificacao -Id 'REDE-01'
        $resultado.Estado | Should -Be 'OK'
        $resultado.Encontrado | Should -Be 'Domain: ativo, Private: ativo, Public: ativo'
    }

    It 'falha e aponta o perfil desativado' {
        Mock -ModuleName AuditoriaWindows Get-PerfilFirewall {
            [pscustomobject]@{ Nome = 'Domain'; Ativo = $true }
            [pscustomobject]@{ Nome = 'Private'; Ativo = $true }
            [pscustomobject]@{ Nome = 'Public'; Ativo = $false }
        }
        $resultado = Invoke-Verificacao -Id 'REDE-01'
        $resultado.Estado | Should -Be 'FALHA'
        $resultado.Encontrado | Should -Match 'Public: desativado'
    }

    It 'não conclui sem nenhum perfil' {
        Mock -ModuleName AuditoriaWindows Get-PerfilFirewall { }
        (Invoke-Verificacao -Id 'REDE-01').Estado | Should -Be 'NAO_VERIFICADO'
    }
}

Describe 'REDE-02 e REDE-03: servidor SMB' {
    It 'REDE-02 falha com SMBv1 ativo e REDE-03 falha sem assinatura' {
        Mock -ModuleName AuditoriaWindows Get-ConfiguracaoSmbServidor { [pscustomobject]@{ Smb1Ativo = $true; AssinaturaExigida = $false } }
        (Invoke-Verificacao -Id 'REDE-02').Estado | Should -Be 'FALHA'
        (Invoke-Verificacao -Id 'REDE-03').Estado | Should -Be 'FALHA'
    }

    It 'REDE-02 e REDE-03 passam com SMBv1 desligado e assinatura exigida' {
        Mock -ModuleName AuditoriaWindows Get-ConfiguracaoSmbServidor { [pscustomobject]@{ Smb1Ativo = $false; AssinaturaExigida = $true } }
        (Invoke-Verificacao -Id 'REDE-02').Estado | Should -Be 'OK'
        (Invoke-Verificacao -Id 'REDE-03').Estado | Should -Be 'OK'
    }
}

Describe 'SIS-01: BitLocker' {
    It 'passa com a unidade protegida' {
        Mock -ModuleName AuditoriaWindows Get-ProtecaoBitLocker { [pscustomobject]@{ Unidade = 'C:'; Protegido = $true; Situacao = 'FullyEncrypted' } }
        $resultado = Invoke-Verificacao -Id 'SIS-01'
        $resultado.Estado | Should -Be 'OK'
        $resultado.Encontrado | Should -Be 'Ativo em C:'
    }

    It 'falha com a unidade sem proteção' {
        Mock -ModuleName AuditoriaWindows Get-ProtecaoBitLocker { [pscustomobject]@{ Unidade = 'C:'; Protegido = $false; Situacao = 'FullyDecrypted' } }
        $resultado = Invoke-Verificacao -Id 'SIS-01'
        $resultado.Estado | Should -Be 'FALHA'
        $resultado.Encontrado | Should -Be 'Sem proteção em C: (FullyDecrypted)'
    }

    It 'não conclui quando a edição não tem BitLocker' {
        Mock -ModuleName AuditoriaWindows Get-ProtecaoBitLocker { $null }
        (Invoke-Verificacao -Id 'SIS-01').Estado | Should -Be 'NAO_VERIFICADO'
    }
}

Describe 'SIS-02 e SIS-03: Microsoft Defender' {
    It 'SIS-02 passa com proteção em tempo real' {
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = 'Normal'; TempoReal = $true; IdadeAssinaturaDias = 1 } }
        (Invoke-Verificacao -Id 'SIS-02').Estado | Should -Be 'OK'
    }

    It 'SIS-02 falha sem proteção em tempo real' {
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = 'Normal'; TempoReal = $false; IdadeAssinaturaDias = 1 } }
        (Invoke-Verificacao -Id 'SIS-02').Estado | Should -Be 'FALHA'
    }

    It 'SIS-02 aceita versões antigas sem o campo de modo' {
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = ''; TempoReal = $true; IdadeAssinaturaDias = 1 } }
        (Invoke-Verificacao -Id 'SIS-02').Estado | Should -Be 'OK'
    }

    It 'SIS-03 com definições de <_> dias' -ForEach 0, 7 {
        $script:idade = $_
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = 'Normal'; TempoReal = $true; IdadeAssinaturaDias = $script:idade } }
        (Invoke-Verificacao -Id 'SIS-03').Estado | Should -Be 'OK'
    }

    It 'SIS-03 falha com definições de 8 dias' {
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = 'Normal'; TempoReal = $true; IdadeAssinaturaDias = 8 } }
        $resultado = Invoke-Verificacao -Id 'SIS-03'
        $resultado.Estado | Should -Be 'FALHA'
        $resultado.Encontrado | Should -Be '8 dias'
    }

    It '<_> não conclui com o Defender em modo passivo' -ForEach 'SIS-02', 'SIS-03' {
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { [pscustomobject]@{ Modo = 'Passive Mode'; TempoReal = $false; IdadeAssinaturaDias = 30 } }
        $resultado = Invoke-Verificacao -Id $_
        $resultado.Estado | Should -Be 'NAO_VERIFICADO'
        $resultado.Encontrado | Should -Match 'Passive Mode'
    }

    It '<_> não conclui sem o Defender' -ForEach 'SIS-02', 'SIS-03' {
        Mock -ModuleName AuditoriaWindows Get-EstadoDefender { $null }
        (Invoke-Verificacao -Id $_).Estado | Should -Be 'NAO_VERIFICADO'
    }
}

Describe 'SIS-04: atualizações do Windows' {
    BeforeEach {
        Mock -ModuleName AuditoriaWindows Get-DataAtual { [datetime]'2026-11-17T10:00:00' }
    }

    It 'com a última atualização há <Dias> dias: <Estado>' -ForEach @(
        @{ Data = '2026-10-20'; Dias = 28; Estado = 'OK' }
        @{ Data = '2026-10-08'; Dias = 40; Estado = 'OK' }
        @{ Data = '2026-10-07'; Dias = 41; Estado = 'FALHA' }
    ) {
        $script:ultima = [pscustomobject]@{ Id = 'KB5000001'; Data = [datetime]$Data }
        Mock -ModuleName AuditoriaWindows Get-UltimaAtualizacao { $script:ultima }
        $resultado = Invoke-Verificacao -Id 'SIS-04'
        $resultado.Estado | Should -Be $Estado
        $resultado.Encontrado | Should -Be ('KB5000001 em {0} ({1} dias)' -f $Data, $Dias)
    }

    It 'não conclui sem nenhuma atualização listada' {
        Mock -ModuleName AuditoriaWindows Get-UltimaAtualizacao { $null }
        (Invoke-Verificacao -Id 'SIS-04').Estado | Should -Be 'NAO_VERIFICADO'
    }
}

Describe 'SIS-05: PowerShell 2.0' {
    It 'com o recurso em <Situacao>: <Estado>' -ForEach @(
        @{ Situacao = 'Enabled'; Estado = 'FALHA' }
        @{ Situacao = 'Disabled'; Estado = 'OK' }
        @{ Situacao = 'DisabledWithPayloadRemoved'; Estado = 'OK' }
    ) {
        $script:situacao = $Situacao
        Mock -ModuleName AuditoriaWindows Get-EstadoRecursoOpcional { $script:situacao }
        (Invoke-Verificacao -Id 'SIS-05').Estado | Should -Be $Estado
        Should -Invoke -ModuleName AuditoriaWindows Get-EstadoRecursoOpcional -ParameterFilter { $Nome -eq 'MicrosoftWindowsPowerShellV2Root' }
    }

    It 'passa quando o recurso não existe nesta versão do Windows' {
        Mock -ModuleName AuditoriaWindows Get-EstadoRecursoOpcional { $null }
        $resultado = Invoke-Verificacao -Id 'SIS-05'
        $resultado.Estado | Should -Be 'OK'
        $resultado.Encontrado | Should -Be 'Não existe nesta versão do Windows'
    }
}

Describe 'LOG-02: tamanho do log de Segurança' {
    It 'com <Mb> MB: <Estado>' -ForEach @(
        @{ Mb = 20; Estado = 'FALHA' }
        @{ Mb = 191; Estado = 'FALHA' }
        @{ Mb = 192; Estado = 'OK' }
        @{ Mb = 1024; Estado = 'OK' }
    ) {
        $script:bytes = [long]$Mb * 1MB
        Mock -ModuleName AuditoriaWindows Get-TamanhoLogEvento { $script:bytes }
        $resultado = Invoke-Verificacao -Id 'LOG-02'
        $resultado.Estado | Should -Be $Estado
        $resultado.Encontrado | Should -Be ('{0} MB' -f $Mb)
        Should -Invoke -ModuleName AuditoriaWindows Get-TamanhoLogEvento -ParameterFilter { $Log -eq 'Security' }
    }
}
