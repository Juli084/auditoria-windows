# Definição das verificações.
#
# Cada verificação lê o sistema só pelas funções de Leitura.ps1 e devolve um
# resultado de New-ResultadoVerificacao. Os limites numéricos que não vêm de
# documentação da Microsoft estão marcados como critério desta ferramenta em
# docs/verificacoes.md.

$script:ChaveSistema = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:ChaveWDigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$script:ChaveDnsCliente = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$script:ChaveTsPolitica = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$script:ChaveTs = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$script:ChaveRdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$script:ChaveScriptBlock = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

$script:DocPoliticas = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings'

function Get-ValorComPolitica {
    # Valor de política (GPO) tem precedência sobre o valor local.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ChavePolitica,
        [Parameter(Mandatory)] [string] $ChaveLocal,
        [Parameter(Mandatory)] [string] $Nome
    )
    $politica = Get-ValorRegistro -Caminho $ChavePolitica -Nome $Nome
    if ($null -ne $politica) {
        return $politica
    }
    return Get-ValorRegistro -Caminho $ChaveLocal -Nome $Nome
}

function Get-ResultadoDefender {
    # Barreira comum às duas verificações do Defender. Devolve um resultado
    # NAO_VERIFICADO quando não dá para avaliar, ou $null quando dá.
    [CmdletBinding()]
    param($Estado)
    if ($null -eq $Estado) {
        return New-ResultadoVerificacao NAO_VERIFICADO 'Microsoft Defender não encontrado'
    }
    if ($Estado.Modo -ne '' -and $Estado.Modo -ne 'Normal') {
        return New-ResultadoVerificacao NAO_VERIFICADO ("Defender em modo '{0}'; confira qual antivírus está ativo" -f $Estado.Modo)
    }
    return $null
}

$script:Verificacoes = @(
    [pscustomobject]@{
        Id           = 'CONTA-01'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'Conta Convidado desativada'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'Desativada'
        Motivo       = 'A conta Convidado deixa alguém sem credencial própria entrar no computador, inclusive pela rede, e não identifica quem usou.'
        Recomendacao = "Desative a conta: Get-LocalUser | Where-Object { `$_.SID.Value.EndsWith('-501') } | Disable-LocalUser"
        Attack       = @('T1078.001')
        Referencias  = @("$script:DocPoliticas/accounts-guest-account-status")
        Avaliar      = {
            $conta = Get-ContaInterna -Rid 501
            if ($null -eq $conta) {
                return New-ResultadoVerificacao NAO_VERIFICADO 'Conta não encontrada'
            }
            if ($conta.Ativa) {
                return New-ResultadoVerificacao FALHA ('Ativa ({0})' -f $conta.Nome)
            }
            New-ResultadoVerificacao OK ('Desativada ({0})' -f $conta.Nome)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-02'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'Administrador interno desativado'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'Desativada'
        Motivo       = 'O SID da conta é previsível e, por padrão, ela não passa pelo modo de aprovação do UAC (FilterAdministratorToken = 0): o que roda nela já roda elevado.'
        Recomendacao = "Use uma conta administradora com nome próprio. Depois de confirmar que ela existe, desative a interna: Get-LocalUser | Where-Object { `$_.SID.Value.EndsWith('-500') } | Disable-LocalUser"
        Attack       = @('T1078.001')
        Referencias  = @(
            "$script:DocPoliticas/accounts-administrator-account-status"
            'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration'
        )
        Avaliar      = {
            $conta = Get-ContaInterna -Rid 500
            if ($null -eq $conta) {
                return New-ResultadoVerificacao NAO_VERIFICADO 'Conta não encontrada'
            }
            if ($conta.Ativa) {
                return New-ResultadoVerificacao FALHA ('Ativa ({0})' -f $conta.Nome)
            }
            New-ResultadoVerificacao OK ('Desativada ({0})' -f $conta.Nome)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-03'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'Senha local com pelo menos 8 caracteres'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'Comprimento mínimo de 8 ou mais'
        Motivo       = 'Com comprimento mínimo 0, uma conta local pode ficar sem senha. A Microsoft recomenda pelo menos 8 caracteres.'
        Recomendacao = 'Defina o comprimento mínimo na política local: net accounts /minpwlen:8 (ou mais). Contas de domínio seguem a política do domínio.'
        Attack       = @('T1110')
        Referencias  = @("$script:DocPoliticas/minimum-password-length")
        Avaliar      = {
            $comprimento = (Get-PoliticaContaLocal).ComprimentoMinimoSenha
            if ($comprimento -eq 0) {
                return New-ResultadoVerificacao FALHA '0 (senha em branco permitida)'
            }
            if ($comprimento -lt 8) {
                return New-ResultadoVerificacao FALHA ('{0} caracteres' -f $comprimento)
            }
            New-ResultadoVerificacao OK ('{0} caracteres' -f $comprimento)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-04'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'Bloqueio de conta após tentativas inválidas'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'Entre 1 e 10 tentativas'
        Motivo       = 'Sem limite, uma senha local pode ser testada sem parar. As linhas de base de segurança do Windows recomendam 10 tentativas.'
        Recomendacao = 'net accounts /lockoutthreshold:10'
        Attack       = @('T1110')
        Referencias  = @("$script:DocPoliticas/account-lockout-threshold")
        Avaliar      = {
            $limite = (Get-PoliticaContaLocal).LimiteBloqueio
            if ($limite -eq 0) {
                return New-ResultadoVerificacao FALHA 'Sem bloqueio (0)'
            }
            if ($limite -gt 10) {
                return New-ResultadoVerificacao FALHA ('{0} tentativas' -f $limite)
            }
            New-ResultadoVerificacao OK ('{0} tentativas' -f $limite)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-05'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'UAC ativo'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'EnableLUA = 1'
        Motivo       = 'Sem o UAC, todo programa aberto por um administrador roda com privilégio total, sem nenhum aviso.'
        Recomendacao = 'Defina EnableLUA = 1 em HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System (política "User Account Control: Run all administrators in Admin Approval Mode") e reinicie.'
        Attack       = @('T1548.002')
        Referencias  = @(
            "$script:DocPoliticas/user-account-control-run-all-administrators-in-admin-approval-mode"
            'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration'
        )
        Avaliar      = {
            $valor = Get-ValorRegistro -Caminho $script:ChaveSistema -Nome 'EnableLUA'
            if ($null -eq $valor) {
                return New-ResultadoVerificacao OK 'Padrão do Windows (ativo)'
            }
            if ($valor -eq 1) {
                return New-ResultadoVerificacao OK 'Ativo'
            }
            New-ResultadoVerificacao FALHA ('Desativado (EnableLUA = {0})' -f $valor)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-06'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'Elevação de administrador pede confirmação'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'ConsentPromptBehaviorAdmin diferente de 0'
        Motivo       = 'Com o valor 0, um programa pede privilégio de administrador e recebe sem aviso.'
        Recomendacao = 'Use 2 (pedir consentimento na área de trabalho segura) ou mantenha o padrão 5.'
        Attack       = @('T1548.002')
        Referencias  = @("$script:DocPoliticas/user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode")
        Avaliar      = {
            $valor = Get-ValorRegistro -Caminho $script:ChaveSistema -Nome 'ConsentPromptBehaviorAdmin'
            if ($null -eq $valor) {
                return New-ResultadoVerificacao OK 'Padrão do Windows (5)'
            }
            if ($valor -eq 0) {
                return New-ResultadoVerificacao FALHA 'Eleva sem perguntar (0)'
            }
            New-ResultadoVerificacao OK ('Pede confirmação ({0})' -f $valor)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-07'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'WDigest não guarda senhas na memória'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'UseLogonCredential ausente ou 0'
        Motivo       = 'Com UseLogonCredential = 1, o Windows mantém a senha de quem fez logon em texto claro na memória do LSASS, de onde ferramentas de extração de credenciais conseguem lê-la.'
        Recomendacao = 'Remova o valor ou defina 0 em HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest. Se ninguém sabe explicar por que está em 1, trate como possível sinal de comprometimento e investigue.'
        Attack       = @('T1003.001')
        Referencias  = @('https://attack.mitre.org/techniques/T1003/001/')
        Avaliar      = {
            $valor = Get-ValorRegistro -Caminho $script:ChaveWDigest -Nome 'UseLogonCredential'
            if ($null -eq $valor) {
                return New-ResultadoVerificacao OK 'Não configurado (padrão: não guarda)'
            }
            if ($valor -eq 1) {
                return New-ResultadoVerificacao FALHA 'Guarda a senha em texto claro (UseLogonCredential = 1)'
            }
            New-ResultadoVerificacao OK ('UseLogonCredential = {0}' -f $valor)
        }
    }
    [pscustomobject]@{
        Id           = 'CONTA-08'
        Categoria    = 'Contas e autenticação'
        Titulo       = 'Tela bloqueia após até 15 minutos sem uso'
        Severidade   = 'baixa'
        RequerAdmin  = $false
        Esperado     = 'InactivityTimeoutSecs entre 1 e 900'
        Motivo       = 'Um computador destravado e sem ninguém na frente dá acesso a tudo o que o usuário pode fazer.'
        Recomendacao = 'Configure a política "Interactive logon: Machine inactivity limit" com 900 segundos ou menos.'
        Attack       = @()
        Referencias  = @("$script:DocPoliticas/interactive-logon-machine-inactivity-limit")
        Avaliar      = {
            $segundos = Get-ValorRegistro -Caminho $script:ChaveSistema -Nome 'InactivityTimeoutSecs'
            if ($null -eq $segundos -or $segundos -eq 0) {
                return New-ResultadoVerificacao FALHA 'Não configurado'
            }
            if ($segundos -gt 900) {
                return New-ResultadoVerificacao FALHA ('{0} segundos' -f $segundos)
            }
            New-ResultadoVerificacao OK ('{0} segundos' -f $segundos)
        }
    }
    [pscustomobject]@{
        Id           = 'REDE-01'
        Categoria    = 'Rede'
        Titulo       = 'Firewall ativo nos três perfis'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'Domain, Private e Public ativos'
        Motivo       = 'O perfil em uso muda com a rede. Um perfil desativado deixa o computador exposto justamente na rede em que ele estiver.'
        Recomendacao = 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'
        Attack       = @()
        Referencias  = @('https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/')
        Avaliar      = {
            $perfis = @(Get-PerfilFirewall)
            if ($perfis.Count -eq 0) {
                return New-ResultadoVerificacao NAO_VERIFICADO 'Nenhum perfil encontrado'
            }
            $descricao = ($perfis | ForEach-Object {
                    '{0}: {1}' -f $_.Nome, $(if ($_.Ativo) { 'ativo' } else { 'desativado' })
                }) -join ', '
            if (@($perfis | Where-Object { -not $_.Ativo }).Count -gt 0) {
                return New-ResultadoVerificacao FALHA $descricao
            }
            New-ResultadoVerificacao OK $descricao
        }
    }
    [pscustomobject]@{
        Id           = 'REDE-02'
        Categoria    = 'Rede'
        Titulo       = 'SMBv1 desativado no servidor'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'EnableSMB1Protocol = False'
        Motivo       = 'O SMBv1 é a versão explorada pelo EternalBlue, usado pelo WannaCry em 2017, e não tem as proteções das versões 2 e 3.'
        Recomendacao = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false, ou remova o recurso "SMB 1.0/CIFS File Sharing Support".'
        Attack       = @('T1210')
        Referencias  = @('https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3')
        Avaliar      = {
            if ((Get-ConfiguracaoSmbServidor).Smb1Ativo) {
                return New-ResultadoVerificacao FALHA 'SMBv1 ativo'
            }
            New-ResultadoVerificacao OK 'SMBv1 desativado'
        }
    }
    [pscustomobject]@{
        Id           = 'REDE-03'
        Categoria    = 'Rede'
        Titulo       = 'Servidor SMB exige assinatura'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'RequireSecuritySignature = True'
        Motivo       = 'Sem assinatura obrigatória, um atacante na rede pode retransmitir uma autenticação SMB (SMB relay) e agir em nome da vítima.'
        Recomendacao = 'Set-SmbServerConfiguration -RequireSecuritySignature $true. Teste antes com impressoras e NAS antigos, que podem não suportar.'
        Attack       = @('T1557.001')
        Referencias  = @(
            'https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview'
            "$script:DocPoliticas/microsoft-network-server-digitally-sign-communications-always"
        )
        Avaliar      = {
            if ((Get-ConfiguracaoSmbServidor).AssinaturaExigida) {
                return New-ResultadoVerificacao OK 'Assinatura exigida'
            }
            New-ResultadoVerificacao FALHA 'Assinatura não exigida'
        }
    }
    [pscustomobject]@{
        Id           = 'REDE-04'
        Categoria    = 'Rede'
        Titulo       = 'LLMNR desativado'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'EnableMulticast = 0 (política)'
        Motivo       = 'Quando o DNS não resolve um nome, o Windows pergunta na rede local por LLMNR e aceita a resposta de qualquer máquina. Ferramentas de envenenamento usam isso para capturar hashes NTLM.'
        Recomendacao = 'Ative a política "Turn off multicast name resolution" (EnableMulticast = 0 em HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient).'
        Attack       = @('T1557.001')
        Referencias  = @('https://attack.mitre.org/techniques/T1557/001/')
        Avaliar      = {
            $valor = Get-ValorRegistro -Caminho $script:ChaveDnsCliente -Nome 'EnableMulticast'
            if ($null -eq $valor) {
                return New-ResultadoVerificacao FALHA 'Ativo (padrão do Windows)'
            }
            if ($valor -eq 0) {
                return New-ResultadoVerificacao OK 'Desativado por política'
            }
            New-ResultadoVerificacao FALHA ('Ativo (EnableMulticast = {0})' -f $valor)
        }
    }
    [pscustomobject]@{
        Id           = 'REDE-05'
        Categoria    = 'Rede'
        Titulo       = 'Área de Trabalho Remota desativada ou com NLA'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'Desativada, ou ativa com Network Level Authentication'
        Motivo       = 'Com NLA, o usuário precisa se autenticar antes de a sessão remota ser criada. Sem NLA, o serviço fica exposto a quem nem tem credencial.'
        Recomendacao = 'Se ninguém usa acesso remoto, desative. Se usa, exija NLA em Configurações > Sistema > Área de Trabalho Remota e não exponha a porta 3389 na internet.'
        Attack       = @('T1021.001')
        Referencias  = @('https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access')
        Avaliar      = {
            $negar = Get-ValorComPolitica -ChavePolitica $script:ChaveTsPolitica -ChaveLocal $script:ChaveTs -Nome 'fDenyTSConnections'
            # Sem valor, o Windows nega conexões remotas.
            if ($null -eq $negar -or $negar -eq 1) {
                return New-ResultadoVerificacao OK 'Desativada'
            }
            $nla = Get-ValorComPolitica -ChavePolitica $script:ChaveTsPolitica -ChaveLocal $script:ChaveRdpTcp -Nome 'UserAuthentication'
            if ($nla -eq 1) {
                return New-ResultadoVerificacao OK 'Ativa, com NLA'
            }
            New-ResultadoVerificacao FALHA 'Ativa, sem NLA'
        }
    }
    [pscustomobject]@{
        Id           = 'SIS-01'
        Categoria    = 'Sistema'
        Titulo       = 'Disco do sistema protegido por BitLocker'
        Severidade   = 'alta'
        RequerAdmin  = $true
        Esperado     = 'Proteção ativa na unidade do sistema'
        Motivo       = 'Sem criptografia, quem leva o notebook ou o disco lê todos os arquivos sem precisar de senha.'
        Recomendacao = 'Ative o BitLocker e guarde a chave de recuperação fora do computador.'
        Attack       = @()
        Referencias  = @('https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/')
        Avaliar      = {
            $protecao = Get-ProtecaoBitLocker
            if ($null -eq $protecao) {
                return New-ResultadoVerificacao NAO_VERIFICADO 'BitLocker não disponível nesta edição do Windows'
            }
            if ($protecao.Protegido) {
                return New-ResultadoVerificacao OK ('Ativo em {0}' -f $protecao.Unidade)
            }
            New-ResultadoVerificacao FALHA ('Sem proteção em {0} ({1})' -f $protecao.Unidade, $protecao.Situacao)
        }
    }
    [pscustomobject]@{
        Id           = 'SIS-02'
        Categoria    = 'Sistema'
        Titulo       = 'Defender com proteção em tempo real'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'Proteção em tempo real ativa'
        Motivo       = 'Sem proteção em tempo real, um arquivo malicioso só é examinado numa varredura agendada, se houver uma.'
        Recomendacao = 'Reative com Set-MpPreference -DisableRealtimeMonitoring $false e descubra quem a desativou.'
        Attack       = @()
        Referencias  = @(
            'https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows'
            'https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility'
        )
        Avaliar      = {
            $estado = Get-EstadoDefender
            $barreira = Get-ResultadoDefender -Estado $estado
            if ($null -ne $barreira) {
                return $barreira
            }
            if ($estado.TempoReal) {
                return New-ResultadoVerificacao OK 'Ativa'
            }
            New-ResultadoVerificacao FALHA 'Desativada'
        }
    }
    [pscustomobject]@{
        Id           = 'SIS-03'
        Categoria    = 'Sistema'
        Titulo       = 'Definições do Defender com até 7 dias'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = '7 dias ou menos'
        Motivo       = 'Definições antigas não reconhecem ameaças recentes.'
        Recomendacao = 'Rode Update-MpSignature e confira se o computador alcança o Windows Update ou o servidor de atualizações.'
        Attack       = @()
        Referencias  = @('https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows')
        Avaliar      = {
            $estado = Get-EstadoDefender
            $barreira = Get-ResultadoDefender -Estado $estado
            if ($null -ne $barreira) {
                return $barreira
            }
            $texto = '{0} dias' -f $estado.IdadeAssinaturaDias
            if ($estado.IdadeAssinaturaDias -gt 7) {
                return New-ResultadoVerificacao FALHA $texto
            }
            New-ResultadoVerificacao OK $texto
        }
    }
    [pscustomobject]@{
        Id           = 'SIS-04'
        Categoria    = 'Sistema'
        Titulo       = 'Atualização do Windows nos últimos 40 dias'
        Severidade   = 'alta'
        RequerAdmin  = $false
        Esperado     = 'Última atualização instalada há 40 dias ou menos'
        Motivo       = 'A Microsoft publica correções de segurança todo mês. Sem atualização há mais de um ciclo, o computador fica exposto a falhas já conhecidas.'
        Recomendacao = 'Verifique o Windows Update. Se a versão do Windows já saiu de suporte, planeje a migração.'
        Attack       = @()
        Referencias  = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix')
        Avaliar      = {
            $ultima = Get-UltimaAtualizacao
            if ($null -eq $ultima) {
                return New-ResultadoVerificacao NAO_VERIFICADO 'Nenhuma atualização listada'
            }
            $dias = ((Get-DataAtual).Date - $ultima.Data.Date).Days
            $texto = '{0} em {1:yyyy-MM-dd} ({2} dias)' -f $ultima.Id, $ultima.Data, $dias
            if ($dias -gt 40) {
                return New-ResultadoVerificacao FALHA $texto
            }
            New-ResultadoVerificacao OK $texto
        }
    }
    [pscustomobject]@{
        Id           = 'SIS-05'
        Categoria    = 'Sistema'
        Titulo       = 'PowerShell 2.0 removido'
        Severidade   = 'media'
        RequerAdmin  = $true
        Esperado     = 'Recurso MicrosoftWindowsPowerShellV2Root ausente ou desativado'
        Motivo       = 'O PowerShell 2.0 não tem registro de blocos de script. Chamar powershell -Version 2 é uma forma conhecida de escapar desse registro.'
        Recomendacao = 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'
        Attack       = @('T1689')
        Referencias  = @('https://attack.mitre.org/techniques/T1689/')
        Avaliar      = {
            $estado = Get-EstadoRecursoOpcional -Nome 'MicrosoftWindowsPowerShellV2Root'
            if ($null -eq $estado) {
                return New-ResultadoVerificacao OK 'Não existe nesta versão do Windows'
            }
            if ($estado -eq 'Enabled') {
                return New-ResultadoVerificacao FALHA 'Instalado'
            }
            New-ResultadoVerificacao OK ('Removido ({0})' -f $estado)
        }
    }
    [pscustomobject]@{
        Id           = 'LOG-01'
        Categoria    = 'Registro de eventos'
        Titulo       = 'Registro de blocos de script do PowerShell ativo'
        Severidade   = 'media'
        RequerAdmin  = $false
        Esperado     = 'EnableScriptBlockLogging = 1 (política)'
        Motivo       = 'Grava no log Microsoft-Windows-PowerShell/Operational (evento 4104) o conteúdo de cada bloco de script executado. Numa investigação, mostra o que de fato rodou.'
        Recomendacao = 'Ative a política "Turn on PowerShell Script Block Logging". O log pode passar a conter dados sensíveis usados em scripts, então restrinja quem pode lê-lo.'
        Attack       = @('T1059.001')
        Referencias  = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1')
        Avaliar      = {
            $valor = Get-ValorRegistro -Caminho $script:ChaveScriptBlock -Nome 'EnableScriptBlockLogging'
            if ($valor -eq 1) {
                return New-ResultadoVerificacao OK 'Ativo por política'
            }
            New-ResultadoVerificacao FALHA 'Não configurado'
        }
    }
    [pscustomobject]@{
        Id           = 'LOG-02'
        Categoria    = 'Registro de eventos'
        Titulo       = 'Log de Segurança com pelo menos 192 MB'
        Severidade   = 'baixa'
        RequerAdmin  = $true
        Esperado     = '192 MB ou mais'
        Motivo       = 'O log de Segurança guarda logons, falhas de senha e mudanças de conta. Pequeno demais, ele sobrescreve os eventos antigos antes de alguém precisar deles.'
        Recomendacao = 'Aumente o tamanho máximo (wevtutil sl Security /ms:201326592) ou envie os eventos para um coletor central.'
        Attack       = @()
        Referencias  = @('https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil')
        Avaliar      = {
            $bytes = Get-TamanhoLogEvento -Log 'Security'
            $texto = '{0} MB' -f [math]::Round($bytes / 1MB)
            if ($bytes -lt 192MB) {
                return New-ResultadoVerificacao FALHA $texto
            }
            New-ResultadoVerificacao OK $texto
        }
    }
)

function Get-DefinicaoVerificacao {
    [CmdletBinding()]
    param()
    $script:Verificacoes
}
