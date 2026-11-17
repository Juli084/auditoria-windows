# Leitura do estado do Windows.
#
# Estas são as únicas funções do módulo que consultam o sistema. As verificações
# chamam só estas funções, e os testes as substituem por dublês. Nenhuma delas
# grava nada: registro, serviços e políticas são apenas lidos.

function Get-ValorRegistro {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Caminho,
        [Parameter(Mandatory)] [string] $Nome
    )
    # Chave ausente e valor ausente devolvem $null. Acesso negado continua sendo
    # erro, para não ser confundido com "não configurado".
    try {
        $chave = Get-Item -LiteralPath $Caminho -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
    return $chave.GetValue($Nome, $null)
}

function Test-Administrador {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identidade = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identidade
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InformacaoSistema {
    [CmdletBinding()]
    param()
    $so = Get-CimInstance -ClassName Win32_OperatingSystem
    [pscustomobject]@{
        Nome   = [string]$so.Caption
        Versao = [string]$so.Version
        Build  = [string]$so.BuildNumber
    }
}

function Get-DataAtual {
    [CmdletBinding()]
    [OutputType([datetime])]
    param()
    return Get-Date
}

function Get-PoliticaContaLocal {
    [CmdletBinding()]
    param()
    # NetUserModalsGet é a mesma API que o "net accounts" usa. Ler por ela evita
    # interpretar a saída do comando, que muda com o idioma do Windows, e não
    # exige administrador.
    if (-not ('AuditoriaWindows.NetApi' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace AuditoriaWindows {
    public static class NetApi {
        [StructLayout(LayoutKind.Sequential)]
        private struct USER_MODALS_INFO_0 {
            public uint MinPasswdLen;
            public uint MaxPasswdAge;
            public uint MinPasswdAge;
            public uint ForceLogoff;
            public uint PasswordHistLen;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct USER_MODALS_INFO_3 {
            public uint LockoutDuration;
            public uint LockoutObservationWindow;
            public uint LockoutThreshold;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetUserModalsGet(string servername, uint level, out IntPtr bufptr);

        [DllImport("netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        private static T Ler<T>(uint nivel) {
            IntPtr buffer;
            uint status = NetUserModalsGet(null, nivel, out buffer);
            if (status != 0) {
                throw new Win32Exception((int)status);
            }
            try {
                return (T)Marshal.PtrToStructure(buffer, typeof(T));
            } finally {
                NetApiBufferFree(buffer);
            }
        }

        public static uint ComprimentoMinimoSenha() {
            return Ler<USER_MODALS_INFO_0>(0).MinPasswdLen;
        }

        public static uint LimiteBloqueio() {
            return Ler<USER_MODALS_INFO_3>(3).LockoutThreshold;
        }
    }
}
'@
    }
    [pscustomobject]@{
        ComprimentoMinimoSenha = [int][AuditoriaWindows.NetApi]::ComprimentoMinimoSenha()
        LimiteBloqueio         = [int][AuditoriaWindows.NetApi]::LimiteBloqueio()
    }
}

function Get-ContaInterna {
    [CmdletBinding()]
    param(
        # 500 é o Administrador interno e 501 é o Convidado. O nome muda com o
        # idioma e pode ter sido trocado, mas o final do SID não muda.
        [Parameter(Mandatory)] [ValidateSet(500, 501)] [int] $Rid
    )
    $sufixo = "-$Rid"
    $conta = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith($sufixo) } | Select-Object -First 1
    if ($null -eq $conta) {
        return $null
    }
    [pscustomobject]@{
        Nome  = [string]$conta.Name
        Ativa = [bool]$conta.Enabled
    }
}

function Get-PerfilFirewall {
    [CmdletBinding()]
    param()
    # ActiveStore é a configuração em vigor, já somando o que vem de política de grupo.
    Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{
            Nome  = [string]$_.Name
            Ativo = ([string]$_.Enabled -eq 'True')
        }
    }
}

function Get-ConfiguracaoSmbServidor {
    [CmdletBinding()]
    param()
    $configuracao = Get-SmbServerConfiguration
    [pscustomobject]@{
        Smb1Ativo         = [bool]$configuracao.EnableSMB1Protocol
        AssinaturaExigida = [bool]$configuracao.RequireSecuritySignature
    }
}

function Get-EstadoDefender {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return $null
    }
    $estado = Get-MpComputerStatus
    # AMRunningMode não existe nas versões antigas do Defender.
    $modo = $estado.PSObject.Properties['AMRunningMode']
    [pscustomobject]@{
        Modo                = if ($null -ne $modo) { [string]$modo.Value } else { '' }
        TempoReal           = [bool]$estado.RealTimeProtectionEnabled
        IdadeAssinaturaDias = [int]$estado.AntivirusSignatureAge
    }
}

function Get-ProtecaoBitLocker {
    [CmdletBinding()]
    param()
    # O módulo BitLocker não existe nas edições Home.
    if (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return $null
    }
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive
    [pscustomobject]@{
        Unidade   = [string]$env:SystemDrive
        Protegido = ([string]$volume.ProtectionStatus -eq 'On')
        Situacao  = [string]$volume.VolumeStatus
    }
}

function Get-EstadoRecursoOpcional {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Nome
    )
    # Lista todos os recursos e procura pelo nome, em vez de pedir um só: pedir
    # um recurso que não existe gera erro, e o PowerShell 2.0 já não existe nas
    # versões mais novas do Windows. Assim, $null significa "não existe aqui".
    $recurso = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq $Nome } | Select-Object -First 1
    if ($null -eq $recurso) {
        return $null
    }
    return [string]$recurso.State
}

function Get-TamanhoLogEvento {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)] [string] $Log
    )
    return [long](Get-WinEvent -ListLog $Log -ErrorAction Stop).MaximumSizeInBytes
}

function Get-UltimaAtualizacao {
    [CmdletBinding()]
    param()
    # Win32_QuickFixEngineering lista as atualizações do sistema operacional.
    # Atualizações do Office, de drivers e as definições do Defender não entram.
    $ultima = Get-HotFix |
        Where-Object { $null -ne $_.InstalledOn } |
        Sort-Object -Property InstalledOn -Descending |
        Select-Object -First 1
    if ($null -eq $ultima) {
        return $null
    }
    [pscustomobject]@{
        Id   = [string]$ultima.HotFixID
        Data = [datetime]$ultima.InstalledOn
    }
}
