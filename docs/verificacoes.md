# Verificações: o que é lido e de onde vem cada critério

Na coluna "Origem do critério":

- **Microsoft** indica que o valor vem da documentação oficial citada;
- **Padrão do Windows** indica que o critério é não ter mudado o comportamento padrão;
- **Critério meu** indica um limite escolhido por mim, com o motivo logo abaixo da tabela.

Os links completos estão no campo `Referencias` de cada verificação, em
[`Verificacoes.ps1`](../AuditoriaWindows/Funcoes/Verificacoes.ps1), e no relatório HTML.

## Contas e autenticação

| Id | O que é lido | OK quando | Origem do critério |
|---|---|---|---|
| CONTA-01 | `Get-LocalUser`, conta cujo SID termina em `-501` | conta desativada | Microsoft: *Accounts: Guest account status* |
| CONTA-02 | `Get-LocalUser`, conta cujo SID termina em `-500` | conta desativada | Microsoft: *Accounts: Administrator account status* e configurações do UAC |
| CONTA-03 | `NetUserModalsGet`, nível 0, `usrmod0_min_passwd_len` | 8 ou mais | Microsoft: *Minimum password length* ("at least a value of 8") |
| CONTA-04 | `NetUserModalsGet`, nível 3, `usrmod3_lockout_threshold` | entre 1 e 10 | Microsoft: *Account lockout threshold* (as linhas de base de segurança recomendam 10) |
| CONTA-05 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` | 1, ou ausente (padrão 1) | Padrão do Windows |
| CONTA-06 | mesma chave, `ConsentPromptBehaviorAdmin` | diferente de 0, ou ausente (padrão 5) | Padrão do Windows |
| CONTA-07 | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` | ausente ou diferente de 1 | Padrão do Windows. O ATT&CK lista desativar o WDigest como mitigação de T1003.001 |
| CONTA-08 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs` | entre 1 e 900 | Critério meu |

## Rede

| Id | O que é lido | OK quando | Origem do critério |
|---|---|---|---|
| REDE-01 | `Get-NetFirewallProfile -PolicyStore ActiveStore` | os três perfis ativos | Padrão do Windows |
| REDE-02 | `Get-SmbServerConfiguration`, `EnableSMB1Protocol` | `False` | Microsoft: *Detect, enable, and disable SMBv1, SMBv2, and SMBv3* |
| REDE-03 | `Get-SmbServerConfiguration`, `RequireSecuritySignature` | `True` | Microsoft: *Overview of SMB signing* e *Microsoft network server: Digitally sign communications (always)* |
| REDE-04 | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` | 0 | Política *Turn off multicast name resolution*. Ligado a T1557.001 |
| REDE-05 | `fDenyTSConnections` e `UserAuthentication`, primeiro em `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, depois nas chaves locais do Terminal Server | RDP desativado, ou ativo com NLA (`UserAuthentication = 1`) | Microsoft: *Enable Remote Desktop on your PC* |

## Sistema

| Id | O que é lido | OK quando | Origem do critério |
|---|---|---|---|
| SIS-01 | `Get-BitLockerVolume` na unidade do sistema | `ProtectionStatus = On` | Microsoft: documentação do BitLocker |
| SIS-02 | `Get-MpComputerStatus`, `RealTimeProtectionEnabled` | `True` | Padrão do Windows |
| SIS-03 | `Get-MpComputerStatus`, `AntivirusSignatureAge` | 7 dias ou menos | Critério meu |
| SIS-04 | `Get-HotFix`, maior `InstalledOn` | 40 dias ou menos | Critério meu |
| SIS-05 | `Get-WindowsOptionalFeature -Online`, recurso `MicrosoftWindowsPowerShellV2Root` | ausente ou desativado | ATT&CK T1689 (*Downgrade Attack*) |

## Registro de eventos

| Id | O que é lido | OK quando | Origem do critério |
|---|---|---|---|
| LOG-01 | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | 1 | Microsoft: *about_Logging* (Windows PowerShell 5.1), evento 4104 |
| LOG-02 | `Get-WinEvent -ListLog Security`, `MaximumSizeInBytes` | 192 MB ou mais | Critério meu |

## Motivo dos critérios meus

- **CONTA-08, 900 segundos.** A documentação da Microsoft não fixa um valor e deixa a decisão
  para o uso do computador. Quinze minutos é um limite que o usuário tolera e que ainda reduz o
  tempo de uma máquina destravada sem ninguém por perto.
- **SIS-03, 7 dias.** Com o Windows Update funcionando, o Defender busca definições novas
  sozinho. Uma semana sem atualização indica que algo está bloqueando a busca, e não só um
  atraso de um ou dois dias.
- **SIS-04, 40 dias.** As correções de segurança saem uma vez por mês. Quarenta dias cobrem um
  ciclo mensal com folga para a instalação; passar disso significa ter perdido pelo menos um.
- **LOG-02, 192 MB.** O objetivo é ter histórico suficiente para investigar um incidente
  descoberto dias depois. Com pouco espaço, num computador com muitos logons, os eventos antigos
  são sobrescritos antes disso. O valor certo depende do volume de eventos de cada máquina; se
  houver coletor central, o tamanho local importa menos.

## Leituras que exigem administrador

`Get-BitLockerVolume`, `Get-WindowsOptionalFeature -Online` e `Get-WinEvent -ListLog Security`
devolvem acesso negado sem elevação. Por isso SIS-01, SIS-05 e LOG-02 são marcadas como
`RequerAdmin` e nem são executadas numa sessão comum: aparecem como `REQUER_ADMIN` em vez de um
erro de leitura.
