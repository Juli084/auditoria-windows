# auditoria-windows

Script PowerShell que confere 20 itens básicos de segurança de um computador Windows e gera um
relatório em JSON e HTML. Só lê: não altera registro, política, serviço nem conta.

Fiz para o cenário de pequena empresa, onde muitas vezes não há domínio, política de grupo nem
ferramenta de gestão, e alguém precisa saber em poucos minutos como cada máquina está configurada.
Roda no Windows PowerShell 5.1, que já vem no Windows 10 e 11, sem instalar nada.

## O que verifica

| Id | Verificação | Severidade | Precisa de administrador |
|---|---|---|---|
| CONTA-01 | Conta Convidado desativada | média | não |
| CONTA-02 | Administrador interno desativado | média | não |
| CONTA-03 | Senha local com pelo menos 8 caracteres | média | não |
| CONTA-04 | Bloqueio de conta entre 1 e 10 tentativas inválidas | média | não |
| CONTA-05 | UAC ativo | alta | não |
| CONTA-06 | Elevação de administrador pede confirmação | alta | não |
| CONTA-07 | WDigest não guarda senhas na memória | alta | não |
| CONTA-08 | Tela bloqueia após até 15 minutos sem uso | baixa | não |
| REDE-01 | Firewall ativo nos perfis Domain, Private e Public | alta | não |
| REDE-02 | SMBv1 desativado no servidor | alta | não |
| REDE-03 | Servidor SMB exige assinatura | média | não |
| REDE-04 | LLMNR desativado | média | não |
| REDE-05 | Área de Trabalho Remota desativada ou com NLA | alta | não |
| SIS-01 | Disco do sistema protegido por BitLocker | alta | sim |
| SIS-02 | Defender com proteção em tempo real | alta | não |
| SIS-03 | Definições do Defender com até 7 dias | média | não |
| SIS-04 | Atualização do Windows nos últimos 40 dias | alta | não |
| SIS-05 | PowerShell 2.0 removido | média | sim |
| LOG-01 | Registro de blocos de script do PowerShell ativo | média | não |
| LOG-02 | Log de Segurança com pelo menos 192 MB | baixa | sim |

O que cada uma lê, o critério usado e a origem do critério estão em
[docs/verificacoes.md](docs/verificacoes.md). Cada item do relatório explica por que importa,
como corrigir e, quando se aplica, a técnica do MITRE ATT&CK que a configuração dificulta.

## Como usar

```powershell
git clone https://github.com/Juli084/auditoria-windows.git
cd auditoria-windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Auditoria.ps1
```

O `-ExecutionPolicy Bypass` vale só para essa execução e não muda a política do computador. Se
você baixar o ZIP em vez de clonar, desbloqueie os arquivos antes com
`Get-ChildItem -Recurse | Unblock-File`.

Sem privilégio de administrador, as três verificações que dependem dele aparecem como "requer
administrador" e as outras 17 rodam normalmente. Para ler todas, abra o PowerShell como
administrador.

A tela mostra a tabela de resultados, e os relatórios vão para a pasta `relatorios`:

- `auditoria-<computador>-<data UTC>.json`, para guardar, comparar ou enviar a outro sistema;
- `auditoria-<computador>-<data UTC>.html`, um arquivo único, sem scripts e sem recursos
  externos, que abre em qualquer navegador.

Opções: `-Pasta <caminho>` muda o destino e `-SemHtml` grava só o JSON.

O módulo também pode ser usado direto:

```powershell
Import-Module .\AuditoriaWindows\AuditoriaWindows.psd1
$auditoria = Invoke-AuditoriaWindows
$auditoria.Verificacoes | Where-Object Estado -eq 'FALHA'
$auditoria | Export-RelatorioAuditoria -Pasta C:\Auditorias
```

## Estados

| Estado | Significado |
|---|---|
| `OK` | a configuração está como esperado |
| `FALHA` | a configuração está diferente do esperado |
| `NAO_VERIFICADO` | não deu para concluir: recurso inexistente nesta edição, outro antivírus ativo ou erro de leitura (a mensagem vai junto) |
| `REQUER_ADMIN` | a leitura exige administrador e a auditoria rodou sem isso |

Um erro numa verificação não interrompe as outras.

## Como funciona

```
Invoke-Auditoria.ps1            ponto de entrada: roda, mostra e grava
AuditoriaWindows/
  Funcoes/Leitura.ps1           única parte que consulta o sistema
  Funcoes/Verificacoes.ps1      as 20 verificações, cada uma com critério, motivo e correção
  Funcoes/Auditoria.ps1         executa as verificações e monta o resultado
  Funcoes/Relatorio.ps1         JSON e HTML
tests/                          Pester
docs/verificacoes.md            fonte e critério de cada verificação
```

Algumas escolhas:

- **Leitura isolada.** As verificações nunca chamam cmdlets do sistema diretamente, só as
  funções de `Leitura.ps1`. Isso permite testar cada regra com dublês, inclusive fora do Windows.
- **Somente leitura comprovada por teste.** `tests/SomenteLeitura.Tests.ps1` analisa a árvore
  sintática dos arquivos de leitura e verificação e falha se aparecer qualquer comando com verbo
  que altera estado (`Set`, `Remove`, `Disable` e outros).
- **Política de senha pela API do Windows.** O comprimento mínimo e o limite de bloqueio vêm de
  `NetUserModalsGet`, a mesma função que o `net accounts` usa. Interpretar a saída do comando
  quebraria em Windows de outro idioma.
- **Contas pelo SID, não pelo nome.** O Administrador e o Convidado mudam de nome com o idioma e
  podem ser renomeados; o final do SID (`-500` e `-501`) não muda.
- **Firewall pelo `ActiveStore`.** É a configuração em vigor, já somando o que vem de política.
- **Política antes do valor local.** Para RDP e NLA, o valor em `HKLM\SOFTWARE\Policies` tem
  precedência, como no próprio Windows.

## Testes

```powershell
Install-Module Pester -RequiredVersion 6.2.0 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester ./tests -Output Detailed
```

- `Verificacoes.Tests.ps1`: cada verificação com casos que passam, que falham, com valor
  ausente e nos limites (900 e 901 segundos, 7 e 8 dias, 40 e 41 dias, 191 e 192 MB).
- `Auditoria.Tests.ps1`: um computador fictício bem configurado passa nas 20 verificações. Sem
  administrador, as leituras que exigem elevação nem são chamadas. Um erro de leitura vira
  `NAO_VERIFICADO` sem derrubar o resto.
- `Relatorio.Tests.ps1`: o HTML codifica todo texto vindo da auditoria e não carrega nada
  externo. O JSON sai em UTF-8 sem BOM e pode ser lido de volta para gerar o HTML de novo.
- `SomenteLeitura.Tests.ps1`: a verificação de comandos descrita acima.
- `Integracao.Tests.ps1`: execução real, sem dublês. Só roda no Windows.

A integração contínua ([.github/workflows/verificar.yml](.github/workflows/verificar.yml)) roda
num runner Windows do GitHub, no Windows PowerShell 5.1 e no PowerShell 7: PSScriptAnalyzer
sem nenhum aviso, todos os testes, e a auditoria real do próprio runner, guardada como artefato.

## Limitações

- **Política local.** Em computador de domínio, a política de senha das contas do domínio fica
  no controlador de domínio; aqui leio só a política local.
- **Bloqueio de tela.** Leio a política do computador. A proteção de tela configurada por cada
  usuário não entra.
- **LLMNR sem NBT-NS.** O NetBIOS sobre TCP/IP, usado no mesmo tipo de ataque, é configurado
  por interface de rede e ainda não é verificado.
- **Atualizações.** `Get-HotFix` lista as atualizações do sistema operacional. Office, drivers
  e aplicativos da Microsoft Store não entram.
- **Outro antivírus.** Com o Defender em modo passivo, SIS-02 e SIS-03 ficam como
  `NAO_VERIFICADO`, porque a proteção pode estar em outro produto que esta ferramenta não lê.
- **PowerShell 7.** O registro de blocos de script verificado é o do Windows PowerShell 5.1. O
  PowerShell 7 tem configuração própria.
- **Critérios.** Os limites de 8 caracteres e 10 tentativas seguem a documentação da Microsoft.
  Os de 15 minutos, 7 dias, 40 dias e 192 MB são critérios meus, explicados em
  [docs/verificacoes.md](docs/verificacoes.md).
- **Escopo.** São 20 itens escolhidos pelo impacto em pequena empresa, não um benchmark
  completo. Para auditoria formal, use o CIS Benchmark ou a linha de base de segurança da
  Microsoft.

## Privacidade

O relatório contém o nome do computador e a configuração de segurança dele. A ferramenta não
faz nenhuma conexão de rede e só grava os dois arquivos na pasta escolhida. A pasta `relatorios`
está no `.gitignore` para não ser enviada por engano a um repositório.

## Licença

[MIT](LICENSE).
