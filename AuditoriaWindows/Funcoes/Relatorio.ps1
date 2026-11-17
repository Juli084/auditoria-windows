$script:RotuloEstado = @{
    OK             = 'OK'
    FALHA          = 'Falha'
    NAO_VERIFICADO = 'Não verificado'
    REQUER_ADMIN   = 'Requer administrador'
}
$script:RotuloSeveridade = @{
    alta  = 'Alta'
    media = 'Média'
    baixa = 'Baixa'
}

function ConvertTo-TextoHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Texto)
    return [System.Net.WebUtility]::HtmlEncode([string]$Texto)
}

function ConvertTo-DataUtc {
    # GeradoEm é texto ISO 8601 na auditoria recém-criada. Lido de volta com
    # ConvertFrom-Json no PowerShell 7, ele já chega como DateTime.
    [CmdletBinding()]
    [OutputType([datetime])]
    param([Parameter(Mandatory)] [object] $Valor)
    if ($Valor -is [datetime]) {
        return $Valor.ToUniversalTime()
    }
    return [datetime]::Parse(
        [string]$Valor,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    ).ToUniversalTime()
}

function ConvertTo-HtmlAuditoria {
    <#
    .SYNOPSIS
    Gera um relatório HTML autocontido, sem scripts e sem recursos externos.

    .DESCRIPTION
    Aceita o objeto de Invoke-AuditoriaWindows ou o JSON salvo, lido com
    ConvertFrom-Json. Todo texto vindo da auditoria passa por codificação HTML.

    .EXAMPLE
    Get-Content .\relatorios\auditoria.json -Raw | ConvertFrom-Json | ConvertTo-HtmlAuditoria
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object] $Auditoria
    )
    process {
        $ordemEstado = @{ FALHA = 0; REQUER_ADMIN = 1; NAO_VERIFICADO = 2; OK = 3 }
        $ordemSeveridade = @{ alta = 0; media = 1; baixa = 2 }
        $verificacoes = @($Auditoria.Verificacoes) | Sort-Object -Property @(
            @{ Expression = { $ordemEstado[$_.Estado] } }
            @{ Expression = { $ordemSeveridade[$_.Severidade] } }
            @{ Expression = { $_.Id } }
        )

        $data = (ConvertTo-DataUtc -Valor $Auditoria.GeradoEm).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
        $sistema = 'não identificado'
        if ($null -ne $Auditoria.Sistema) {
            $sistema = '{0} (build {1})' -f $Auditoria.Sistema.Nome, $Auditoria.Sistema.Build
        }
        $privilegio = if ($Auditoria.ExecutadoComoAdministrador) { 'administrador' } else { 'usuário comum' }

        $html = New-Object -TypeName System.Text.StringBuilder
        [void]$html.AppendLine('<!doctype html>')
        [void]$html.AppendLine('<html lang="pt-BR">')
        [void]$html.AppendLine('<head>')
        [void]$html.AppendLine('<meta charset="utf-8">')
        [void]$html.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
        [void]$html.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
        [void]$html.AppendLine('<meta name="referrer" content="no-referrer">')
        [void]$html.AppendLine(('<title>Auditoria do Windows: {0}</title>' -f (ConvertTo-TextoHtml $Auditoria.Computador)))
        [void]$html.AppendLine('<style>')
        [void]$html.AppendLine($script:EstiloRelatorio)
        [void]$html.AppendLine('</style>')
        [void]$html.AppendLine('</head>')
        [void]$html.AppendLine('<body>')
        [void]$html.AppendLine('<main>')
        [void]$html.AppendLine('<header>')
        [void]$html.AppendLine('<h1>Auditoria de configuração do Windows</h1>')
        [void]$html.AppendLine('<dl class="dados">')
        [void]$html.AppendLine(('<div><dt>Computador</dt><dd>{0}</dd></div>' -f (ConvertTo-TextoHtml $Auditoria.Computador)))
        [void]$html.AppendLine(('<div><dt>Sistema</dt><dd>{0}</dd></div>' -f (ConvertTo-TextoHtml $sistema)))
        [void]$html.AppendLine(('<div><dt>Gerado em</dt><dd>{0} UTC</dd></div>' -f (ConvertTo-TextoHtml $data)))
        [void]$html.AppendLine(('<div><dt>Executado como</dt><dd>{0}</dd></div>' -f (ConvertTo-TextoHtml $privilegio)))
        [void]$html.AppendLine(('<div><dt>Versão</dt><dd>auditoria-windows {0}</dd></div>' -f (ConvertTo-TextoHtml $Auditoria.Versao)))
        [void]$html.AppendLine('</dl>')
        [void]$html.AppendLine('</header>')

        [void]$html.AppendLine('<section aria-label="Resumo"><ul class="resumo">')
        foreach ($estado in 'FALHA', 'REQUER_ADMIN', 'NAO_VERIFICADO', 'OK') {
            $quantidade = $Auditoria.Resumo.$estado
            [void]$html.AppendLine(('<li class="estado-{0}"><span class="rotulo">{2}</span><span class="numero">{1}</span></li>' -f $estado.ToLowerInvariant(), [int]$quantidade, (ConvertTo-TextoHtml $script:RotuloEstado[$estado])))
        }
        [void]$html.AppendLine('</ul></section>')

        if ($Auditoria.Resumo.REQUER_ADMIN -gt 0) {
            [void]$html.AppendLine('<p class="aviso">Algumas verificações não foram lidas porque a auditoria rodou sem privilégio de administrador.</p>')
        }

        [void]$html.AppendLine('<section aria-label="Verificações">')
        foreach ($item in $verificacoes) {
            [void]$html.AppendLine(('<article class="verificacao estado-{0}">' -f ([string]$item.Estado).ToLowerInvariant()))
            [void]$html.AppendLine('<div class="linha">')
            [void]$html.AppendLine(('<span class="selo">{0}</span>' -f (ConvertTo-TextoHtml $script:RotuloEstado[[string]$item.Estado])))
            [void]$html.AppendLine(('<h2><span class="id">{0}</span> {1}</h2>' -f (ConvertTo-TextoHtml $item.Id), (ConvertTo-TextoHtml $item.Titulo)))
            [void]$html.AppendLine(('<span class="severidade">Severidade {0}</span>' -f (ConvertTo-TextoHtml $script:RotuloSeveridade[[string]$item.Severidade])))
            [void]$html.AppendLine('</div>')
            [void]$html.AppendLine('<dl class="valores">')
            [void]$html.AppendLine(('<div><dt>Encontrado</dt><dd>{0}</dd></div>' -f (ConvertTo-TextoHtml $item.Encontrado)))
            [void]$html.AppendLine(('<div><dt>Esperado</dt><dd>{0}</dd></div>' -f (ConvertTo-TextoHtml $item.Esperado)))
            [void]$html.AppendLine('</dl>')
            [void]$html.AppendLine('<details>')
            [void]$html.AppendLine('<summary>Por que importa e como corrigir</summary>')
            [void]$html.AppendLine(('<p>{0}</p>' -f (ConvertTo-TextoHtml $item.Motivo)))
            [void]$html.AppendLine(('<p><strong>Recomendação:</strong> {0}</p>' -f (ConvertTo-TextoHtml $item.Recomendacao)))
            $links = New-Object -TypeName System.Collections.Generic.List[string]
            foreach ($tecnica in @($item.Attack)) {
                $endereco = 'https://attack.mitre.org/techniques/{0}/' -f ([string]$tecnica).Replace('.', '/')
                $links.Add(('<a href="{0}">ATT&amp;CK {1}</a>' -f (ConvertTo-TextoHtml $endereco), (ConvertTo-TextoHtml $tecnica)))
            }
            foreach ($referencia in @($item.Referencias)) {
                $links.Add(('<a href="{0}">{0}</a>' -f (ConvertTo-TextoHtml $referencia)))
            }
            if ($links.Count -gt 0) {
                [void]$html.AppendLine(('<p class="referencias">{0}</p>' -f ($links -join '<br>')))
            }
            [void]$html.AppendLine('</details>')
            [void]$html.AppendLine('</article>')
        }
        [void]$html.AppendLine('</section>')
        [void]$html.AppendLine('<footer><p>Relatório gerado só com leituras: a ferramenta não altera nenhuma configuração.</p></footer>')
        [void]$html.AppendLine('</main>')
        [void]$html.AppendLine('</body>')
        [void]$html.AppendLine('</html>')
        $html.ToString()
    }
}

function Export-RelatorioAuditoria {
    <#
    .SYNOPSIS
    Grava a auditoria em JSON e, se não for pedido o contrário, em HTML.

    .DESCRIPTION
    Os arquivos são gravados em UTF-8 sem BOM, com o nome do computador e o
    horário UTC da auditoria. Devolve os caminhos gravados.

    .EXAMPLE
    Invoke-AuditoriaWindows | Export-RelatorioAuditoria -Pasta .\relatorios
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object] $Auditoria,
        [Parameter(Mandatory)] [string] $Pasta,
        [switch] $SemHtml
    )
    process {
        if (-not (Test-Path -LiteralPath $Pasta -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $Pasta -Force
        }
        # Caminho absoluto: os métodos de System.IO resolvem caminhos relativos
        # pelo diretório do processo, não pela pasta atual do PowerShell.
        $destino = (Resolve-Path -LiteralPath $Pasta).ProviderPath

        $computador = [string]$Auditoria.Computador -replace '[^A-Za-z0-9_-]', '_'
        if (-not $computador) {
            $computador = 'computador'
        }
        $momento = (ConvertTo-DataUtc -Valor $Auditoria.GeradoEm).ToString('yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture)
        $base = Join-Path -Path $destino -ChildPath ('auditoria-{0}-{1}' -f $computador, $momento)
        $utf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false

        $caminhoJson = "$base.json"
        [System.IO.File]::WriteAllText($caminhoJson, (ConvertTo-Json -InputObject $Auditoria -Depth 6), $utf8)

        $caminhoHtml = $null
        if (-not $SemHtml) {
            $caminhoHtml = "$base.html"
            [System.IO.File]::WriteAllText($caminhoHtml, (ConvertTo-HtmlAuditoria -Auditoria $Auditoria), $utf8)
        }

        [pscustomobject]@{
            Json = $caminhoJson
            Html = $caminhoHtml
        }
    }
}

$script:EstiloRelatorio = @'
:root {
  --fundo: #f6f7f9;
  --papel: #ffffff;
  --texto: #1c2430;
  --suave: #5a6577;
  --borda: #d9dee6;
  --falha: #b42318;
  --falha-fundo: #fdecea;
  --admin: #8a4b00;
  --admin-fundo: #fff4e0;
  --nao: #475467;
  --nao-fundo: #eef1f5;
  --ok: #1e6b3a;
  --ok-fundo: #e7f5ec;
  --link: #1d4ed8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fundo: #12161c;
    --papel: #1b2129;
    --texto: #e6e9ee;
    --suave: #a3adbb;
    --borda: #303845;
    --falha: #ff8a80;
    --falha-fundo: #3a1d1b;
    --admin: #ffc070;
    --admin-fundo: #382a14;
    --nao: #c3cad5;
    --nao-fundo: #262d37;
    --ok: #7bd99a;
    --ok-fundo: #18301f;
    --link: #93b4ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--fundo); color: var(--texto); font: 15px/1.5 "Segoe UI", system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.5rem; margin: 0 0 12px; }
h2 { font-size: 1rem; margin: 0; flex: 1 1 auto; }
a { color: var(--link); word-break: break-all; }
.dados { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px 16px; margin: 0 0 20px; }
.dados dt, .valores dt { color: var(--suave); font-size: .8rem; }
.dados dd, .valores dd { margin: 0; }
.resumo { list-style: none; padding: 0; margin: 0 0 16px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.resumo li { padding: 10px 12px; border-radius: 8px; border: 1px solid var(--borda); background: var(--papel); }
.resumo .rotulo { display: block; color: var(--suave); font-size: .8rem; }
.numero { display: block; font-size: 1.6rem; font-weight: 700; line-height: 1.2; }
.aviso { background: var(--admin-fundo); color: var(--admin); padding: 10px 12px; border-radius: 8px; }
.verificacao { background: var(--papel); border: 1px solid var(--borda); border-left-width: 5px; border-radius: 8px; padding: 12px 14px; margin: 0 0 10px; }
.linha { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 12px; }
.id { color: var(--suave); font-weight: 600; margin-right: 4px; }
.selo { font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; padding: 2px 8px; border-radius: 999px; }
.severidade { color: var(--suave); font-size: .85rem; }
.valores { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 16px; margin: 10px 0 6px; }
details summary { cursor: pointer; color: var(--suave); font-size: .9rem; }
details p { margin: 8px 0; }
.referencias { font-size: .85rem; }
.estado-falha { border-left-color: var(--falha); }
.estado-falha .selo { background: var(--falha-fundo); color: var(--falha); }
.estado-requer_admin { border-left-color: var(--admin); }
.estado-requer_admin .selo { background: var(--admin-fundo); color: var(--admin); }
.estado-nao_verificado { border-left-color: var(--nao); }
.estado-nao_verificado .selo { background: var(--nao-fundo); color: var(--nao); }
.estado-ok { border-left-color: var(--ok); }
.estado-ok .selo { background: var(--ok-fundo); color: var(--ok); }
.resumo .estado-falha .numero { color: var(--falha); }
.resumo .estado-requer_admin .numero { color: var(--admin); }
.resumo .estado-ok .numero { color: var(--ok); }
footer { color: var(--suave); font-size: .85rem; margin-top: 24px; }
@media (max-width: 560px) { .valores { grid-template-columns: 1fr; } }
@media print { body { background: #fff; } .verificacao { break-inside: avoid; } }
'@
