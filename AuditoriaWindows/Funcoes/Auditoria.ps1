function Invoke-AuditoriaWindows {
    <#
    .SYNOPSIS
    Executa todas as verificações e devolve o resultado da auditoria.

    .DESCRIPTION
    Só lê a configuração do computador. Verificações que exigem administrador
    não são executadas quando a sessão não é elevada; aparecem como
    REQUER_ADMIN. Um erro de leitura numa verificação não interrompe as outras:
    ela aparece como NAO_VERIFICADO, com a mensagem do erro.

    .EXAMPLE
    Invoke-AuditoriaWindows | Export-RelatorioAuditoria -Pasta .\relatorios
    #>
    [CmdletBinding()]
    param()

    $administrador = Test-Administrador

    $resultados = foreach ($verificacao in Get-DefinicaoVerificacao) {
        if ($verificacao.RequerAdmin -and -not $administrador) {
            $resultado = New-ResultadoVerificacao REQUER_ADMIN 'Não lido: execute como administrador'
        } else {
            try {
                $resultado = & $verificacao.Avaliar
            } catch {
                $resultado = New-ResultadoVerificacao NAO_VERIFICADO ('Erro na leitura: {0}' -f $_.Exception.Message)
            }
            if ($null -eq $resultado) {
                $resultado = New-ResultadoVerificacao NAO_VERIFICADO 'A verificação não devolveu resultado'
            }
        }
        [pscustomobject]@{
            Id           = $verificacao.Id
            Categoria    = $verificacao.Categoria
            Titulo       = $verificacao.Titulo
            Severidade   = $verificacao.Severidade
            Estado       = $resultado.Estado
            Encontrado   = $resultado.Encontrado
            Esperado     = $verificacao.Esperado
            Motivo       = $verificacao.Motivo
            Recomendacao = $verificacao.Recomendacao
            Attack       = @($verificacao.Attack)
            Referencias  = @($verificacao.Referencias)
        }
    }
    $resultados = @($resultados)

    $resumo = [ordered]@{}
    foreach ($estado in $script:Estados) {
        $resumo[$estado] = @($resultados | Where-Object { $_.Estado -eq $estado }).Count
    }

    try {
        $sistema = Get-InformacaoSistema
    } catch {
        $sistema = $null
    }

    [pscustomobject]@{
        Ferramenta                 = 'auditoria-windows'
        Versao                     = [string]$ExecutionContext.SessionState.Module.Version
        GeradoEm                   = (Get-DataAtual).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        Computador                 = [string]$env:COMPUTERNAME
        Sistema                    = $sistema
        ExecutadoComoAdministrador = [bool]$administrador
        Resumo                     = [pscustomobject]$resumo
        Verificacoes               = $resultados
    }
}
