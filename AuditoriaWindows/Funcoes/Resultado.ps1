# Estados possíveis de uma verificação.
#
# OK              a configuração está como esperado
# FALHA           a configuração está diferente do esperado
# NAO_VERIFICADO  não deu para concluir (recurso inexistente, outro antivírus, erro de leitura)
# REQUER_ADMIN    a leitura exige administrador e a auditoria rodou sem isso

$script:Estados = @('OK', 'FALHA', 'NAO_VERIFICADO', 'REQUER_ADMIN')
$script:Severidades = @('alta', 'media', 'baixa')

function New-ResultadoVerificacao {
    # Só monta um objeto em memória; não muda estado nenhum.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('OK', 'FALHA', 'NAO_VERIFICADO', 'REQUER_ADMIN')]
        [string] $Estado,

        [Parameter(Mandatory, Position = 1)]
        [AllowEmptyString()]
        [string] $Encontrado
    )
    [pscustomobject]@{
        Estado     = $Estado
        Encontrado = $Encontrado
    }
}
