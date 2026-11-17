# Garante pela análise do código que leitura, verificações e orquestração só
# chamam comandos que não alteram o sistema. A gravação de arquivos fica
# restrita a Relatorio.ps1, que só escreve os relatórios na pasta pedida.

BeforeDiscovery {
    $raiz = Split-Path -Path $PSScriptRoot -Parent
    $arquivos = @('Leitura.ps1', 'Verificacoes.ps1', 'Auditoria.ps1', 'Resultado.ps1') | ForEach-Object {
        @{ Nome = $_; Caminho = Join-Path -Path $raiz -ChildPath "AuditoriaWindows/Funcoes/$_" }
    }
}

Describe 'Somente leitura' {
    It '<Nome> não chama comandos que alteram o sistema' -ForEach $arquivos {
        $tokens = $null
        $erros = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Caminho, [ref]$tokens, [ref]$erros)
        $erros | Should -BeNullOrEmpty

        $verbosProibidos = @(
            'Set', 'Remove', 'Clear', 'Disable', 'Enable', 'Install', 'Uninstall', 'Stop', 'Start',
            'Restart', 'Suspend', 'Resume', 'Rename', 'Move', 'Copy', 'Update', 'Register', 'Unregister',
            'Add', 'Write', 'Out', 'Export', 'Invoke', 'New', 'Reset', 'Grant', 'Revoke', 'Block', 'Unblock'
        )
        # Exceções com motivo: Add-Type compila a chamada à API de leitura de
        # política; New-Object e New-ResultadoVerificacao criam objetos em memória.
        $permitidos = @('Add-Type', 'New-Object', 'New-ResultadoVerificacao')

        $comandos = $ast.FindAll({ param($no) $no -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } |
            Where-Object { $_ }
        $proibidos = $comandos | Where-Object {
            ($_ -notin $permitidos) -and ($verbosProibidos -contains ($_ -split '-', 2)[0])
        }
        $proibidos | Should -BeNullOrEmpty
    }
}
