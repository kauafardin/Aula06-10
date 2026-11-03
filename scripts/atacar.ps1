# ================================================================
#  ATALHO para o ataques.ps1 desta estacao.
#
#  Le a URL e as chaves do config.h, entao elas NAO aparecem na
#  linha de comando nem no seu print de tela.
#
#  Uso (na pasta scripts, ou de qualquer lugar com o caminho completo):
#    powershell -ExecutionPolicy Bypass -File .\atacar.ps1
#    powershell -ExecutionPolicy Bypass -File .\atacar.ps1 -Teste Falso
#    powershell -ExecutionPolicy Bypass -File .\atacar.ps1 -Teste Tentativas
#    powershell -ExecutionPolicy Bypass -File .\atacar.ps1 -Url https://outro.workers.dev -SemChaves
#
#  OBS: a listagem de /tentativas e' feita aqui, e nao pela funcao
#  Teste-Tentativas do ataques.ps1, que sempre sai com a tabela vazia.
#  Motivo: o Invoke-RestMethod emite o array JSON como UM objeto no
#  pipeline, em vez de enumerar os N registros. Canalizado direto pro
#  "Select-Object -First 10 motivo, ip, @{...}", o Select ve 1 item so,
#  com motivo/ip sendo arrays, e o calculo de "quando" estoura ao
#  chamar FromUnixTimeMilliseconds num array -> cabecalho sem linhas.
#  A correcao e' guardar a resposta numa variavel antes de formatar.
# ================================================================
param(
  [ValidateSet("Falso","SemChave","ComChave","Valido","Adulterado","Replay","Atrasado","Tentativas","Todos")]
  [string]$Teste = "Todos",
  [string]$Url = "",
  [switch]$SemChaves          # ataca um alvo aberto, sem mandar chave nenhuma
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$cfg = Join-Path $PSScriptRoot "..\esp32\estacao_cofre\config.h"
if (-not (Test-Path $cfg)) { throw "Nao achei o config.h em $cfg" }

function Pega([string]$nome) {
  $linha = Get-Content $cfg | Select-String -Pattern "^#define\s+$nome\s" | Select-Object -First 1
  if (-not $linha) { throw "Nao achei #define $nome no config.h" }
  return $linha.Line.Split('"')[1]
}

if ($Url -eq "") { $Url = Pega "WORKER_URL" }
$Url = $Url.TrimEnd("/")
Write-Host "Alvo: $Url" -ForegroundColor Cyan

# ---- listagem propria do /tentativas (ver OBS no cabecalho) ----
function Listar-Tentativas([string]$chave) {
  Write-Host ""
  Write-Host "== Tentativas recusadas (GET /tentativas) ==" -ForegroundColor Cyan
  try {
    # Guardar numa variavel ANTES de enumerar: o Invoke-RestMethod emite o
    # array JSON como UM objeto no pipeline, nao como N itens.
    $resposta = Invoke-RestMethod -Uri "$Url/tentativas" -Headers @{ "X-API-Key" = $chave } -TimeoutSec 25
    $dados = @($resposta)
  } catch {
    Write-Host "   falhou: $($_.Exception.Message)" -ForegroundColor Red
    return
  }
  if ($dados.Count -eq 0) {
    Write-Host "   (nenhuma tentativa registrada ainda)" -ForegroundColor DarkGray
    return
  }
  $tabela = foreach ($d in ($dados | Select-Object -First 10)) {
    [PSCustomObject]@{
      motivo = $d.motivo
      ip     = $d.ip
      quando = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$d.timestamp).ToLocalTime().ToString("HH:mm:ss")
    }
  }
  $tabela | Format-Table -AutoSize
  Write-Host "   total registrado: $($dados.Count)" -ForegroundColor DarkGray
}

$script = Join-Path $PSScriptRoot "ataques.ps1"

if ($Teste -eq "Tentativas") {
  if ($SemChaves) { throw "O /tentativas exige a API key: rode sem -SemChaves." }
  Listar-Tentativas (Pega "API_KEY")
  exit
}

if ($SemChaves) {
  & $script -Url $Url -Teste $Teste
  exit
}

$api  = Pega "API_KEY"
$hmac = Pega "CHAVE_HMAC"

if ($Teste -ne "Todos") {
  & $script -Url $Url -ApiKey $api -ChaveHmac $hmac -Teste $Teste
  exit
}

# "Todos" na mao, um teste por vez: assim o Teste-Tentativas quebrado do
# ataques.ps1 (que imprime a tabela vazia) nunca chega a rodar, e a
# listagem sai uma vez so, pela Listar-Tentativas daqui.
foreach ($t in @("Falso","SemChave","ComChave","Valido","Adulterado","Replay","Atrasado")) {
  & $script -Url $Url -ApiKey $api -ChaveHmac $hmac -Teste $t
}
Listar-Tentativas $api
