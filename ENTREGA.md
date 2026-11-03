# Entrega — Estação Cofre (Segurança, Autenticação e Criptografia)

**Aluno:** Kauã Fardin
**Turma:** AMF 2026-02
**Prefixo MQTT (`NOME`):** `sis1a/kaua/`
**Link do Worker:** `https://iot-d1.kauafardin2004.workers.dev`

---

## Evidências (prints)

### Passo 1 — Antes de trancar

Para pegar o "antes" eu usei o histórico de versões da Cloudflare: fiz rollback para a versão
`0b288739` (o Worker da atividade de D1), rodei o ataque, e voltei para a versão nova.

![POST /insert sem credencial devolvendo 200](prints/passo1-insert-aberto.png)

Sem API key, sem assinatura, sem nada: **HTTP 200 OK: temp=999**. E o valor entrou no banco:

![O 999 gravado no banco](prints/passo1-999-no-banco.png)

`999 °C` é impossível para temperatura ambiente, e mesmo assim o Worker antigo gravou. Ele não
tinha autenticação nem validação de faixa.

- `cofre.html` em `ws :8080`, mostrando estações da turma **LEGÍVEIS**:

> Não consegui este print. A página conecta normal em `ws://test.mosquitto.org:8080/mqtt` e assina
> `sis1a/#`, mas nenhuma estação da turma estava publicando na hora. Publicar uma estação falsa só
> para a foto seria inventar a evidência.

### Passo 3 — Camada 2 (API key)

![Ataques com a camada 2 ligada](prints/passo3e5-ataques.png)

`Falso` e `SemChave` → **401**. `ComChave` → **200**. A camada 2 funciona.

### Passo 4 — Camada 1 (TLS)

![Serial com NTP e TLS](prints/passo4-serial-ntp-tls.png)

```
[WiFi] conectando...... ok | IP=10.10.0.2 | RSSI=-96 dBm
[NTP]  sincronizando relogio............. ok (1793147907)
[MQTT] conectando em test.mosquitto.org:8885 (TLS + login)... falhou rc=-2 | TLS: UNKNOWN ERROR CODE (0050)
```

O `setCACert()` está ativo nas duas conexões, o NTP sincroniza (sem isso toda assinatura seria
recusada por `expirada`) e o MQTT vai mesmo pela **8885** com TLS. Mas o handshake não fecha, então
não tenho um `200 OK` para mostrar.

O código `0050` é `MBEDTLS_ERR_NET_CONN_RESET`: a conexão cai no transporte, antes da validação do
certificado. Não é CA errada — isso daria `X509 - Certificate verification failed`.

**Teste que isolou a causa.** Escrevi uma função `provaTLS()` que faz um `GET /resumo` (rota de
leitura, não grava nada) e chamei duas vezes no `setup()`: uma com a CA certa e outra com a errada.

![Autoteste de TLS](prints/passo4-tls-gateway-wokwi.png)

```
[TLS CA certa ] GET /resumo -> -1
                erro: UNKNOWN ERROR CODE (0050)
```

O HTTPS para a **Cloudflare** falha com o mesmo erro do MQTT. Ou seja, não é o broker bloqueando:
o gateway de rede do Wokwi não completa conexão TLS nenhuma.

Conferi da minha máquina, no mesmo horário, para descartar que o problema fosse meu:

| Verificação | Resultado |
|---|---|
| `GET /resumo` no meu Worker | 200, responde normal |
| TLS em `test.mosquitto.org:8883` e `:8885` | handshake TLS 1.3 ok |
| CA do Mosquitto no `certificados.h` | válida até 07/06/2030 |

Worker no ar, broker no ar, certificados certos, relógio certo. O que não funciona é a saída de
rede do simulador.

- Serial com a **CA errada**: falha de TLS (`X509 - Certificate verification failed`):

> Não consegui. Esse teste compara um handshake que funciona com um que falha, e aqui nenhum dos
> dois completa — os dois param no mesmo ponto, antes do X509.

### Passos 5 e 6 — Camada 3 (HMAC + anti-replay)

**Antes** (`EXIGIR_ASSINATURA = nao`): é o mesmo print do Passo 3. Com só a API key ligada,
`Adulterado` gravou **temp=45** assinado como 25.0, `Replay` passou nas duas vezes e `Atrasado`
também passou.

**Depois** (`EXIGIR_ASSINATURA = sim`):

![Todos os ataques recusados](prints/passo6-depois.png)

Mesmo comando, mesma chave, mesmo Worker. Mudou uma variável:

| Teste | Antes | Depois |
|---|---|---|
| `ComChave` (sem assinar) | 200 | **401** assinatura invalida |
| `Adulterado` | 200 `temp=45` | **401** assinatura invalida |
| `Valido` | 200 | 200 |
| `Replay` 1ª vez | 200 | 200 |
| `Replay` 2ª vez | 200 | **401** replay |
| `Atrasado` | 200 | **401** expirada |

O `Valido` continuar em 200 é tão importante quanto os 401: mostra que a tranca não quebrou o uso
normal.

**Tentativas recusadas:** estão no rodapé do print acima, com os quatro motivos diferentes
(`sem API key`, `assinatura invalida`, `replay`, `expirada`), cada um com IP e horário. O IP é o
meu porque o atacante do exercício sou eu.

### Passo 7 — Camada 4 (cofre AES-GCM) — sem evidência

Depende do ESP32 publicar em `sis1a/kaua/cofre`, e isso precisa do MQTT conectado. Ver o Passo 4.

### Passo 8 — Comandos assinados — sem evidência

Mesma causa: o tópico de comando é MQTT. O `aoReceber()` está escrito e valida assinatura, janela
de 30 s e replay, mas não chegou a rodar contra o broker.

---

## O que mudei no código

**1. `DHTTYPE` de `DHT11` para `DHT22`.** O Wokwi só tem o DHT22. Com `DHT11` a leitura voltava
`nan` e o `loop()` abortava antes de mandar qualquer coisa.

**2. Criei o `.gitignore`.** A pasta da atividade veio sem ele, e o README diz que ele já cuida do
`config.h`. Sem isso o primeiro `git add .` subiria as três chaves.

**3. `diagram.json` — duas correções no Serial Monitor.** Faltava declarar
`"serialMonitor": { "display": "always", "newLine": "lf" }`, e os pinos estavam como
`esp:TX0`/`esp:RX0`, que são da placa antiga. A `board-esp32-devkit-c-v4` usa **`esp:TX`/`esp:RX`**.
Com o nome errado os fios iam para pinos que não existem: o sketch imprimia e o painel ficava
vazio, sem nenhum erro.

**4. Tirei os dois laços infinitos do `setup()`.** O original esperava para sempre pelo NTP e para
sempre pelo broker. Se qualquer um falhasse, o `loop()` nunca rodava — e é ele que manda as
leituras. Agora o NTP tem limite de 30 s e o MQTT tenta uma vez, com reconexão a cada 5 min no
`loop()`. Assim as leituras continuam indo pro Worker mesmo com o broker fora.

**5. Adicionei a função `provaTLS()`.** Faz um `GET /resumo` só para exercitar o handshake, com a
CA certa e com a errada. Foi o que permitiu descobrir que o problema era de rede e não de
certificado.

**6. Criei o `scripts/atacar.ps1`.** Ele lê a URL e as chaves do `config.h` e repassa para o
`ataques.ps1`, para nenhuma chave aparecer na linha de comando nem nos prints. No caminho achei um
bug no `ataques.ps1`: a tabela de tentativas sempre saía vazia. O motivo é que o
`Invoke-RestMethod` emite o array JSON como **um único objeto** no pipeline, então o
`Select-Object -First 10 motivo, ip` recebe um item só. Guardando a resposta numa variável antes
de formatar, os registros aparecem.

**7. Nada no `worker.js` nem na `cofre.html`.** Os dois já vinham completos.

---

## Respostas

### 1. No Passo 4 vocês trocaram a CA e a conexão falhou. Por que *falhar* é o comportamento correto? O que aconteceria com `setInsecure()` nessa mesma situação?

Falhar é o certo porque a placa ficou sem como provar com quem estava falando. Se o certificado não
foi assinado por uma CA que o ESP32 conhece, a única resposta segura é recusar. É exatamente isso
que um man-in-the-middle provocaria: ele apresenta um certificado assinado por ele mesmo, e o
cliente percebe.

Com `setInsecure()` essa conferência é desligada. O canal continua cifrado, mas cifrado **com o
atacante**: ele termina o TLS do nosso lado, lê e altera tudo em claro, e abre outro TLS com o
servidor real. O ESP32 imprime `200 OK` e segue entregando a API key e as leituras na mão dele. É o
pior caso, porque parece que está tudo funcionando.

### 2. O TLS já cifra o caminho até o broker. Por que, mesmo assim, a temperatura aparecia legível para a turma no Passo 1, e por que o AES-GCM resolve isso?

Porque o TLS protege o trecho, não a mensagem. O broker é uma das pontas: ele decifra para poder
rotear e republica em claro para todo mundo inscrito em `sis1a/#`. Como o `test.mosquitto.org` é
público, "todo mundo" é a turma inteira. Trocar para `wss://` não mudaria isso.

O AES-GCM muda **o que** é protegido: o ESP32 cifra o payload antes de publicar, e só quem tem a
chave decifra. O broker passa a ver só `{"iv":"...","dados":"..."}`. É a diferença entre mandar um
cartão-postal dentro de um túnel blindado e mandar uma carta lacrada. A tag de 16 bytes ainda
garante que, se mexerem em 1 bit, a página recusa abrir em vez de mostrar valor errado.

### 3. Comparem API key e assinatura HMAC: o que um atacante consegue fazer se capturar *uma* requisição de cada tipo?

A diferença é o que viaja: a API key é uma senha que viaja, a assinatura é uma prova que viaja.

Capturando uma requisição **com API key**, ele tem o segredo inteiro, porque a chave vai no
cabeçalho. Com uma captura ele monta qualquer requisição nova, para sempre, até a chave ser trocada.

Capturando uma **com assinatura HMAC**, ele tem o resultado de uma conta que só a chave produz, mas
não a chave. Consegue reenviar exatamente aquele corpo (replay) e nada mais. Mudar `25.0` para
`45.0` quebra a assinatura, e até o replay morre nas duas defesas do Worker: o `ts` sai da janela de
60 s e a assinatura já está na tabela `assinaturas_usadas`.

### 4. O `ts` vai *dentro* do corpo assinado. O que daria errado se ele fosse num cabeçalho separado, fora da assinatura?

O atacante capturaria uma requisição válida, manteria corpo e assinatura intactos (a assinatura
continua batendo, porque o corpo não mudou) e trocaria só o cabeçalho para o horário atual. A
janela de 60 s viraria enfeite.

A tabela `assinaturas_usadas` ainda pegaria o replay imediato, mas o Worker apaga dela o que tem
mais de 5 min. Bastaria esperar 6 minutos: a assinatura já saiu da tabela, o horário é novo, e
passa. A regra geral é que tudo que o servidor usa para decidir precisa estar coberto pela
assinatura.

### 5. Por que o Worker faz `request.text()` e assina o texto cru, em vez de fazer `request.json()` e montar o JSON de novo pra conferir?

Porque HMAC assina bytes, não significado. `{"valor":27.8}` e `{ "valor": 27.8 }` são o mesmo objeto
e dois textos diferentes, com HMACs diferentes.

Se o Worker remontasse o JSON, estaria assinando a versão dele. Qualquer diferença de serialização
derrubaria leituras legítimas com 401 — no nosso caso, o ESP32 monta com `String(valor, 1)`, que
escreve `24.0`, enquanto o `JSON.stringify` escreveria `24`.

Tem também o lado da segurança: normalizar antes de verificar abre porta para ambiguidade, como um
corpo com a chave repetida. Por isso o `worker.js` lê o texto cru primeiro e só faz `JSON.parse`
depois que a autenticação passa.

### 6. As rotas `/list` e `/resumo` continuam abertas. Isso é problema? Para que tipo de dado (pensem no Projeto Final de vocês) passaria a ser?

Nesta atividade não é grande problema: é temperatura de uma sala. Mas já incomoda em dois pontos.
Primeiro, metadado vaza mesmo sem o valor importar — quem tem a URL sabe quando a estação liga e
quando parou. Segundo, nada limita requisições, então dá para queimar a cota do Worker.

Passa a ser sério quando o dado fala de pessoas. No meu Projeto Final, um sensor de presença, o
histórico de ocupação diz a que horas a sala fica vazia. Isso é informação para arrombamento, não
telemetria. A correção é barata: o `autenticar()` já foi feito para ser reaproveitado em qualquer
rota, como já acontece no `/tentativas`, que está protegido porque guarda IP.

### 7. A chave AES foi colada à mão na página. Como resolver isso num produto com mil dispositivos vendidos?

Colar à mão funciona com uma placa. Com mil é inviável, e se a chave fosse a mesma nos mil, vazar de
um vazaria de todos.

A solução é uma chave por dispositivo, entregue com criptografia assimétrica. Na fábrica cada
dispositivo gera seu par de chaves e guarda a privada em área protegida (eFuse, secure element); só
a pública sai. O app pede a chave ao servidor, que a entrega cifrada com a pública — quem
interceptar não abre. E a chave AES passa a ser de sessão: curta, rotacionada, revogável
individualmente.

Na prática não se escreve isso à mão. Usa-se TLS mútuo (certificado de cliente por dispositivo) ou
um serviço de provisionamento pronto, que já resolvem identidade, rotação e revogação.

### 8. No seu Projeto Final, qual é o pior estrago que alguém faria sem as camadas de hoje? Qual camada vocês vão levar pra lá, e por quê?

Meu Projeto Final é o sensor de ocupação e desperdício de luz: um PIR detecta movimento e um LDR
mede a luz, os dois mandam para o Worker `sensor-sala`. A rota `/desperdicio` cruza os dois e mostra
luz acesa sem movimento. Não tem atuador.

Como não tem relé, o pior caso não é físico, é de privacidade. As rotas `/por-hora` e
`/ultimo-movimento` juntas formam um mapa de ocupação da sala. E a ironia é que o produto do sistema
é justamente a informação "não tem ninguém aqui" — é isso que o `/desperdicio` procura. Para a
faculdade é relatório de economia de energia; para quem quer entrar sem ser visto, é a mesma coisa.

O segundo estrago é dado falso. Sem autenticação na escrita, qualquer um injeta movimento inventado
em `/movimento`. Aí o `/desperdicio` para de acusar desperdício, porque o sistema "vê" movimento o
tempo todo, e o projeto deixa de funcionar parecendo que funciona.

Camadas que vou levar:

| Camada | O que faço | Contra o quê |
|---|---|---|
| 1 — TLS validado | trocar `setInsecure()` por `setCACert()` | man-in-the-middle no Wi-Fi da faculdade |
| 2 — `autenticar()` na escrita | proteger `/movimento` e `/luz` | movimento falso cegando o `/desperdicio` |
| Leitura autenticada | proteger `/por-hora` e `/desperdicio` | o mapa de ocupação da sala |
| Segredo fora do Git | `config.h` no `.gitignore` | chave vazada anula tudo acima |

A prioridade é a camada 1, porque sem ela as outras são entregues de graça: quem está no meio do
caminho lê a chave e vira um cliente legítimo. O comando assinado do Passo 8 não se aplica hoje
porque não tem atuador, mas entra no dia em que o projeto ganhar um relé para apagar a luz sozinho.

---

## Desafios extras (opcional)

Não fiz. Sem MQTT funcionando no simulador, o AAD do AES-GCM e o alarme de tentativas não teriam
como ser testados.

---

**Entrega:** este `ENTREGA.md`, `estacao_cofre.ino`, `worker.js` e `certificados.h`, no GitHub,
**sem o `config.h`**.
