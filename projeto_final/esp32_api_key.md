# Lado ESP32 — mandar a API key (e não vazá-la)

Depois de proteger as rotas do Worker, o ESP32 precisa mandar a chave, senão o
próprio projeto passa a levar 401.

## 1. Crie a aba `config.h` no Wokwi

```cpp
// config.h — SEGREDOS. Não versionar (veja o passo 3).
#define API_KEY "cole-aqui-a-chave-do-Secret-API_KEY"
```

## 2. No `sketch.ino`

Acrescente o include, junto do `certificados.h`:

```cpp
#include "certificados.h"
#include "config.h"
```

E dentro do `postJson()`, junto dos outros `addHeader`:

```cpp
http.addHeader("X-API-Key", API_KEY);
```

## 3. `.gitignore` do repositório do projeto

```
config.h
```

Isso é o requisito 3 do checkpoint. O `certificados.h` fica **de fora** do
`.gitignore` de propósito: certificado de CA é público e faz parte da entrega.

---

## Por que a API key e não a assinatura HMAC?

O checkpoint aceita as duas (*"comando assinado **ou** rota protegida com
`autenticar()`"*). Para este projeto a API key resolve o caso de hoje, que é
impedir escrita de terceiro.

Mas vale saber o que fica de fora: a API key **viaja inteira em toda
requisição**. Se vazar uma vez — num print, num log de proxy, num commit — o
atacante escreve no banco para sempre, até a chave ser trocada. A assinatura
HMAC não tem esse problema, porque o segredo nunca sai do dispositivo: o que
viaja é só a prova de que o corpo foi assinado por quem tem a chave.

Como aqui o canal já é TLS **validado** (`setCACert`), a chave não vaza no
caminho — e é por isso que a camada 1 vem antes de tudo. Sem ela, a API key
seria entregue de bandeja para quem estivesse no meio.

Se o projeto ganhar um relé para apagar a luz sozinho, aí a assinatura passa a
valer a pena: comando que mexe no mundo físico merece `comando|ts|assinatura`,
com janela de tempo e anti-replay, como no Passo 8.
