// ================================================================
//  PATCH de autenticacao para o Worker  sensor-sala
//  (Passo 9 / checkpoint do Projeto Final - requisito 2)
//
//  COMO APLICAR
//  ------------
//  1. Cloudflare -> Workers -> sensor-sala -> Edit code
//  2. Cole TODO este arquivo no FIM do worker.js (depois do
//     "export default { ... }"). Sao so funcoes auxiliares.
//  3. No comeco de CADA rota de ESCRITA (POST /movimento e POST /luz),
//     antes de qualquer env.DB.prepare(...), acrescente:
//
//         const barrado = await autenticar(request, env);
//         if (barrado) return barrado;
//
//  4. Settings -> Variables and Secrets -> Secret  API_KEY
//     (pode ser a mesma chave da atividade, ou uma nova; se for nova,
//      lembre de atualizar o ESP32 tambem)
//  5. Deploy.
//
//  OPCIONAL, mas e' o que eu faria: proteger tambem as rotas de LEITURA
//  /por-hora, /ultimo-movimento e /desperdicio. Elas sao o mapa de
//  ocupacao da sala - dizem a que horas nao tem ninguem la dentro.
// ================================================================

// Devolve null se pode passar, ou a Response de recusa (401).
async function autenticar(request, env) {
  if (!env.API_KEY) {
    return new Response("Configure o Secret API_KEY no Worker", { status: 500 });
  }
  const recebida = request.headers.get("X-API-Key") || "";
  if (!iguais(recebida, env.API_KEY)) {
    return negar(request, env, 401, "sem API key ou API key errada");
  }
  return null;
}

// Comparacao em tempo constante: nao revela ONDE a chave diverge.
// Comparar com === sai mais cedo na primeira diferenca, e a diferenca
// de tempo, medida muitas vezes, vaza a chave caractere a caractere.
function iguais(a, b) {
  if (a.length !== b.length) return false;
  let dif = 0;
  for (let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return dif === 0;
}

// Recusa e registra a tentativa. Nao guarda segredo nenhum: so o motivo,
// o IP e a hora. Se a tabela nao existir, segue recusando do mesmo jeito.
async function negar(request, env, status, motivo) {
  try {
    await env.DB.prepare(
      "INSERT INTO tentativas (motivo, ip, timestamp) VALUES (?, ?, ?)"
    ).bind(motivo, request.headers.get("CF-Connecting-IP") || "?", Date.now()).run();
  } catch (e) { /* tabela ainda nao criada */ }
  return new Response(`Recusado: ${motivo}`, { status });
}

// ----------------------------------------------------------------
//  Tabela de tentativas (rode no console do D1 deste projeto).
//  Opcional: sem ela a autenticacao funciona igual, so nao fica log.
// ----------------------------------------------------------------
//  CREATE TABLE IF NOT EXISTS tentativas (
//    id        INTEGER PRIMARY KEY AUTOINCREMENT,
//    motivo    TEXT    NOT NULL,
//    ip        TEXT,
//    timestamp INTEGER NOT NULL
//  );
