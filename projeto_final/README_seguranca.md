# Trecho para o README do Projeto Final

O Passo 9 pede 3 ou 4 linhas dizendo **qual camada vocês usaram e contra qual
ameaça**. Cole o bloco abaixo no README do repositório do projeto.

---

## Segurança

O ESP32 fala com o Worker por **HTTPS com certificado validado**
(`setCACert(CA_WORKER)`, com a CA pública em `certificados.h`) — não há
`setInsecure()` no projeto. Isso fecha a porta do *man-in-the-middle*: antes,
o canal era cifrado mas a placa não conferia **com quem** estava falando, e
qualquer um na mesma rede podia se passar pelo Worker, ler as leituras e
alterar o que fosse gravado.

As rotas de escrita `POST /movimento` e `POST /luz` passam por `autenticar()`
antes de tocar no banco, com a chave em `X-API-Key` guardada como *Secret* na
Cloudflare. Isso barra a ameaça que mais machucaria este projeto
especificamente: injetar movimento falso. Como a rota `/desperdicio` procura
*luz acesa sem movimento*, basta um atacante inventar movimentos para o
sistema parar de acusar desperdício — e falhar silenciosamente, parecendo que
está funcionando.

Os segredos ficam em `config.h`, que está no `.gitignore`. O `certificados.h`
é versionado de propósito: certificado de CA é público, não é segredo.

**O que ainda não está protegido, e por quê importa:** as rotas de leitura
(`/por-hora`, `/ultimo-movimento`, `/desperdicio`) continuam abertas. Juntas,
elas formam um mapa de ocupação da sala — a que horas enche, a que horas
esvazia. Para a faculdade isso é um relatório de economia de energia; para
quem quer entrar sem ser visto, é a mesma informação. Proteger essas rotas com
o mesmo `autenticar()` é o próximo passo.
