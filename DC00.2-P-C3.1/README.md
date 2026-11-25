# DC00.2-P-C3.1

O runner usa diretamente os módulos históricos de P, C1 e C2 para avaliar os
17 casos `legacy_data` do plano C2. Cada caso tem um controle positivo e um
vetor do catálogo, totalizando 34 controles. T10-A.01 é um segundo controle de
leitura opaca, com código esperado zero para os dois vetores.

Os vetores associam cada ID a um validador fixo e usam fixtures versionadas,
inventário assinado e manifesto vinculado a um gate de teste. As chaves
Ed25519, o relógio e os envelopes são determinísticos e exclusivos dos testes
sintéticos. T06 verifica assinatura forjada, substituição conjunta contra uma
âncora fixa, chave JSON duplicada em envelope assinado e referência sem
artefato disponível. T12.04 altera a assinatura do MethodDef. T12.05 mantém a
identidade declarada, deslocando a extensão para outra sobrecarga válida.

Com as dependências de `DC00.2-P/requirements.txt` já disponíveis, execute
a partir da raiz do repositório. O runner bloqueia eventos de rede e criação
de processos auditados pelo CPython e retorna código diferente de zero se
algum controle falhar ou se houver tentativa bloqueada.

```sh
python -EB DC00.2-P-C3.1/run.py > /tmp/c31-results.json
diff -u DC00.2-P-C3.1/results.json /tmp/c31-results.json
```

O JSON registra as versões do ambiente, os códigos observados, o motivo de
cada rejeição e os dados usados pelos oráculos. Use as versões registradas
para reproduzir o arquivo byte a byte. O bloqueio de eventos é próprio do
runner e tem alcance limitado às operações auditadas pelo CPython. A execução
se limita aos 17 casos pedidos. O plano histórico inclui outros quatro casos
estruturais, sete de gate assinado e 29 com requisitos de evidência externa.
