# DC00.2-P-C3.1-R1

A reprodução independente partiu de um checkout limpo de
`92756b5d12652a9b784ff50ea7bb70e1c1ded577`. Antes das mudanças, o runner
histórico executou os 34 controles com CPython 3.12.14, jsonschema 4.25.1 e
cryptography 46.0.3. A saída foi idêntica, byte a byte, a
`DC00.2-P-C3.1/results.json`. A cópia gerada está em
`baseline-reproduced.json` e tem SHA-256
`6d71bcd8241d8ae5b469bda0407ee06165b03904063d573e7751488065c24b39`.

| Constatação | Verificação da revisão |
| --- | --- |
| R01 | T14.01 executa duas implementações de cobertura sobre as mesmas linhas. O perfil de chamadas Python registra os nós e arestas transitivos executados, e o validador histórico verifica a interseção por propriedade. A mutação usa uma segunda entrada que chama o mesmo leitor transitivo. O escopo é o grafo de chamadas Python exercitado neste caso sintético, na thread corrente. Chamadas nativas, caminhos de código não exercitados e a infraestrutura comum de coleta ficam fora dessa medição. |
| R02 | `anchors.json` fixa os valores de referência usados pela revisão. O manifesto observado é construído a partir dos dados lidos e confrontado com o digest fixo ligado ao gate. Inventário, registro opaco e mapa de link confiáveis são entradas separadas dos dados observados. Os testes alteram fonte, dependência e manifesto com artefato e assinatura correspondentes. O arquivo versionado é a raiz de referência deste teste sintético e as chaves reproduzíveis são públicas por construção. |
| R03 | Duas falhas coexistem no mesmo snapshot de linhas e inventário, verificadas nas duas ordens. Outro manifesto contém simultaneamente assinatura inválida e artefato ausente. As verificações isoladas demonstram as causas, inclusive quando ambas têm código 12. A precedência é independente da ordem e o oráculo de mutação única rejeita o conjunto concorrente. |
| R04 | A instalação do audit hook é confirmada por um evento sentinela do CPython. Uma chamada real a `socket.socket` é interrompida pelo evento `socket.__new__`. As famílias de eventos de criação de processo são exercitadas com `sys.audit`, sem iniciar os processos correspondentes. Uma leitura local verifica o limite de filesystem. O teste injeta ainda um evento de processo interceptado dentro de um caso e exige saída 1 mesmo quando o caso captura a exceção. |
| R05 | T12.04 registra a rejeição 12 por `independent identity` em `validator.methoddef`. O adaptador emite o código 15 do catálogo somente quando a divergência de identidade é de assinatura e uma nova chamada, reparando apenas esse campo, é aceita. T12.05 registra o código 15 retornado diretamente pelo validador histórico para outro extent. |
| R06 | Os 17 oráculos cobrem resultado, motivo e rastro das duas variantes. O teste adversarial remove ou corrompe cada campo de cada rastro e exige rejeição pelo oráculo. |

O audit hook é uma defesa cooperativa limitada aos eventos correspondentes
publicados depois da instalação no intérprete. O relatório distingue
sondas esperadas de eventos inesperados nos controles. A contenção de
código nativo e a observação de operações sem evento dependem do supervisor
externo. Os contratos B05/B06 e os riscos OR00.7 continuam aplicáveis.

Execute da raiz do repositório com as dependências de
`DC00.2-P/requirements.txt` já instaladas.

```sh
python -EB DC00.2-P-C3.1/run.py > /tmp/c31-baseline.json
cmp DC00.2-P-C3.1-R1/baseline-reproduced.json /tmp/c31-baseline.json
python -EB DC00.2-P-C3.1-R1/run.py > /tmp/c31-r1.json
cmp DC00.2-P-C3.1-R1/results.json /tmp/c31-r1.json
python -EB -m unittest discover -s DC00.2-P-C3.1-R1 -v
```

`results.json` registra 34 controles, três cenários concorrentes e oito
sondas do audit hook. `tests.log` registra a suíte adversarial. O catálogo
histórico tem 57 casos, dos quais 17 pertencem a esta execução. Os quatro
estruturais, sete de gate assinado e 29 com requisitos externos estão fora
da execução C3.1-R1. Esta revisão é sintética e preparatória.
