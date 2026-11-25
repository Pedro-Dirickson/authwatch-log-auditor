# CLAUDE.md — AuthWatch Log Auditor

## Visão Geral do Projeto
Ferramenta CLI leve em Python puro (stdlib) para análise de segurança em logs de autenticação (Linux auth.log e logs de acesso web/API), detectando padrões de força bruta, varredura de usuários e acessos fora de horário comercial.

## Regras de Arquitetura e Código
- Utilizar exclusivamente a biblioteca padrão do Python 3.11+ (`re`, `datetime`, `collections`, `json`, `argparse`, `pathlib`).
- Estrutura modular limpa em `src/authwatch/`:
  - `parser.py`: Extração estruturada de timestamp, IP de origem, usuário e status (`FAILED`/`SUCCESS`) a partir de logs Linux SSH e JSONL de API.
  - `detector.py`: Regras de detecção de incidentes (Brute Force por IP em janela de tempo, User Enumeration com múltiplos usuários inválidos e Off-Hours Login).
  - `reporter.py`: Saída resumida no terminal e exportação de relatório de incidentes em JSON.
  - `cli.py`: Interface de linha de comando com opções `--file`, `--threshold`, `--window` e `--export`.
- Incluir testes unitários com `unittest` em `tests/` e um arquivo `samples/sample_auth.log` realista para demonstração imediata.

## Fluxo de Trabalho Git e Publicação
- Dividir em commits atômicos e semânticos (`feat:`, `docs:`).
- Ao finalizar e validar os testes, criar o repositório público `authwatch-log-auditor` na conta `Pedro-Dirickson` via `gh repo create authwatch-log-auditor --public --source=. --remote=origin --push` e exibir a URL final.
