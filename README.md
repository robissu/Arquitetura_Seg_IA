# Arquitetura_Seg_IA

Protótipo desenvolvido no contexto do **TCC de Ciência da Computação de Robson Daniel Marchesan**.

## Descrição

Este projeto implementa uma arquitetura de análise de segurança para **código gerado por inteligência artificial**, com foco na identificação, classificação e interpretação de vulnerabilidades. A proposta apoia o desenvolvimento seguro assistido por IA permitindo:

- analisar código gerado por modelos de linguagem;
- identificar vulnerabilidades por meio de SAST e heurísticas complementares;
- classificar os achados com base em **CWE**, **OWASP** e no Guia GIA produzido no TCC;
- recomendar ações de mitigação e correção estruturadas.

---

## Arquitetura proposta

O protótipo é composto por quatro módulos executados em sequência:

```text
Módulo 1 — Coleta e normalização
           ↓
Módulo 2 — Análise de segurança
           ↓
Módulo 3 — Classificação
           ↓
Módulo 4 — Recomendação
```

---

## Estado atual do desenvolvimento

### Concluído

**Módulo 1 — Coleta e normalização** (`src/collect/normalize.py`)

- remoção de artefatos textuais de saídas de LLM (texto introdutório, conclusivo, cercas de markdown);
- normalização de quebras de linha e codificação UTF-8;
- organização de imports com isort e formatação determinística com Black;
- validação sintática com `ast.parse` — código inválido é bloqueado e marcado;
- extração de metadados estruturais: imports, funções, classes, linhas duplicadas e linhas comentadas;
- detecção de fragmentos incompletos (`...`, comentários de omissão).

**Módulo 2 — Análise de segurança** (`src/analyze/`)

Camada 1 — SAST com Bandit (`sast.py`):

- execução do Bandit via subprocess com saída em JSON;
- captura de severidade, confiança, regra, linha e trecho de contexto de cada achado;
- saída padronizada no formato intermediário unificado.

Camada 2 — Heurísticas complementares (`heuristics.py`):

| ID | O que detecta |
|---|---|
| H001 | `except Exception: pass` ou `except:` sem corpo |
| H002 | `except Exception as e: pass` silencioso |
| H003 | TODO/FIXME em funções com nome sensível de segurança |
| H004 | Função de verificação de acesso que retorna sempre `True` ou `1` |
| H005 | Entrada externa usada diretamente como argumento sem validação |
| H006 | Rota Flask/Django com método sensível sem decorator de autenticação |
| H007 | Rota com parâmetro ID sem checagem de propriedade do recurso (IDOR) |
| H008 | Import de pacote ausente em `requirements.txt` |

**Base de conhecimento** (`data/knowledge_base.json`)

- arquivo JSON com as sete categorias do Guia GIA (GIA-001 a GIA-007);
- cada entrada contém: CWE, OWASP, impacto, exemplos de ocorrência e as três etapas de mitigação (o que verificar, como corrigir, como validar).

### Em desenvolvimento

- **Módulo 3 — Classificação**: associa cada achado ao GIA, CWE e OWASP correspondente.
- **Módulo 4 — Recomendação**: consulta a base de conhecimento e gera o relatório final em JSON.

---

## Estrutura do projeto

```text
Arquitetura_Seg_IA/
│
├── data/
│   ├── input/                    # Entradas brutas de código gerado por IA
│   ├── output/                   # Relatórios JSON finais (não versionado)
│   └── knowledge_base.json       # Base de conhecimento GIA-001..007
│
├── src/
│   ├── collect/
│   │   └── normalize.py          # Módulo 1 — coleta e normalização
│   ├── analyze/
│   │   ├── sast.py               # Módulo 2 — wrapper Bandit
│   │   └── heuristics.py         # Módulo 2 — heurísticas H001-H008
│   ├── utils/
│   │   └── io_utils.py           # Funções auxiliares de leitura e escrita
│   └── main.py                   # Ponto de entrada do protótipo
│
├── .venv/                        # Ambiente virtual Python (não versionado)
├── requirements.txt
└── README.md
```

---

## Tecnologias utilizadas

- **Python 3.14**
- **isort** — organização de imports
- **Black** — formatação determinística
- **ast** (stdlib) — travessia de AST para heurísticas estruturais
- **Bandit** — análise estática de segurança (SAST)

---

## Requisitos

- Python 3.14 ou superior
- Git (opcional, para clonar o repositório)
- PowerShell, Command Prompt ou terminal integrado do VS Code

---

## Como configurar o ambiente

### 1. Clonar o repositório

```bash
git clone https://github.com/robissu/Arquitetura_Seg_IA.git
cd Arquitetura_Seg_IA
```

### 2. Criar e ativar o ambiente virtual

No PowerShell:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& .\.venv\Scripts\Activate.ps1
```

No Command Prompt:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3. Instalar as dependências

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## Como executar

### 1. Adicionar uma entrada de teste

Crie ou edite um arquivo em `data/input/`, por exemplo `data/input/exemplo_01.txt`. O arquivo pode conter uma saída bruta de código gerado por IA, incluindo texto explicativo e cercas de markdown.

### 2. Executar o protótipo

Na raiz do projeto, com o ambiente virtual ativado:

```bash
python src/main.py
```

---

## Próximos passos

- implementar o Módulo 3 — Classificação (associar achados a GIA, CWE e OWASP);
- implementar o Módulo 4 — Recomendação (gerar relatório final em JSON com orientações de mitigação);
- integrar os quatro módulos no fluxo completo em `main.py`;
- criar suíte de testes automatizados com pytest.

---

## Observações

Este repositório representa um **protótipo em desenvolvimento** voltado à validação da arquitetura proposta no TCC. O escopo atual cobre os Módulos 1 e 2; os Módulos 3 e 4 estão em implementação.

---

## Autor

**Robson Daniel Marchesan**
TCC de Ciência da Computação — UFSM
Orientador: Prof. Raul Ceretta Nunes — DCOM
