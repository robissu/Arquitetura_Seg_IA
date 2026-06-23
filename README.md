# Arquitetura_Seg_IA

Protótipo desenvolvido no contexto do **TCC de Ciência da Computação de Robson Daniel Marchesan**.

## Descrição

Este projeto implementa uma arquitetura de análise de segurança para **código gerado por inteligência artificial**, com foco na identificação, classificação e interpretação de vulnerabilidades. A proposta apoia o desenvolvimento seguro assistido por IA permitindo:

- analisar código gerado por modelos de linguagem;
- identificar vulnerabilidades por meio de SAST e heurísticas complementares;
- classificar os achados com base em **CWE**, **OWASP** e no Guia GIA produzido no TCC;
- recomendar ações de mitigação e correção estruturadas, sem alterar o código.

---

## Arquitetura proposta

O protótipo é composto por quatro módulos integrados em um fluxo contínuo:

```text
Entrada (.txt — código bruto gerado por IA)
           ↓
Módulo 1 — Coleta e normalização
           ↓
Módulo 2 — Análise de segurança   (Bandit  +  heurísticas, em paralelo)
           ↓
Módulo 3 — Classificação          (achado → GIA / CWE / OWASP)
           ↓
Módulo 4 — Recomendação           (consulta ao guia + relatório final)
           ↓
Saída (data/output/<nome>_report.json)
```

No Módulo 2, a análise estática (Bandit) e as heurísticas complementares atuam **em paralelo** sobre o mesmo código normalizado; seus achados são reunidos em um formato intermediário comum antes da classificação.

---

## Fluxo de execução

O ponto de entrada (`src/main.py`) executa, para cada arquivo de entrada:

1. **Normalização** (`normalize_code`) — limpa o artefato e valida a sintaxe. Código inválido **bloqueia** a análise e gera um relatório de erro.
2. **Análise** (`run_bandit` + `run_heuristics`) — produz achados no formato intermediário unificado.
3. **Classificação** (`classify_findings`) — enriquece cada achado com `gia_id`, `gia_category`, `cwe`, `owasp`, `priority` e `requires_manual_review`.
4. **Recomendação** (`generate_report`) — consulta o guia pelo `gia_id` e monta o relatório final.
5. **Persistência** (`save_report`) — grava `data/output/<nome>_report.json`.

---

## Estado atual do desenvolvimento

### Módulo 1 — Coleta e normalização (`src/collect/normalize.py`)

- remoção de artefatos textuais de saídas de LLM (texto introdutório, conclusivo, cercas de markdown);
- normalização de quebras de linha e codificação UTF-8;
- organização de imports com isort e formatação determinística com Black;
- validação sintática com `ast.parse` — código inválido é bloqueado e marcado;
- extração de metadados estruturais: imports, funções, classes, contagem de linhas;
- detecção de fragmentos incompletos (`...`, comentários de omissão).

### Módulo 2 — Análise de segurança (`src/analyze/`)

Camada 1 — SAST com Bandit (`sast.py`):

- execução do Bandit via subprocess com saída em JSON;
- captura de severidade, confiança, regra, linha e trecho de contexto de cada achado;
- saída padronizada no formato intermediário unificado.

Camada 2 — Heurísticas complementares (`heuristics.py`), via travessia de AST:

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

### Módulo 3 — Classificação (`src/classify/classifier.py`)

- associa cada achado a uma categoria do Guia GIA por meio dos mapeamentos `BANDIT_TO_GIA` e `HEURISTIC_TO_GIA`;
- enriquece o achado com categoria, CWE, OWASP e prioridade lidos do `knowledge_base.json` (o guia é a única fonte de verdade);
- achados sem mapeamento direto são marcados como `requires_manual_review` para revisão humana.

### Módulo 4 — Recomendação (`src/recommend/recommender.py`)

- consulta a base de conhecimento pelo `gia_id` e devolve as orientações de mitigação (impacto, o que verificar, como corrigir, como validar);
- **não corrige o código** — apenas fornece orientações estruturadas;
- monta o relatório final em JSON, com lista por achado e um resumo agrupado por GIA.

### Base de conhecimento (`data/knowledge_base.json`)

- arquivo JSON com as sete categorias do Guia GIA (GIA-001 a GIA-007);
- cada entrada contém: CWE, OWASP, impacto, exemplos de ocorrência e as três etapas de mitigação (o que verificar, como corrigir, como validar).

---

## Formato do relatório

Cada execução gera um relatório JSON com três seções:

```text
{
  "analysis_summary": {        # visão geral
    "file", "status",
    "total_findings",
    "by_severity",             # contagem por HIGH / MEDIUM / LOW
    "by_gia"                   # contagem por categoria GIA
  },
  "findings": [                # um item por achado
    {
      "id", "origin", "rule_id", "line", "severity", "confidence",
      "description", "context",
      "classification": { "gia_id", "gia_category", "cwe", "owasp", "priority" },
      "recommendation": {
        "impact", "what_to_check", "how_to_fix",
        "how_to_validate", "requires_manual_review"
      }
    }
  ],
  "gia_summary": [             # achados agrupados por categoria GIA
    { "gia_id", "gia_category", "priority", "cwe", "owasp",
      "finding_count", "finding_ids", "lines", "recommendation" }
  ]
}
```

Para entradas com código sintaticamente inválido, o relatório registra `status: "invalid"`, sem achados, e inclui as seções `errors` e `warnings` da normalização.

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
│   ├── classify/
│   │   └── classifier.py         # Módulo 3 — classificação (achado → GIA)
│   ├── recommend/
│   │   └── recommender.py        # Módulo 4 — recomendação e relatório final
│   ├── utils/
│   │   └── io_utils.py           # Funções auxiliares de leitura e escrita
│   └── main.py                   # Ponto de entrada — pipeline completo
│
├── tests/                        # Suíte pytest + TRACEABILITY.md (rastreabilidade)
├── demo_pipeline.py              # Runner de demonstração (normalize → análise)
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

Crie ou edite um arquivo em `data/input/` contendo uma saída bruta de código gerado por IA (com texto explicativo e cercas de markdown, se houver). O repositório já inclui exemplos:

- `exemplo_01.txt` — código sintaticamente inválido (a análise é bloqueada);
- `exemplo_02.txt` — API Flask vulnerável (GIA-001, 002, 003, 005, 007);
- `exemplo_03.txt` — cliente de API com segredos embutidos e configuração insegura (GIA-003, 004, 006).

### 2. Executar o protótipo

Na raiz do projeto:

```bash
# processa todos os arquivos de data/input/
python src/main.py

# ou processa um arquivo específico
python src/main.py data/input/exemplo_02.txt
```

O `main.py` localiza automaticamente as ferramentas do ambiente virtual, então pode ser executado diretamente com o interpretador do `.venv` mesmo sem ativá-lo.

### 3. Conferir o resultado

O protótipo imprime um resumo no terminal e grava o relatório completo em `data/output/<nome>_report.json`.

### 4. (Opcional) Rodar a suíte de testes

```bash
pytest tests/
```

A suíte cobre cada módulo e o pipeline integrado; a matriz `tests/TRACEABILITY.md` liga cada teste a CWE, OWASP e referências.

---

## Próximos passos

- integrar verificação de dependências (pip-audit) e secret scanning ao pipeline de CI;
- ampliar o conjunto de exemplos de entrada e a cobertura de regras Bandit mapeadas;
- como trabalho futuro, generalizar a arquitetura para além de código Python.

---

## Observações

Este repositório representa um **protótipo** voltado à validação da arquitetura proposta no TCC. O escopo é restrito a código Python e o módulo de recomendação nunca altera o código analisado — apenas fornece orientações de mitigação.

---

## Autor

**Robson Daniel Marchesan**
TCC de Ciência da Computação — UFSM
Orientador: Prof. Raul Ceretta Nunes — DCOM
