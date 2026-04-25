# Arquitetura_Seg_IA

Protótipo desenvolvido no contexto do **TCC de Ciência da Computação de Robson Daniel Marchesan**.

## Descrição

Este projeto tem como objetivo estruturar um protótipo de análise de segurança para **código gerado por inteligência artificial**, com foco na identificação, classificação e interpretação de vulnerabilidades de segurança presentes no código analisado.

A proposta busca apoiar o desenvolvimento seguro assistido por IA, permitindo:

- analisar código gerado por modelos de linguagem;
- identificar vulnerabilidades de segurança;
- classificar essas vulnerabilidades com base em taxonomias e bases de conhecimento como **CWE**, **OWASP** e outras referências relevantes;
- sugerir recomendações de correção e mitigação;
- apoiar programadores na prevenção de falhas de segurança recorrentes.

---

## Objetivo da arquitetura

A arquitetura proposta foi concebida para processar código gerado por IA em um fluxo contínuo de análise, estruturado em módulos que permitem:

1. **coletar e normalizar** o código recebido;
2. **analisar** o código em busca de vulnerabilidades;
3. **classificar** os achados segundo categorias conhecidas de segurança;
4. **recomendar** ações de mitigação e correção.

---

## Arquitetura proposta

A arquitetura completa do protótipo é composta pelos seguintes módulos:

1. **Módulo de coleta e normalização**
2. **Módulo de análise**
3. **Módulo de classificação**
4. **Módulo de recomendação**

### Fluxo proposto

```text
Módulo de coleta e normalização
        ↓
Módulo de análise
        ↓
Módulo de classificação
        ↓
Módulo de recomendação
```

---

## Estado atual do desenvolvimento

### Concluído
- **Módulo de coleta e normalização**

### Em desenvolvimento
- Módulo de análise
- Módulo de classificação
- Módulo de recomendação

---

## Estrutura do projeto

```text
Arquitetura_Seg_IA/
│
├── data/
│   ├── input/              # Entradas brutas de código gerado por IA
│   └── output/             # Saídas normalizadas e resultados intermediários
│
├── src/
│   ├── collect/
│   │   └── normalize.py    # Módulo de coleta e normalização
│   │
│   ├── utils/
│   │   └── io_utils.py     # Funções auxiliares de leitura e escrita
│   │
│   └── main.py             # Ponto de entrada do protótipo
│
├── .venv/                  # Ambiente virtual Python (não versionado)
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Tecnologias utilizadas

O protótipo utiliza, até o momento:

- **Python 3.14**
- **isort** — organização de imports
- **Black** — formatação determinística do código
- **ast.parse** — validação sintática preliminar e apoio à extração estrutural
- **Bandit** — análise estática de segurança (SAST)

---

## Funcionalidade implementada até o momento

O módulo de coleta e normalização já realiza:

- remoção de artefatos textuais provenientes da saída de modelos de linguagem;
- tratamento de cercas de markdown e trechos não pertencentes ao código;
- normalização de quebras de linha;
- organização de imports;
- formatação determinística do código;
- validação sintática preliminar;
- extração de metadados estruturais, como imports, funções e classes.

---

## Requisitos

Para executar o projeto, é necessário ter instalado:

- **Python 3.14 ou superior**
- **Git** (opcional, caso o projeto seja clonado do GitHub)
- terminal PowerShell, Command Prompt ou terminal integrado do VS Code

---

## Como configurar o ambiente

### 1. Clonar o repositório

```bash
git clone https://github.com/robissu/Arquitetura_Seg_IA.git
cd Arquitetura_Seg_IA
```

### 2. Criar o ambiente virtual

No PowerShell:

```powershell
python -m venv .venv
```

### 3. Ativar o ambiente virtual

No PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& .\.venv\Scripts\Activate.ps1
```

No Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

### 4. Instalar as dependências

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## Como executar

### 1. Adicione uma entrada de teste

Crie ou edite um arquivo dentro de:

```text
data/input/
```

Exemplo:

```text
data/input/exemplo_01.txt
```

Esse arquivo pode conter uma saída bruta de código gerado por IA, incluindo markdown e texto explicativo.

### 2. Execute o protótipo

Na raiz do projeto, com o ambiente virtual ativado:

```bash
python src/main.py
```

### 3. Resultado esperado

Ao executar, o protótipo:

- lê o arquivo de entrada;
- normaliza o conteúdo;
- valida a sintaxe;
- extrai metadados básicos;
- imprime os resultados no terminal;
- salva o código normalizado em:

```text
data/output/
```

---

## Exemplo de entrada

Arquivo `data/input/exemplo_01.txt`:

```text
Claro! Aqui está o código solicitado:

<bloco de código Python gerado por IA>
```

## Exemplo de saída esperada

```python
import os
import sys


def hello():
    print("oi")
```

---

## Próximos passos

Os próximos passos previstos no desenvolvimento do protótipo são:

- integrar o módulo de análise estática com foco em segurança;
- capturar o output do SAST em formato estruturado;
- mapear vulnerabilidades para categorias como **CWE** e **OWASP**;
- implementar o módulo de classificação;
- implementar o módulo de recomendação com base em um guia técnico de mitigação;
- gerar relatórios com indicação de localização da vulnerabilidade, classificação, impacto e sugestão de correção.

---

## Observações

Este repositório representa um **protótipo em desenvolvimento**, voltado à validação da arquitetura proposta no TCC. A implementação atual cobre apenas a etapa inicial de coleta e normalização, sendo expandida gradualmente para contemplar os módulos seguintes.

---

## Autor

**Robson Daniel Marchesan**  
TCC de Ciência da Computação
