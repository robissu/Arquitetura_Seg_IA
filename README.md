# Arquitetura_Seg_IA

Protótipo desenvolvido no contexto do **TCC de Ciência da Computação de Robson Daniel Marchesan**.

## Objetivo

A proposta deste projeto é estruturar um protótipo de análise de código gerado por inteligência artificial, com foco na identificação, classificação e interpretação de vulnerabilidades de segurança presentes no código analisado.

A arquitetura tem como objetivo:

- analisar código gerado por IA;
- identificar vulnerabilidades de segurança;
- classificar essas vulnerabilidades com base em taxonomias e bases de conhecimento como **CWE**, **OWASP** e outras referências relevantes;
- sugerir recomendações de correção e mitigação;
- apoiar o programador na prevenção de falhas de segurança recorrentes.

---

## Proposta da Arquitetura

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