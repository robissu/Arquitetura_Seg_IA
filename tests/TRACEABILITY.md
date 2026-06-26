# Matriz de rastreabilidade — testes, detectores e fontes

Este documento liga cada detector do protótipo (regra Bandit ou heurística) ao
caso de teste que o valida, à categoria do guia (GIA), ao identificador CWE, à
categoria OWASP Top 10 2021 e à(s) fonte(s) científica(s) que fundamentam a
detecção. Serve como evidência de cobertura e como tabela de apoio para o texto
do TCC.

## 1. Detectores → CWE / OWASP / GIA / referência

| Detector | Teste | CWE | OWASP 2021 | GIA | Referência principal |
|---|---|---|---|---|---|
| Bandit B608 | `test_sast::test_sql_por_concatenacao_gera_b608` | CWE-89 | A03 – Injection | GIA-001 | Bandit docs; Pearce et al. (2022) |
| Bandit B602 | `test_sast::test_subprocess_shell_true_gera_b602` | CWE-78 | A03 – Injection | GIA-001 | Bandit docs |
| Bandit B307 | `test_sast::test_eval_de_entrada_gera_b307` | CWE-95 | A03 – Injection | GIA-001 | Bandit docs |
| H001 | `test_heuristics::test_h001_except_pass_silencioso` | CWE-703 | A09 – Logging/Monitoring Failures | GIA-005 | MITRE CWE; Tihanyi et al. (2025) |
| H002 | `test_heuristics::test_h002_except_com_nome_silencioso` | CWE-703 | A09 – Logging/Monitoring Failures | GIA-005 | MITRE CWE |
| H003 | `test_heuristics::test_h003_todo_em_funcao_de_seguranca` | CWE-546 | — | GIA-007 | MITRE CWE; Sajadi et al. (2025) |
| H004 | `test_heuristics::test_h004_verificacao_de_acesso_stub` | CWE-862 / CWE-863 | A01 – Broken Access Control | GIA-007 | MITRE CWE |
| H005 | `test_heuristics::test_h005_entrada_externa_sem_validacao` | CWE-20 | A03 – Injection | GIA-001 | MITRE CWE; Pearce et al. (2022) |
| H006 | `test_heuristics::test_h006_rota_sensivel_sem_autenticacao` | CWE-306 | A01 / A07 | GIA-002 | MITRE CWE; Dora et al. (2025) |
| H007 | `test_heuristics::test_h007_rota_com_id_sem_checar_dono` | CWE-639 | A01 – Broken Access Control | GIA-002 | MITRE CWE; Zhao et al. (2025) |
| H008 | `test_heuristics::test_h008_import_ausente_em_requirements` | CWE-1104 / CWE-829 | A06 – Vulnerable/Outdated Components | GIA-003 | Spracklen et al. (2025) |
| H009 | `test_heuristics::test_h009_segredo_por_formato_que_b105_perde` | CWE-798 | A02 – Cryptographic Failures | GIA-004 | MITRE CWE; limitação do B105 (§3.3.2.1) |

## 2. Classificação e recomendação → fontes

| Comportamento | Teste | Fonte |
|---|---|---|
| B608 → GIA-001 / CWE-89 / A03 | `test_classifier::test_b608_mapeia_gia001_cwe89_owasp_a03` | OWASP Top 10 2021; MITRE CWE-89 |
| H006 → GIA-002 / CWE-306 / A07 | `test_classifier::test_h006_mapeia_gia002_cwe306_owasp_a07` | OWASP Top 10 2021; MITRE CWE-306 |
| Regra sem mapeamento → revisão manual | `test_classifier::test_regra_sem_mapeamento_exige_revisao_manual` | TCC §3.3.3 (3º nível da classificação) |
| GIA-001 → mitigação com verificar/corrigir/validar | `test_recommender::test_gia001_recomendacao_tem_os_tres_campos` | OWASP Cheat Sheet Series; OWASP ASVS (Validação) |
| GIA-003 → cita pip-audit e PyPI | `test_recommender::test_gia003_menciona_pip_audit_e_pypi` | Spracklen et al. (2025); pip-audit docs |
| Entrada inválida → análise bloqueada | `test_recommender::test_generate_error_report_para_entrada_invalida`; `test_pipeline::test_entrada_invalida_bloqueia_analise` | NIST SP 800-218 (SSDF); módulo `ast` |

## 3. Normalização → fontes

| Comportamento | Teste | Fonte |
|---|---|---|
| Validação sintática (bloqueio de código inválido) | `test_normalize::test_codigo_invalido_status_invalid` | Módulo `ast` (Python Language Reference) |
| Extração de metadados estruturais | `test_normalize::test_metadados_estruturais_extraidos` | Módulo `ast` |
| Remoção de cercas de markdown | `test_normalize::test_remove_cercas_markdown` | — (pré-processamento de saída de LLM) |

## 4. Catálogo de fontes

**Normas e catálogos (identificadores estáveis, verificáveis):**

- MITRE CWE — Common Weakness Enumeration. https://cwe.mitre.org/
- OWASP Top 10 (2021). https://owasp.org/Top10/
- OWASP Application Security Verification Standard (ASVS) 5.0.
- OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/
- NIST SP 800-218 — Secure Software Development Framework (SSDF); SP 800-218A
  (práticas para IA generativa). https://csrc.nist.gov/

**Documentação de ferramentas:**

- Bandit (PyCQA) — security linter para Python. https://bandit.readthedocs.io/
- Python `ast` — https://docs.python.org/3/library/ast.html
- isort — https://pycqa.github.io/isort/
- Black — https://black.readthedocs.io/
- pip-audit — https://pypi.org/project/pip-audit/

**Referências acadêmicas** (já presentes em `data/knowledge_base.json` →
`evidencias_literatura`; conferir os dados bibliográficos completos contra a
bibliografia do TCC):

- Pearce et al. (2022); Fu et al. (2025); Dora et al. (2025);
  Spracklen et al. (2025); Zhao et al. (2025); Sajadi et al. (2025);
  Tihanyi et al. (2025).

> Observação: os identificadores de catálogo (CWE, OWASP, NIST) e a documentação
> de ferramentas têm referências estáveis e diretamente citáveis. As referências
> acadêmicas reaproveitam exatamente as já adotadas no guia do TCC.
