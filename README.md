<div align="center">

<img src="docs/assets/banner-illustrated.png" alt="Pen-PE-Scripts — Revisão de binários Windows com resultados rastreáveis." width="100%">

# Pen-PE-Scripts

### Revisão de binários Windows com resultados rastreáveis.

Coleção PowerShell para revisar características de segurança de executáveis PE, permissões e comportamentos associados. Os módulos abrangem inspeção estática e verificações que podem executar o binário; essa diferença deve orientar cada avaliação.

[![PowerShell 5+](https://img.shields.io/badge/PowerShell%205%2B-243E4A?style=flat-square)](Invoke-PEAudit.ps1) [![Windows PE](https://img.shields.io/badge/Windows%20PE-243E4A?style=flat-square)](Audit-PEMitigations.ps1)

[Começar](#começar) · [Arquitetura](#arquitetura) · [Operação](docs/OPERATIONS.md) · [Limites](#limites-e-responsabilidade)

</div>

## O que você encontra

- Inspeção de mitigações PE, entropia, imports e manifesto.
- Verificação de permissões e configurações relevantes à revisão.
- Orquestrador com consolidação de resultados em relatório.

## Começar

Requisitos: Windows e PowerShell 5.0 ou superior. Comece pela ajuda estática e revisão dos parâmetros, sem executar uma amostra:

```powershell
Get-Help ./Invoke-PEAudit.ps1 -Full
Get-Help ./Audit-PEMitigations.ps1 -Full
```

O orquestrador oferece `SkipRuntime` e `SkipDllPoC`, mas não trate nomes de opções como garantia de ausência de efeitos: confira os módulos selecionados. Prepare uma VM autorizada e um conjunto de binários sintéticos antes de realizar validação funcional.

## Arquitetura

| Caminho | Responsabilidade |
| :--- | :--- |
| [`Invoke-PEAudit.ps1`](Invoke-PEAudit.ps1) | Orquestra módulos e gera relatórios; contém fases estática e runtime. |
| [`Audit-PEMitigations.ps1`](Audit-PEMitigations.ps1) | Mitigações e características do formato PE. |
| [`Check-PEEntropy.ps1`](Check-PEEntropy.ps1) | Entropia por seção. |
| [`Check-ManifestPrivileges.ps1`](Check-ManifestPrivileges.ps1) | Requisitos de privilégio do manifesto. |
| [`Find-DangerousImports.ps1`](Find-DangerousImports.ps1) | Inventário de imports para revisão. |
| [`Check-NamedPipes.ps1`](Check-NamedPipes.ps1) | Verificações runtime de named pipes. |
| [`Check-TempRace.ps1`](Check-TempRace.ps1) | Verificações runtime relacionadas a arquivos temporários. |

## Configuração

Os contratos de configuração estão nos manifests e arquivos de entrada indicados acima. Não há uma configuração universal que substitua a preparação do ambiente.

Use valores específicos do seu ambiente. Tokens, senhas, bancos, logs e evidências não pertencem ao README. Revise modelos de configuração antes de copiá-los e não publique suas cópias preenchidas.

## Verificação e desenvolvimento

Não há suíte dedicada identificada. A validação de mudanças deve usar binários sintéticos e resultados esperados conhecidos em VM descartável, sem executar amostras desconhecidas no host de trabalho.

Os comandos de verificação descrevem o fluxo do projeto. Consulte a CI ou registre a execução no seu ambiente antes de considerar uma revisão validada; a documentação não substitui esse resultado.

## Limites e responsabilidade

Requer PowerShell 5.0 ou superior conforme #Requires. O orquestrador não é passivo por padrão: alguns módulos executam o alvo e outros geram artefatos. Execute apenas em VM de laboratório autorizada, com snapshot e binários cuja procedência seja conhecida. Indicadores heurísticos não constituem vulnerabilidades confirmadas.

Use somente dados e sistemas sob sua responsabilidade ou com autorização explícita. Registre escopo, responsáveis e retenção de evidências antes de operações de segurança. Achados e relatórios precisam distinguir observação, hipótese e confirmação.

## Documentação

- [Operação, manutenção e verificação](docs/OPERATIONS.md)


## Licença

Não foi encontrado um arquivo LICENSE na raiz desta revisão. A disponibilidade do código não deve ser interpretada como concessão automática de direitos de redistribuição.

O banner é uma ilustração de identidade criada com IA; não representa uma instalação, cliente ou resultado real.
