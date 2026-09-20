# Pen-PE-Scripts — operação e manutenção

[Voltar à apresentação](../README.md)

## Mapa de leitura

A documentação principal descreve o fluxo de entrada. Para alterar o projeto, comece pelos contratos abaixo e acompanhe os dados até a persistência ou os artefatos de saída:

- [`Invoke-PEAudit.ps1`](../Invoke-PEAudit.ps1): Orquestra módulos e gera relatórios; contém fases estática e runtime.
- [`Audit-PEMitigations.ps1`](../Audit-PEMitigations.ps1): Mitigações e características do formato PE.
- [`Check-PEEntropy.ps1`](../Check-PEEntropy.ps1): Entropia por seção.
- [`Check-ManifestPrivileges.ps1`](../Check-ManifestPrivileges.ps1): Requisitos de privilégio do manifesto.
- [`Find-DangerousImports.ps1`](../Find-DangerousImports.ps1): Inventário de imports para revisão.
- [`Check-NamedPipes.ps1`](../Check-NamedPipes.ps1): Verificações runtime de named pipes.
- [`Check-TempRace.ps1`](../Check-TempRace.ps1): Verificações runtime relacionadas a arquivos temporários.

## Preparar uma instalação ou revisão

1. Registre a revisão Git e leia os manifests desta mesma versão.
2. Prepare um ambiente isolado com dados sintéticos. Identifique dependências externas e quem administra cada uma.
3. Preencha configurações e segredos localmente. Revise os valores padrão e não reutilize credenciais de demonstração.
4. Faça um backup restaurável de qualquer dado existente antes de migrações ou substituição de serviços.
5. Valide o fluxo principal e registre limitações observadas; um processo iniciado não comprova que todo o produto funciona.

## Verificação específica

Não há suíte dedicada identificada. A validação de mudanças deve usar binários sintéticos e resultados esperados conhecidos em VM descartável, sem executar amostras desconhecidas no host de trabalho.

## Dados e recuperação

Identifique bancos, volumes e diretórios de evidência nos contratos desta versão. Copiar apenas o código não cria backup dos dados. Uma restauração deve ser ensaiada em ambiente separado, conferindo acesso, vínculos entre entidades e arquivos necessários aos entregáveis. Preserve chaves de cifragem e configuração por canal privado quando forem necessárias à recuperação.

Evite anexar logs brutos a issues: remova tokens, identificadores pessoais e conteúdo de clientes. O mesmo cuidado vale para screenshots, relatórios e exemplos de API.

## Diagnóstico

| Sintoma | Primeira verificação |
| :--- | :--- |
| Processo ou build falha no início | Runtime e dependências contra os manifests da revisão. |
| Interface ou integração indisponível | Endereço configurado, serviço dependente e permissões do ambiente. |
| Dados ausentes ou divergentes | Origem utilizada, revisão do esquema e resultado da importação/ingestão. |
| Exportação ou artefato incompleto | Entrada sintética mínima, arquivos associados e dependências da geração. |

## Limites conhecidos

Requer PowerShell 5.0 ou superior conforme #Requires. O orquestrador não é passivo por padrão: alguns módulos executam o alvo e outros geram artefatos. Execute apenas em VM de laboratório autorizada, com snapshot e binários cuja procedência seja conhecida. Indicadores heurísticos não constituem vulnerabilidades confirmadas.

## Critério para atualizar esta documentação

Atualize a apresentação quando mudar nome, entrada, configuração ou responsabilidades. Atualize este guia quando mudar persistência, recuperação ou verificação. Documente comandos e resultados separadamente; só declare um teste aprovado quando houver execução e evidência correspondentes.
