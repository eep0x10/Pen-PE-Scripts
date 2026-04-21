# Pen-PE-Scripts

> Toolkit PowerShell para análise e exploração de vulnerabilidades em binários PE do Windows.
> Parsing nativo de PE sem dependências externas — só PowerShell 5+ e, opcionalmente, um compilador C para geração de PoC.

---

## Scripts

| Script | Vetor | PoC | Runtime |
|---|---|---|---|
| `Check-DllHijacking.ps1` | DLL Hijacking (4 vetores) | Sim | Sim |
| `Check-DllSideloading.ps1` | DLL Sideloading | Sim | Sim |
| `Check-COMHijacking.ps1` | COM Object Hijacking via HKCU | Sim | Sim (admin) |
| `Check-PEPlanting.ps1` | Binary Planting / PATH execution | Não | Sim (WMI) |
| `Audit-PEMitigations.ps1` | Audit de mitigações (ASLR/DEP/CFG/…) | — | — |
| `Find-HardcodedSecrets.ps1` | Segredos hardcoded / strings de alto valor | — | — |

---

## `Check-DllHijacking.ps1`

Detecta DLLs que podem ser interceptadas explorando o search order do Windows loader.

**Vetores detectados:**

| Vetor | Descrição | Risco |
|---|---|---|
| `PHANTOM` | DLL importada inexistente no sistema | CRÍTICO |
| `WRITABLE_LOAD` | DLL carregada de diretório com escrita | ALTO |
| `PATH_WEAK` | Diretório do PATH é gravável | ALTO |
| `APP_DIR` | Diretório da aplicação é gravável | MÉDIO |

**Como funciona:** Parsing do PE header (imports estáticos e delay-load), consulta ao registry (KnownDLLs, SafeDllSearchMode), verificação de permissões via P/Invoke. O PoC compila uma DLL phantom ou proxy com forwarders e valida via Windows Named Event.

```powershell
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe"
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -GeneratePoC
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -InteractiveScan -ScanSeconds 60
```

**Parâmetros:**

| Parâmetro | Descrição |
|---|---|
| `-ExePath` | (Obrigatório) Caminho do executável alvo |
| `-GeneratePoC` | Compila e valida DLL maliciosa |
| `-RuntimeScan` | Executa alvo por 3s e captura DLLs carregadas |
| `-InteractiveScan` | Executa em modo interativo (usuário controla duração) |
| `-ScanSeconds` | Duração do scan interativo (padrão: 30s) |
| `-DeepPathScan` | Análise profunda de todos os diretórios do PATH |

---

## `Check-DllSideloading.ps1`

Analisa binários assinados/reputados para uso como veículo de sideloading — execução de payload no contexto de um processo legítimo, ideal para evasão.

**Pontuação de atratividade:**

| Score | Rating | Critério |
|---|---|---|
| 4 | EXCELENTE | Assinado + vendor reputado + sem UAC + DLLs exploráveis |
| 3 | BOM | Maioria dos critérios atendidos |
| 2 | MODERADO | Parcialmente atendido |
| 1 | BAIXO | Pouco atrativo |
| 0 | INVIÁVEL | Não recomendado |

**Como funciona:** Mesmo parsing PE do script de hijacking, filtragem de KnownDLLs (imunes), scoring por vendor reputation e presença de Authenticode. O PoC copia o EXE para diretório temporário, planta DLL proxy com forwarders e valida via named event.

```powershell
.\Check-DllSideloading.ps1 -ExePath "C:\Program Files\Adobe\Acrobat\AcroRd32.exe"
.\Check-DllSideloading.ps1 -ExePath "C:\Windows\System32\msiexec.exe" -GeneratePoC -SideloadDir "C:\temp\test"
.\Check-DllSideloading.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -GeneratePoC
```

**Parâmetros:**

| Parâmetro | Descrição |
|---|---|
| `-ExePath` | (Obrigatório) Caminho do executável alvo |
| `-GeneratePoC` | Gera PoC completo de sideloading |
| `-SideloadDir` | Diretório customizado para teste (padrão: `%TEMP%`) |
| `-RuntimeScan` | Captura DLLs em runtime |
| `-InteractiveScan` | Modo interativo |
| `-ScanSeconds` | Duração do scan interativo |

---

## `Check-COMHijacking.ps1`

Extrai CLSIDs referenciados pelo binário e verifica quais estão registrados apenas em HKLM — podendo ser "shadowed" via HKCU sem privilégio elevado.

**Como funciona:** Scan de strings no binário para padrões de GUID `{xxxxxxxx-…}`, consulta ao registry (HKLM vs HKCU, incluindo WOW64). Com `-GeneratePoC` compila uma DLL, registra no `HKCU\SOFTWARE\Classes\CLSID\{guid}\InprocServer32` e valida via named event. Com `-RuntimeScan` usa ETW (`Microsoft-Windows-COM-Perf`) para capturar ativações COM em tempo real (requer admin).

```powershell
.\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe"
.\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -GeneratePoC
.\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -ScanSeconds 30
.\Check-COMHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -GeneratePoC -ClsidFilter "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}"
```

**Parâmetros:**

| Parâmetro | Descrição |
|---|---|
| `-ExePath` | (Obrigatório) Caminho do executável alvo |
| `-GeneratePoC` | Compila DLL, registra no HKCU, valida |
| `-RuntimeScan` | ETW para captura de ativações COM (admin) |
| `-ScanSeconds` | Duração do monitoramento runtime (padrão: 20s) |
| `-ClsidFilter` | Limita análise a um CLSID específico |

**Cleanup automático:** o PoC remove as entradas HKCU após validação. Em caso de falha, o caminho para limpeza manual é exibido.

---

## `Check-PEPlanting.ps1`

Detecta chamadas a executáveis via caminho relativo (sem `\` ou `/`) em `CreateProcess*`, `ShellExecute*` e similares — vetor de binary planting se algum diretório do PATH for gravável.

**Como funciona:** Parsing da import table para identificar APIs de criação de processo, extração de strings com padrões `*.exe`/`*.bat`/`*.cmd` sem separador de path, verificação de permissão de escrita nos diretórios do PATH via P/Invoke. O runtime scan usa WMI (`__InstanceCreationEvent`) para monitorar processos filhos sem exigir admin.

```powershell
.\Check-PEPlanting.ps1 -ExePath "C:\Program Files\App\app.exe"
.\Check-PEPlanting.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan
.\Check-PEPlanting.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -ScanSeconds 60 -DeepPathScan
```

**Parâmetros:**

| Parâmetro | Descrição |
|---|---|
| `-ExePath` | (Obrigatório) Caminho do executável alvo |
| `-RuntimeScan` | Monitora processos filhos via WMI |
| `-ScanSeconds` | Duração do monitoramento (padrão: 20s) |
| `-DeepPathScan` | Lista todos os diretórios do PATH graváveis |

---

## `Audit-PEMitigations.ps1`

Triage rápido de attack surface: audita flags de segurança em um ou múltiplos binários PE.

**Flags verificadas:**

| Flag | DllCharacteristics bit | Impacto |
|---|---|---|
| ASLR (`/DYNAMICBASE`) | `0x0040` | Randomiza endereço base em cada carga |
| High Entropy VA | `0x0020` | ASLR 64-bit com entropia máxima |
| DEP (`/NXCOMPAT`) | `0x0100` | Marca pilha/heap como não-executável (W^X) |
| Force Integrity | `0x0080` | Exige assinatura de código válida no boot |
| CFG (`/guard:cf`) | `0x4000` | Control Flow Guard: valida destinos de call indirect |
| SafeSEH | Load Config | Cadeia SEH validada contra tabela estática |
| Authenticode | Security Dir. | Presença de assinatura digital |

```powershell
.\Audit-PEMitigations.ps1 -Path "C:\Program Files\App"
.\Audit-PEMitigations.ps1 -Path "C:\Windows\System32" -Recurse -ShowVulnOnly
.\Audit-PEMitigations.ps1 -Path "C:\Program Files" -Recurse -CsvOutput "C:\results.csv"
```

**Parâmetros:**

| Parâmetro | Descrição |
|---|---|
| `-Path` | (Obrigatório) Arquivo PE ou diretório |
| `-Recurse` | Escaneia subdiretórios |
| `-ShowVulnOnly` | Exibe apenas binários com alguma mitigação ausente |
| `-CsvOutput` | Exporta resultados em CSV |

---

## `Find-HardcodedSecrets.ps1`

Extrai strings ASCII e Unicode do binário e aplica ~30 regras para detectar segredos hardcoded.

**Categorias de detecção:**

| Categoria | Exemplos | Severidade |
|---|---|---|
| Chaves privadas | PEM `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| URL com credenciais | `https://user:pass@host` | CRITICAL |
| AWS Keys | `AKIA[0-9A-Z]{16}` | CRITICAL |
| JWT tokens | `eyJ...` | HIGH |
| GitHub/Slack tokens | `ghp_...`, `xoxb-...` | HIGH |
| Azure/GCP keys | `AccountKey=`, `AIza...` | HIGH |
| DB connection strings | `Server=...;Password=...` | HIGH |
| Bearer tokens | `Authorization: Bearer ...` | MEDIUM |
| High entropy (≥4.5) | Strings longas com distribuição uniforme | MEDIUM |
| IPs internos com porta | `192.168.x.x:8080` | LOW |

Também mapeia cada achado para a **seção PE** de origem (`.rdata`, `.data`, `.rsrc`, etc.) e calcula a **entropia de Shannon** da string.

```powershell
.\Find-HardcodedSecrets.ps1 -ExePath "C:\App\app.exe"
.\Find-HardcodedSecrets.ps1 -ExePath "C:\App\app.dll" -MinEntropy 4.0 -OutputFile "C:\secrets.json"
```

**Parâmetros:**

| Parâmetro | Descrição |
|---|---|
| `-ExePath` | (Obrigatório) Arquivo PE a analisar |
| `-MinLength` | Comprimento mínimo de string (padrão: 6) |
| `-MinEntropy` | Limiar de entropia para alertar (padrão: 4.5) |
| `-OutputFile` | Exporta resultados em JSON |

---

## Fluxo de Trabalho (Pentest de Binários)

```
1. Triage de attack surface
   └── Audit-PEMitigations  →  mapa de flags: ASLR/DEP/CFG/SafeSEH/Authenticode

2. Reconhecimento do binário
   └── Find-HardcodedSecrets  →  credenciais, tokens, endpoints hardcoded

3. Vetores de carregamento de DLL
   ├── Check-DllHijacking     →  PHANTOM / WRITABLE_LOAD / PATH_WEAK / APP_DIR
   ├── Check-DllSideloading   →  binário assinado como veículo de payload
   └── Check-COMHijacking     →  shadow de COM object via HKCU

4. Execução via PATH
   └── Check-PEPlanting       →  CreateProcess relativo + PATH gravável

5. Validação com PoC
   └── -GeneratePoC em qualquer dos 3 scripts de DLL/COM → compila, implanta, confirma
```

---

## Internals Comuns

### Parsing PE nativo (sem ferramentas externas)

Todos os scripts fazem parsing manual do formato PE via `[System.IO.File]::ReadAllBytes()`:

```
0x3C        → e_lfanew (ponteiro para PE signature)
PE+4        → Machine field (0x014C=x86, 0x8664=x64)
PE+24       → Optional Header
OptHdr+70   → DllCharacteristics (mesmo offset para PE32 e PE32+)
OptHdr+96   → DataDirectory[0] (PE32)
OptHdr+112  → DataDirectory[0] (PE32+)
DataDir[1]  → Import Directory
DataDir[4]  → Security Directory (Authenticode)
DataDir[10] → Load Config (SafeSEH, CFG GuardFlags)
```

### Validação de PoC via Named Event (sem spawn de processo)

```c
// DLL compilada inline (C source gerado pelo script)
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Global\\PenPEProof_<random>");
        if (hEvent) { SetEvent(hEvent); CloseHandle(hEvent); }
    }
    return TRUE;
}
```

O script cria o evento com `EventWaitHandle`, aguarda com timeout — se sinalizado, exploração confirmada.

### P/Invoke inlined (sem dependências externas)

```powershell
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class NativeModEnum {
    [DllImport("psapi.dll")]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess, ...);
}
'@
```

---

## Requisitos

| Requisito | Versão | Necessário para |
|---|---|---|
| Windows | 7+ / Server 2008 R2+ | Todos os scripts |
| PowerShell | 5.0+ | Todos os scripts |
| Visual Studio (cl.exe) | qualquer | `-GeneratePoC` |
| MinGW / GCC | qualquer | `-GeneratePoC` (alternativa) |
| Admin | — | `-RuntimeScan` em `Check-COMHijacking` |

> **Detecção de compilador:** os scripts detectam automaticamente MSVC via `vswhere.exe` ou GCC via `$env:PATH`. Sem compilador, a análise estática funciona normalmente — apenas o `-GeneratePoC` fica indisponível.

---

## Aviso Legal

> **USO AUTORIZADO APENAS.**
>
> Estas ferramentas foram desenvolvidas exclusivamente para:
> - Testes de penetração com autorização escrita do proprietário do sistema
> - Pesquisa de segurança em ambientes controlados
> - Auditorias de segurança internas
>
> O uso não autorizado contra sistemas de terceiros é ilegal e antiético.
> Os autores não se responsabilizam pelo uso indevido destas ferramentas.

---

## Licença

MIT License — veja [LICENSE](LICENSE) para detalhes.
