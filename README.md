# Pen-PE-Scripts

> Toolkit PowerShell para análise e exploração de vulnerabilidades **DLL Hijacking** e **DLL Sideloading** em executáveis Windows (PE files).

---

## Visão Geral

Este toolkit automatiza a detecção, análise e validação (com PoC funcional) de duas das principais vulnerabilidades baseadas em DLL no Windows:

| Vulnerabilidade | Script | Descrição |
|---|---|---|
| **DLL Hijacking** | `Check-DllHijacking.ps1` | Detecta DLLs que podem ser interceptadas pelo controle do search order |
| **DLL Sideloading** | `Check-DllSideloading.ps1` | Identifica binários assinados que carregam DLLs de diretórios controláveis |

Ambos os scripts funcionam **sem dependências externas** — apenas PowerShell 5+ nativo e, opcionalmente, um compilador C (MSVC ou MinGW/GCC) para geração de PoC.

---

## Scripts

### `Check-DllHijacking.ps1`

Analisa um executável PE e identifica DLLs vulneráveis a hijacking. Detecta quatro vetores distintos:

| Vetor | Descrição | Risco |
|---|---|---|
| `PHANTOM` | DLL importada mas inexistente no sistema | CRÍTICO |
| `WRITABLE_LOAD` | DLL carregada de diretório com permissão de escrita | ALTO |
| `PATH_WEAK` | Diretório no PATH tem escrita liberada | ALTO |
| `APP_DIR` | Diretório da aplicação é gravável | MÉDIO |

**Como funciona:**

1. Faz parsing do header PE (x86/x64), import table (estática e delay-load) e manifesto embutido
2. Consulta o registro do Windows (`KnownDLLs`, `SafeDllSearchMode`) para mapear o search order real
3. Verifica permissões de escrita via P/Invoke em cada diretório da cadeia de resolução
4. Opcionalmente executa o alvo e captura DLLs carregadas em runtime via `EnumProcessModulesEx`
5. Gera e compila uma DLL maliciosa (phantom ou proxy com forwarders) e valida exploração via named event

**Parâmetros principais:**

```powershell
-ExePath        <string>   # (Obrigatório) Caminho do executável alvo
-GeneratePoC               # Gera, compila e valida DLL maliciosa
-RuntimeScan               # Executa o alvo por 3s e captura DLLs em runtime
-InteractiveScan           # Executa o alvo em modo interativo (usuário controla duração)
-ScanSeconds    <int>      # Duração do scan interativo (padrão: 30s)
-DeepPathScan              # Analisa todos os diretórios do PATH em profundidade
```

**Exemplos:**

```powershell
# Análise estática básica
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe"

# Análise com captura de DLLs em runtime
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan

# Análise completa + geração de PoC automático
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -GeneratePoC

# Scan interativo com 60 segundos (para aplicações com inicialização lenta)
.\Check-DllHijacking.ps1 -ExePath "C:\Program Files\App\app.exe" -InteractiveScan -ScanSeconds 60
```

**Output (exemplo):**

```
[*] === DLL HIJACKING ANALYSIS ===
[*] Target: C:\Program Files\App\app.exe (x64)
[*] Code-signed: Yes (Acme Corp)
[*] Security flags: ASLR=True, DEP=True, StackCanary=True

[!] Imported DLLs: 12 (static) + 3 (delay-load)

[-] [CRITICO] PHANTOM   -> version.dll      (não encontrada no sistema)
[-] [ALTO]    PATH_WEAK -> C:\custom\bin\   (gravável, versão.dll não existe aqui ainda)
[+] [INFO]    kernel32.dll                  (KnownDLL, imune)
```

---

### `Check-DllSideloading.ps1`

Analisa um executável assinado para verificar se pode ser usado como veículo de DLL sideloading — técnica amplamente usada para evasão de AV/EDR, pois o payload executa no contexto de um binário legítimo.

**Como funciona:**

1. Faz o mesmo parsing PE do script de hijacking
2. Filtra DLLs que **podem** ser sideloaded (exclui KnownDLLs, que são cached pelo loader)
3. Atribui uma **pontuação de atratividade** ao binário (0-4):
   - Possui assinatura Authenticode válida
   - Vendor de reputação (Microsoft, Adobe, Google, etc.)
   - Tem DLLs exploráveis disponíveis
   - Não requer elevação (sem UAC prompt)
4. Gera um diretório de sideload isolado, copia o EXE e dependências, compila DLL proxy com forwarders para o original, e valida execução

**Pontuação de Atratividade:**

| Score | Rating | Significado |
|---|---|---|
| 4 | EXCELENTE | Binário ideal para sideloading — assinado, reputado, sem UAC |
| 3 | BOM | Boa opção com pequenas limitações |
| 2 | MODERADO | Utilizável mas com restrições |
| 1 | BAIXO | Pouco atrativo para sideloading |
| 0 | INVIÁVEL | Não recomendado |

**Parâmetros principais:**

```powershell
-ExePath        <string>   # (Obrigatório) Caminho do executável alvo
-GeneratePoC               # Gera PoC completo de sideloading
-SideloadDir    <string>   # Diretório customizado para teste (padrão: %TEMP%)
-RuntimeScan               # Captura DLLs em runtime
-InteractiveScan           # Modo interativo
-ScanSeconds    <int>      # Duração do scan interativo
```

**Exemplos:**

```powershell
# Análise de atratividade
.\Check-DllSideloading.ps1 -ExePath "C:\Program Files\Adobe\Acrobat\AcroRd32.exe"

# Gerar PoC em diretório customizado
.\Check-DllSideloading.ps1 -ExePath "C:\Windows\System32\msiexec.exe" -GeneratePoC -SideloadDir "C:\temp\test"

# Análise com runtime + PoC
.\Check-DllSideloading.ps1 -ExePath "C:\Program Files\App\app.exe" -RuntimeScan -GeneratePoC
```

---

## Requisitos

| Requisito | Versão | Obrigatório |
|---|---|---|
| Windows | 7 / Server 2008 R2+ | Sim |
| PowerShell | 5.0+ | Sim |
| Visual Studio (cl.exe) | qualquer | Apenas para `-GeneratePoC` |
| MinGW / GCC | qualquer | Alternativa ao MSVC para `-GeneratePoC` |

> **Detecção de compilador:** os scripts auto-detectam o compilador disponível via `vswhere.exe` (MSVC) ou `$env:PATH` (GCC/MinGW). Se nenhum compilador for encontrado, a análise ainda funciona normalmente — apenas a geração de PoC fica indisponível.

---

## Fluxo de Trabalho Típico (Pentest)

```
1. Recon estático
   └── Análise de imports, manifesto, assinatura, flags de segurança

2. Identificação de vetores
   └── PHANTOM / WRITABLE_LOAD / PATH_WEAK / APP_DIR

3. Validação em runtime (opcional)
   └── -RuntimeScan / -InteractiveScan

4. Geração e validação de PoC
   └── -GeneratePoC → compila DLL → implanta → confirma via named event

5. Relatório
   └── Output color-coded + risco classificado (CRÍTICO / ALTO / MÉDIO)
```

---

## Internals

### Parsing de PE sem ferramentas externas

Ambos os scripts fazem parsing manual do formato PE via `[System.IO.File]::ReadAllBytes()` e `[System.BitConverter]`:

- **Offset 0x3C** → ponteiro para o PE header
- **Machine field** → detecta x86 (`0x014C`) ou x64 (`0x8664`)
- **Import Directory** → extrai DLL names da import table (incluindo delay-load via `0x0D`)
- **Resource Directory** → extrai manifesto XML embutido

### P/Invoke inlined

Os scripts definem classes C# inline com `Add-Type` para acesso a APIs nativas:

```csharp
// EnumProcessModulesEx — captura DLLs carregadas em runtime
[DllImport("psapi.dll")] 
static extern bool EnumProcessModulesEx(IntPtr hProcess, ...);

// Teste de permissão de escrita em diretórios
bool CanWrite(string path) { /* CreateFile test */ }
```

### Validação de PoC via Named Event

O PoC não cria processos filhos nem grava arquivos de flag — usa **Windows Named Events** para confirmar execução:

```c
// DLL maliciosa gerada
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Global\\PenPEProof_<random>");
        if (hEvent) { SetEvent(hEvent); CloseHandle(hEvent); }
    }
    return TRUE;
}
```

O script aguarda o evento com timeout configurável — se sinalizado, a exploração é confirmada.

---

## Avisos Legais

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
