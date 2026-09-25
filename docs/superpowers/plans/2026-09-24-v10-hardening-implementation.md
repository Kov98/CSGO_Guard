# CSGO Guard v10 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evoluir a CSGO Guard v9 no próprio repositório para uma v10 mais forte, mantendo a arquitetura existente e adicionando hardening client/kernel, telemetria CSGO autoritativa, detectores server-side mais robustos, replay/calibração e CI/release reproduzível.

**Architecture:** A v9 permanece como baseline. A v10 reforça os limites de confiança existentes em vez de substituí-los: launcher/client → serviço SYSTEM → driver; cliente/game server → protocolo autenticado → backend; game server autoritativo → pipeline de detectores → quorum de evidências. Mudanças de ABI/protocolo serão versionadas e testadas antes de habilitar enforcement.

**Tech Stack:** C++17/CMake, C/WDK, C#/.NET 8, PowerShell, Python, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-24-v10-hardening-design.md`

## Global Constraints

- Preservar funcionalidades válidas da v9; nenhuma reescrita total.
- Não adicionar bypass de PatchGuard, driver unsigned de produção, rootkit, leitura/escrita arbitrária de memória física ou IOCTL genérico de memória.
- Telemetria de gameplay usada para enforcement deve ser autoritativa do game server.
- Nenhum detector comportamental isolado pode causar ban automático.
- Driver deve continuar SYSTEM-only, HVCI-compatible e sem memória W+X.
- Segredos reais nunca entram no repositório.
- Steam ticket final permanece fora desta rodada.
- Cada patch fechado deve ter ZIP reproduzível.

## Review Focus

1. **Replay/duplicação:** requisição repetida ou fora de ordem deve ser rejeitada sem consumir estado antes da autenticação.
2. **ABI truncada/oversized:** todo request de serviço/driver deve validar `size`, `version` e limites antes de acessar campos.
3. **Telemetria não autoritativa:** o backend deve rejeitar/ignorar campos de gameplay que não estejam assinados pela credencial do game server.
4. **Quorum enviesado:** sinais altamente correlacionados da mesma família não podem contar como famílias independentes para autoban.
5. **Degradação silenciosa:** perda do serviço, driver ou attestation deve mudar o estado para `degraded/untrusted`, nunca permanecer `healthy`.

---

### Task 1: Importar a v9 como baseline reproduzível e preservar a spec

**Files:**
- Create/update: raiz inteira do projeto a partir de `CSGO_Guard_v9.zip`
- Preserve: `docs/superpowers/specs/2026-09-24-v10-hardening-design.md`
- Create: `docs/superpowers/baselines/v9-baseline.md`
- Modify: `PROJECT_MANIFEST.txt`, `PROJECT_SHA256SUMS.txt`

**Interfaces:**
- Consumes: artefato v9 da conversa.
- Produces: árvore v9 no GitHub que os próximos tasks modificam.

- [ ] **Step 1: Registrar o baseline conhecido**

Criar `docs/superpowers/baselines/v9-baseline.md`:

```markdown
# v9 baseline

Validation before v10 work:
- static_validate.py: PASS
- server_side_contract_test.py: PASS
- audit_kernel_surface.py: PASS

Archive SHA-256: <computed from imported archive>
Source files: 199
Code files reported by static validator: 136
Code lines reported by static validator: 10798
```

- [ ] **Step 2: Importar os arquivos da v9 sem criar pasta de versão**

A raiz do repositório deve conter `CMakeLists.txt`, `src/`, `include/`, `kernel/`, `config/`, `scripts/`, `tests/` e docs da v9. Não criar `v9/` ou `v10/`.

- [ ] **Step 3: Rodar o baseline**

Run:
```bash
python scripts/static_validate.py
python scripts/server_side_contract_test.py
python scripts/audit_kernel_surface.py
```

Expected:
```text
STATIC VALIDATION PASSED
SERVER-SIDE CONTRACT TEST PASSED
KERNEL SURFACE AUDIT PASS
```

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "chore: import v9 baseline for v10 hardening"
```

---

### Task 2: Versionar e endurecer IPC cliente → serviço

**Files:**
- Modify: `include/ac/service_ipc.hpp`
- Modify: `src/common/service_ipc.cpp`
- Modify: `src/service/main.cpp`
- Modify: `src/client/main.cpp`
- Create: `tests/service_ipc_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `ServiceRequest`, `ServiceResponse`.
- Produces:
  - `ServiceRequestV10` com `struct_size`, `version`, `request_id`, `client_pid`, `session_id`, `sequence`, `nonce`, `Mac request_mac`.
  - `ServiceResponseV10` com echo de `request_id`, `sequence`, health state e prova autenticada.

- [ ] **Step 1: Escrever teste de rejeição por versão/tamanho**

```cpp
TEST(ServiceIpc, RejectsTruncatedAndWrongVersion) {
    ac::ServiceRequest req{};
    req.struct_size = sizeof(req) - 1;
    EXPECT_FALSE(ac::validate_service_request_header(req));

    req.struct_size = sizeof(req);
    req.version = ac::kServiceVersion + 1;
    EXPECT_FALSE(ac::validate_service_request_header(req));
}
```

- [ ] **Step 2: Rodar e confirmar FAIL**

Run:
```bash
ctest --test-dir build -R service_ipc --output-on-failure
```

Expected: FAIL porque `validate_service_request_header` ainda não existe.

- [ ] **Step 3: Implementar cabeçalho v10 e validação**

Em `include/ac/service_ipc.hpp`:

```cpp
constexpr std::uint16_t kServiceVersion = 10;

enum class ServiceHealth : std::uint32_t {
    Healthy = 0,
    Degraded = 1,
    Untrusted = 2,
};

#pragma pack(push, 1)
struct ServiceRequest {
    std::uint32_t magic = kServiceMagic;
    std::uint16_t version = kServiceVersion;
    std::uint16_t struct_size = sizeof(ServiceRequest);
    std::uint64_t request_id = 0;
    std::uint64_t session_id = 0;
    std::uint64_t sequence = 0;
    std::uint64_t unix_time = 0;
    std::uint32_t client_pid = 0;
    std::uint32_t game_pid = 0;
    std::array<std::uint8_t, 16> nonce{};
    Digest attestation_nonce{};
    std::uint32_t required_pcr_mask = 0x00FFFFFFu;
    Mac request_mac{};
};
#pragma pack(pop)

bool validate_service_request_header(const ServiceRequest&) noexcept;
```

Validação deve checar magic, versão, tamanho exato, PID não zero, nonce não zero e freshness antes de qualquer uso de campos variáveis.

- [ ] **Step 4: Adicionar anti-replay por `request_id + sequence + nonce`**

O serviço mantém janela LRU limitada por PID/sessão. A entrada só é consumida depois de MAC/freshness passarem.

- [ ] **Step 5: Testar replay e MAC inválido**

Adicionar teste que envia a mesma sequência duas vezes e confirma que a segunda é rejeitada; alterar um byte do request e confirmar falha de MAC.

- [ ] **Step 6: Rodar testes**

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

- [ ] **Step 7: Commit**

```bash
git add include/ac/service_ipc.hpp src/common/service_ipc.cpp src/service/main.cpp src/client/main.cpp tests/service_ipc_tests.cpp CMakeLists.txt
git commit -m "feat: harden authenticated service IPC"
```

---

### Task 3: Endurecer ABI e health telemetry do driver

**Files:**
- Modify: `kernel/include/guard_shared.h`
- Modify: `kernel/driver/device.c`
- Modify: `kernel/driver/events.c`
- Modify: `kernel/driver/policy.c`
- Modify: `src/common/kernel_driver.cpp`
- Modify: `include/ac/kernel_driver.hpp`
- Modify: `tests/kernel_abi_tests.cpp`
- Modify: `scripts/audit_kernel_surface.py`

**Interfaces:**
- Consumes: IOCTLs atuais.
- Produces: ABI `0x000A0001`, request envelope versionado e `GuardHealthResponse`.

- [ ] **Step 1: Escrever testes de layout/ABI**

```cpp
static_assert(GUARD_DRIVER_ABI_VERSION == 0x000A0001u);
static_assert(sizeof(GuardRequestHeader) == 24);
static_assert(sizeof(GuardPingResponse) >= sizeof(GuardRequestHeader));
```

- [ ] **Step 2: Adicionar envelope comum**

```c
typedef struct GuardRequestHeader {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t session_id;
    uint64_t monotonic_sequence;
} GuardRequestHeader;
```

Todo IOCTL mutável começa com esse header e valida:
- `InputBufferLength >= struct_size`
- `struct_size == sizeof(expected)`
- ABI exata
- sequência monotônica para a sessão ativa
- PIDs consistentes com o serviço que configurou a proteção.

- [ ] **Step 3: Adicionar health response sem abrir nova primitiva poderosa**

```c
typedef struct GuardHealthResponse {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t monotonic_counter;
    uint64_t event_sequence;
    uint64_t dropped_events;
    uint32_t protected_client_pid;
    uint32_t protected_game_pid;
    uint32_t policy_flags;
    uint32_t callbacks_ready_mask;
} GuardHealthResponse;
```

- [ ] **Step 4: Expandir auditor**

Falhar se aparecer:
```text
METHOD_NEITHER
MmMapIoSpace
MmCopyVirtualMemory
ZwMapViewOfSection
__writecr0
KeStackAttachProcess
```

Permitir somente IOCTLs explicitamente listados em `guard_shared.h`.

- [ ] **Step 5: Rodar testes/auditor**

```bash
python scripts/audit_kernel_surface.py
ctest --test-dir build -R kernel_abi --output-on-failure
```

- [ ] **Step 6: Commit**

```bash
git add kernel include/ac/kernel_driver.hpp src/common/kernel_driver.cpp tests/kernel_abi_tests.cpp scripts/audit_kernel_surface.py
git commit -m "feat: harden kernel ABI and health telemetry"
```

---

### Task 4: Introduzir health state unificado e attestation freshness

**Files:**
- Create: `include/ac/health_state.hpp`
- Create: `src/common/health_state.cpp`
- Modify: `src/client/main.cpp`
- Modify: `src/service/main.cpp`
- Modify: `src/backend/Models/AdmissionReport.cs`
- Modify: `src/backend/Services/AdmissionPolicy.cs`
- Create: `tests/health_state_tests.cpp`

**Interfaces:**
- Produces:
```cpp
enum class HealthState : std::uint8_t { Healthy, Degraded, Untrusted };

struct HealthInputs {
    bool service_authenticated;
    bool driver_present;
    bool driver_callbacks_ready;
    bool platform_attestation_fresh;
    bool measured_boot_valid;
    bool runtime_attestation_verified;
    std::uint64_t last_service_ms;
    std::uint64_t last_driver_ms;
};
HealthState evaluate_health(const HealthInputs&, std::uint64_t now_ms) noexcept;
```

- [ ] **Step 1: Escrever tabela de testes**

Casos mínimos:
- tudo válido → Healthy;
- serviço velho → Untrusted;
- driver ausente → Untrusted;
- runtime attestation indisponível mas política não obrigatória → Degraded;
- measured boot falha quando obrigatório → Untrusted.

- [ ] **Step 2: Implementar função pura e integrar**

Cliente envia health state; backend recalcula a partir das evidências e nunca confia cegamente no enum do cliente.

- [ ] **Step 3: Adicionar freshness configurável**

Em `GuardOptions.cs`:
```csharp
public int MaxServiceAttestationAgeSeconds { get; set; } = 10;
public int MaxKernelHealthAgeSeconds { get; set; } = 10;
public int MaxPlatformAttestationAgeSeconds { get; set; } = 30;
```

- [ ] **Step 4: Rodar testes e commit**

```bash
ctest --test-dir build -R health_state --output-on-failure
dotnet run --project src/backend_selftest/GuardBackendSelfTest.csproj
git commit -am "feat: add unified anti-cheat health state"
```

---

### Task 5: Integrar telemetria autoritativa real do game server CSGO

**Files:**
- Modify: `include/ac/game_server_sdk.hpp`
- Modify: `src/server_sdk/game_server_sdk.cpp`
- Modify: `src/examples/game_server_integration.cpp`
- Modify: `src/backend/Models/MatchTelemetryEvent.cs`
- Create: `docs/GAME_SERVER_TELEMETRY_V10.md`
- Create: `tests/game_server_sdk_tests.cpp`

**Interfaces:**
- Produces:
```cpp
struct AuthoritativePlayerFrame {
    std::uint64_t tick;
    std::uint64_t command_number;
    std::uint64_t command_tick;
    std::uint64_t tick_base;
    Vec3 origin;
    Vec3 velocity;
    QAngle view_angles;
    QAngle aim_punch;
    std::uint32_t buttons;
    bool on_ground;
    bool alive;
    WeaponState weapon;
};

struct AuthoritativeTargetFrame {
    SteamId64 player;
    std::uint64_t tick;
    Vec3 origin;
    bool alive;
    bool visible;
};
```

- [ ] **Step 1: Testar serialização do frame**

Criar frame com valores de limite, serializar e confirmar round-trip exato e tamanho máximo.

- [ ] **Step 2: Implementar builder server-only**

A API do SDK deve aceitar dados já lidos do estado do servidor/jogo. Não expor função que aceite um blob produzido pelo cliente.

- [ ] **Step 3: Vincular batch a `server_id + match_id + session_id + tick range`**

Cada batch assinado contém:
```text
server_id
match_id
player_id
session_id
first_tick
last_tick
sequence
nonce
payload_sha256
HMAC
```

- [ ] **Step 4: Backend rejeita batch sem autoridade ativa**

`MatchAuthorityRegistry` deve confirmar que `server_id/match_id/session_id/player_id` estão vinculados antes do pipeline de detectores.

- [ ] **Step 5: Testar replay, troca de jogador e tick range inválido**

- [ ] **Step 6: Commit**

```bash
git add include/ac/game_server_sdk.hpp src/server_sdk src/examples src/backend/Models src/backend/Services/MatchAuthorityRegistry.cs tests/game_server_sdk_tests.cpp docs/GAME_SERVER_TELEMETRY_V10.md
git commit -m "feat: integrate authoritative CSGO server telemetry"
```

---

### Task 6: Refinar detector pipeline e reduzir falso positivo correlacionado

**Files:**
- Modify: `src/backend/Detection/DetectorPipeline.cs`
- Modify: `src/backend/Detection/DetectionContext.cs`
- Modify: `src/backend/Detection/MatchPlayerState.cs`
- Modify: detectores em `src/backend/Detection/Detectors/`
- Modify: `src/backend/Services/EvidenceQuorum.cs`
- Modify: `src/backend/Services/GuardOptions.cs`
- Modify: `src/backend_selftest/Program.cs`

**Interfaces:**
- Produces: sinais com `Family`, `Kind`, `Confidence`, `HighConfidence`, `SourceWindowId` e `CorrelationGroup`.

- [ ] **Step 1: Adicionar metadados de correlação**

Em `DetectionSignal.cs`:
```csharp
public string SourceWindowId { get; init; } = "";
public string CorrelationGroup { get; init; } = "";
```

- [ ] **Step 2: Testar quorum contra sinais correlacionados**

Um `aim-snap`, `reaction-time` e `first-shot` derivados do mesmo tiro não podem contar como três famílias independentes quando compartilham o mesmo `CorrelationGroup`.

- [ ] **Step 3: Refinar arma/recoil/lag compensation**

- usar `WeaponProfileCatalog` como autoridade de cycle time/max speed;
- recoil only quando profile hash válido;
- lag compensation only quando target snapshot é do histórico server-side;
- suprimir detector quando dado necessário não é autoritativo/validado.

- [ ] **Step 4: Introduzir estabilidade temporal**

Um detector estatístico só vira high-confidence após pelo menos duas janelas independentes separadas no tempo.

- [ ] **Step 5: Rodar selftests**

```bash
dotnet run --project src/backend_selftest/GuardBackendSelfTest.csproj
python scripts/server_side_contract_test.py
```

- [ ] **Step 6: Commit**

```bash
git add src/backend src/backend_selftest scripts/server_side_contract_test.py
git commit -m "feat: refine evidence correlation and detector confidence"
```

---

### Task 7: Replay corpus, comparação entre versões e calibração

**Files:**
- Modify: `src/backend/Services/TelemetryReplayStore.cs`
- Modify: `src/replaytool/Program.cs`
- Modify: `scripts/calibrate_detectors.py`
- Create: `scripts/compare_detector_versions.py`
- Create: `docs/DETECTOR_CALIBRATION_V10.md`
- Create: `tests/replay_fixture/`

**Interfaces:**
- Replay output:
```json
{
  "schema": 10,
  "match_id": "...",
  "server_id": "...",
  "build_id": "...",
  "weapon_profile_set_sha256": "...",
  "events": []
}
```

- [ ] **Step 1: Criar fixtures determinísticos**

Criar pequeno fixture limpo e fixture sintético com violações explícitas de protocolo/tick para teste, sem modelar cheat real de forma ofensiva.

- [ ] **Step 2: Replay deve reproduzir os mesmos sinais**

Rodar duas vezes o mesmo replay e comparar JSON normalizado; deve ser byte-equivalente exceto timestamps de execução fora do resultado.

- [ ] **Step 3: Implementar comparação v9/v10**

`compare_detector_versions.py` recebe dois summaries e produz:
```text
new_signals
removed_signals
changed_confidence
clean_false_positive_delta
known_violation_coverage_delta
```

- [ ] **Step 4: Gate de promoção**

`calibrate_detectors.py` deve sair com código != 0 se um detector novo exceder o limite configurado de falso positivo em corpus limpo.

- [ ] **Step 5: Commit**

```bash
git add src/replaytool src/backend/Services/TelemetryReplayStore.cs scripts docs/DETECTOR_CALIBRATION_V10.md tests/replay_fixture
git commit -m "feat: add reproducible detector replay calibration"
```

---

### Task 8: CI, secret scanning e release ZIP reproduzível

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/windows-driver.yml`
- Create: `scripts/release_zip.py`
- Modify: `scripts/static_validate.py`
- Modify: `scripts/build_all.ps1`
- Modify: `TEST_STATUS.md`
- Modify: `BUILD_REPORT.md`

**Interfaces:**
- Produces: `dist/CSGO_Guard_v10.zip` + `dist/CSGO_Guard_v10.sha256`.

- [ ] **Step 1: CI portátil**

Linux runner:
```yaml
- run: python scripts/static_validate.py
- run: python scripts/server_side_contract_test.py
- run: python scripts/audit_kernel_surface.py
- run: python scripts/calibrate_detectors.py --self-test
```

Windows runner:
```yaml
- run: cmake --preset vs2022-x64
- run: cmake --build --preset vs2022-x64-release
- run: dotnet build src/backend/GuardBackend.csproj -c Release
- run: dotnet build src/backend_selftest/GuardBackendSelfTest.csproj -c Release
```

Driver workflow deve compilar apenas quando WDK estiver disponível e nunca autoassinar como se fosse produção.

- [ ] **Step 2: Secret scan**

`static_validate.py` falha para:
```text
-----BEGIN PRIVATE KEY-----
CHANGE-ME
api_key=<non-example>
*.pfx
*.key
```
exceto fixtures explicitamente allowlisted.

- [ ] **Step 3: ZIP determinístico**

`release_zip.py`:
- ordena caminhos;
- normaliza timestamp ZIP;
- exclui `.git`, `build`, `dist`, secrets e binários temporários;
- gera SHA-256.

- [ ] **Step 4: Rodar pipeline local disponível**

```bash
python scripts/static_validate.py
python scripts/server_side_contract_test.py
python scripts/audit_kernel_surface.py
python scripts/release_zip.py --version v10
```

- [ ] **Step 5: Commit**

```bash
git add .github scripts TEST_STATUS.md BUILD_REPORT.md
git commit -m "ci: add v10 security and release pipeline"
```

---

### Task 9: Revisão final, merge e entrega do patch v10

**Files:**
- Modify: `README.md`
- Modify: `SECURITY.md`
- Create: `CHANGELOG_V10.md`
- Update generated manifests/hashes.

**Interfaces:**
- Produces: main atualizado + ZIP enviado na conversa.

- [ ] **Step 1: Rodar verificação completa possível**

```bash
python scripts/static_validate.py
python scripts/server_side_contract_test.py
python scripts/audit_kernel_surface.py
```

No Windows/Visual Studio:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_all.ps1 -Configuration Release
powershell -ExecutionPolicy Bypass -File .\scripts\validate_security.ps1
```

- [ ] **Step 2: Conferir que nenhum segredo entrou no Git**

Buscar chaves, certificados privados e credenciais.

- [ ] **Step 3: Gerar release**

```bash
python scripts/release_zip.py --version v10
```

- [ ] **Step 4: Revisar diff contra baseline v9**

Confirmar:
- nenhuma remoção acidental de detector;
- nenhum IOCTL ofensivo novo;
- nenhum campo de gameplay passou a confiar no cliente;
- ABI/protocol versions coerentes;
- docs e configs correspondem ao código.

- [ ] **Step 5: Merge e entrega**

Atualizar `main` para o estado v10 revisado e fornecer `CSGO_Guard_v10.zip` no chat.
