# CSGO Guard v10 Hardening Design

## Objetivo

Evoluir a CSGO Guard v9 para uma v10 mais forte sem reescrever o projeto do zero. A v10 preserva componentes válidos da v9 e substitui apenas implementações frágeis, genéricas ou pouco testadas.

O repositório representa sempre o estado atual do produto. Não haverá pastas v9/v10 lado a lado no `main`; o histórico do Git preservará versões anteriores. Cada patch fechado também terá um ZIP exportado para inspeção local no VS Code/Visual Studio.

## Princípios

- Segurança real acima de contagem artificial de linhas/arquivos.
- Telemetria server-side autoritativa: o cliente do jogador nunca é autoridade sobre sua própria detecção.
- Defesa em profundidade: plataforma, serviço, driver, cliente, protocolo e backend devem se validar mutuamente.
- Nenhum detector comportamental isolado deve causar ban automático sem quorum de evidências.
- Nada de técnicas de rootkit, bypass de PatchGuard, leitura/escrita arbitrária de memória física ou primitivas de kernel que aumentem a superfície ofensiva.
- Compatibilidade com HVCI/VBS e APIs documentadas do Windows.
- Segredos fora do repositório; builds e testes devem falhar quando configuração insegura for usada em modo de produção.
- Toda mudança relevante deve ter teste ou validação automática correspondente.

## Escopo da v10

### 1. Client-side

Preservar a arquitetura atual de launcher + cliente + serviço SYSTEM + driver e aprofundar:

- IPC autenticado entre cliente e serviço, com binding a PID, sessão e identidade da instalação.
- Rotação/derivação de credenciais de sessão e anti-replay em todos os canais.
- Verificação de integridade do cliente, serviço e driver por manifesto versionado.
- Coleta de postura: Secure Boot, UEFI, TPM 2.0, Measured Boot, VBS, HVCI, IOMMU/DMA protection, Secure Launch e políticas de Code Integrity.
- TPM/AIK e atestação PCR desafiada pelo servidor.
- Coleta do Secure Kernel Runtime Attestation Report quando disponível, mantendo o backend como verificador final.
- Monitoramento defensivo de módulos/imagens/processos e regiões executáveis do jogo, sem varrer memória arbitrária de terceiros.
- Proteção de handles e callbacks kernel já existentes, revisados para superfície mínima.
- Watchdog/health state do cliente, serviço e driver com estado explícito `healthy/degraded/untrusted`.

### 2. Driver kernel

Preservar o driver atual e endurecer:

- IOCTL mínimo, com ACL SYSTEM-only.
- Validação rigorosa de tamanho, versão e origem de cada request.
- Nenhuma interface genérica de read/write de memória.
- Callbacks documentados de processo/thread/image/handle.
- Proteção do processo do anti-cheat e do processo do jogo contra handles perigosos.
- Telemetria kernel com contadores monotônicos, nonce e binding de sessão.
- Compatibilidade HVCI, NX e ausência de memória W+X.
- Auditor automático que falha se APIs perigosas ou padrões proibidos aparecerem.

### 3. Server-side e gameplay

Aprimorar a v9, não substituir tudo:

- Perfis de arma por build do CSGO.
- Fire-rate por arma e modo de disparo.
- Recoil model específico por arma quando dados confiáveis estiverem disponíveis.
- Histórico autoritativo de alvo/posição por tick.
- Lag-compensation-aware target history.
- Aim acquisition, aim snap, aim lock, reaction time e recoil analisados por janela estatística.
- Bunnyhop, fast-duck e input automation com thresholds calibráveis.
- Tick manipulation, choke, interpolation/NoLerp e regressões temporais.
- Movimento impossível e domínio de ângulos.
- First-shot accuracy, fire-control e weapon-state sanity.
- Quorum entre famílias independentes antes de ban automático.
- Estados separados: allow, observe, review, deny e ban.

### 4. Replay e calibração

- Captura JSONL autoritativa de partidas com limites de tamanho.
- Replay offline reproduzível.
- Corpus separado de jogadores limpos e cheats conhecidos.
- Relatórios por detector: prevalência em limpos, cobertura em cheats, precisão, falsos positivos e estabilidade temporal.
- Thresholds de produção não devem ser promovidos sem dados suficientes.
- Ferramenta para comparar comportamento entre versões do detector.

### 5. Backend e protocolo

- Protocolo versionado com HMAC/assinatura, freshness, sequência e anti-replay.
- Credenciais por jogador/instalação e por game server.
- Validação de attestation antes de admission.
- Snapshot assinado de sessão e join authorization.
- Rate limiting e payload bounds.
- Ledger de ban/revogação encadeado por hash e autenticado.
- Configuração de produção deve rejeitar `CHANGE-ME`, segredos vazios e políticas incompletas.

### 6. Steam

A identidade Steam visual continuará vindo da conta Steam local para UI, mas autorização forte por Steam ticket fica para fase posterior, como combinado.

Quando implementada:
- ticket é validado exclusivamente pelo backend;
- SteamID64 do cliente local não é tratado como prova de identidade;
- launcher reflete nome/avatar atuais da conta validada.

### 7. CI, testes e release

Adicionar/fortalecer GitHub Actions para:

- validação estática;
- build CMake portátil quando aplicável;
- build .NET;
- testes unitários e contratos;
- scan de segredos;
- auditor de superfície kernel;
- validação de configs;
- replay smoke tests;
- verificação de ZIP/release artifact.

Build real do driver Windows/WDK, TPM físico, Driver Verifier e HLK permanecem como validação em máquina Windows compatível.

## Fluxo Git

- `main`: melhor versão estável atual.
- trabalho de v10 em branch dedicada;
- commits pequenos por subsistema;
- revisão antes de merge;
- merge da v10 substitui o estado anterior no `main`;
- histórico do Git preserva a v9;
- cada patch fechado gera ZIP correspondente para inspeção local.

## Critérios de sucesso da v10

1. Nenhuma regressão nos contratos de segurança da v9.
2. Mais cobertura automatizada de client-side, driver, protocolo e server-side.
3. Menos dependência de thresholds genéricos.
4. Mais sinais autoritativos do game server e menos confiança no cliente.
5. Superfície kernel igual ou menor apesar do aumento de capacidade.
6. Replay/calibração capazes de medir falso positivo de forma reproduzível.
7. Pipeline CI rejeita configuração insegura e regressões conhecidas.
8. Cada patch relevante pode ser reproduzido do GitHub e entregue também como ZIP.

## Fora de escopo desta rodada

- bypass de PatchGuard;
- driver unsigned em produção;
- leitura/escrita arbitrária de memória física;
- técnicas de rootkit;
- ban automático baseado em um único detector comportamental;
- autenticação Steam ticket final;
- afirmação de compatibilidade total com hardware/TPM sem teste real em Windows.
