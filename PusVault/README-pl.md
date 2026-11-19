> 🌐 **Dokumentacja w dwóch językach / Documentation in two languages:**  
> 🇬🇧 **[English (README.md)](./README.md)** | 🇵🇱 **Polski (Aktualny)**

# PUS-Vault - Bezpieczny Menedżer Sekretów i Konfiguracji (PVSP v1.0)

[![.NET](https://img.shields.io/badge/.NET-8.0.134-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Language](https://img.shields.io/badge/C%23-12-239120?logo=csharp&logoColor=white)](https://learn.microsoft.com/en-us/dotnet/csharp/)
[![Protocol](https://img.shields.io/badge/Protok%C3%B3%C5%82-PVSP%20v1.0-0A66C2)](../Assets/projekt-protoko%C5%82u.pdf)
[![Security](https://img.shields.io/badge/Bezpiecze%C5%84stwo-TLS%201.3%20%2B%20HMAC--SHA256-2EA043)](./src/Pus.Vault.Common/PvspCryptoHelper.cs)
[![Tests](https://img.shields.io/badge/Testy-32%2F32%20Zaliczonych-brightgreen)](./tests/Pus.Vault.Tests/)
[![CI/CD](https://github.com/zephir-x/pk-pus/actions/workflows/pus-vault-ci.yml/badge.svg)](https://github.com/zephir-x/pk-pus/actions/workflows/pus-vault-ci.yml)
[![Docker](https://img.shields.io/badge/Docker-Multi--Stage%20%2B%20Compose-2496ED?logo=docker&logoColor=white)](./Dockerfile)
[![Platform](https://img.shields.io/badge/System-Linux%20%2F%20WSL2%20Ubuntu%2024.04-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/)

Stanowy, wielowątkowy menedżer sekretów i konfiguracji w architekturze Klient–Serwer, zrealizowany w **.NET 8 (C#)** w ramach przedmiotu **Programowanie Usług Sieciowych (PUS)**. Komunikacja odbywa się wyłącznie z wykorzystaniem autorskiego protokołu aplikacyjnego **PVSP v1.0 (PUS-Vault Secret Protocol)** bezpośrednio na surowych gniazdach strumieniowych `System.Net.Sockets.Socket` (TCP Dual-Stack IPv6 + IPv4-mapped), z obowiązkowym szyfrowaniem **TLS 1.3** (własny Urząd Certyfikacji - Custom Root CA) oraz kanonicznym uwierzytelnianiem wiadomości **HMAC-SHA256**.

---

## Spis treści

1. [Przegląd projektu](#1-przegląd-projektu)
2. [Architektura i struktura repozytorium](#2-architektura-i-struktura-repozytorium)
3. [Protokół PVSP v1.0 w pigułce](#3-protokół-pvsp-v10-w-pigułce)
4. [Wymagania środowiskowe](#4-wymagania-środowiskowe)
5. [Instrukcja uruchomienia](#5-instrukcja-uruchomienia)
6. [Komendy CLI i konfiguracja](#6-komendy-cli-i-konfiguracja)
7. [Testy automatyczne i raport wydajności](#7-testy-automatyczne-i-raport-wydajności)
8. [Scenariusze demonstracyjne na żywo](#8-scenariusze-demonstracyjne-na-żywo)
9. [Znane ograniczenia](#9-znane-ograniczenia)
10. [Autorzy i dokumentacja powiązana](#10-autorzy-i-dokumentacja-powiązana)

---

## 1. Przegląd projektu

**PUS-Vault** centralizuje poufne dane konfiguracyjne (klucze API, hasła bazodanowe, tokeny dostępowe) w jednym serwerowym magazynie typu klucz–wartość dostępnym przez interaktywnego klienta konsolowego CLI. Zamiast korzystać z wysokopoziomowych wrapperów sieciowych (`TcpClient`, `TcpListener`, `HttpClient`), cała komunikacja sieciowa oraz ramkowanie strumienia zostały zaimplementowane bezpośrednio na gniazdach `System.Net.Sockets.Socket` owiniętych w `SslStream`.

### Główne możliwości systemu
- **Niskopoziomowe gniazda Dual-Stack:** Pojedyncze gniazdo nasłuchujące IPv6 (`DualMode = true`) na porcie `8443/TCP`, obsługujące jednocześnie klientów IPv6 (`::1`) oraz IPv4 (`127.0.0.1` mapowane jako `::ffff:127.0.0.1`), z konfigurowalnymi limitami (`--max-sessions` / `--max-handshakes`), ograniczonym timeoutem kolejki handshake'u TLS (`10s`) oraz czystym zamykaniem na `SIGINT`/`SIGTERM`.
- **Hybrydowe ramkowanie (Binarny Nagłówek + JSON):** Stały **12-bajtowy nagłówek binarny Big-Endian** (`Magic=0x5053`, `Version=0x01`, `Type`, `MessageId`, `PayloadLength`) połączony ze ścisłym ładunkiem UTF-8 JSON oraz jawną pętlą odczytu `ReadExactly`, eliminującą problem fragmentacji TCP (*partial reads*).
- **Wielowarstwowe bezpieczeństwo (*Defense-in-Depth*):**
    - Obowiązkowy **TLS 1.3** z weryfikacją certyfikatu względem prywatnego **Custom Root CA** (`X509ChainTrustMode.CustomRootTrust`), walidacją nazwy hosta/SAN oraz rozszerzenia EKU `serverAuth`.
    - Przechowywanie haseł wyłącznie jako skróty **PBKDF2-HMAC-SHA256** (16-bajtowa losowa sól, 600 000 iteracji), ścisłe stałoczasowe wyzwanie `serverNonceEcho` (`<= 32 B`), 256-bitowy token sesji CSPRNG (`sessionToken`) oraz progresywny *backoff* z TTL 15 min i limitem `4096` wpisów przeciwko atakom *brute-force*.
    - Kanoniczne podpisy **HMAC-SHA256** per sesja (binarny format z prefiksami długości, porównanie stałoczasowe `FixedTimeEquals`), ściśle monotoniczne `Message ID`, izolowany bufor duplikatów `DATA_REQ`, odporne na przepełnienie okno czasowe Anti-Replay $\pm 30\text{s}$, escapowanie znaków sterujących/ANSI (`\u001b`) w logach audytowych oraz sanityzowane/limitowane ramki `ERROR` (`<= 512 B` UTF-8 bez odbijania nieznanych nazw pól i akcji).
    - Bezwzględne deadline'y faz (`10s` HELLO, `15s` AUTH, reset `60s` Idle wyłącznie po poprawnych ramkach), kontrola dostępu oparta na rolach **RBAC** (`READ_WRITE` vs `READ_ONLY`) oraz *Sliding Window Rate Limiter* (`20 DATA_REQ / 10s`).
- **Odporność i persystencja:** Serializowany, atomowy zapis magazynu za abstrakcją `IVaultStorage` (`vault_store.json.tmp` -> `Flush(true)` -> `File.Move` z uprawnieniami `0600` i walidacją zepsutego/`null` JSON przy starcie), wątek tła `PING`/`PONG` co 20s z natychmiastowym zamykaniem zerwanego transportu i odzyskiwaniem sesji, dedykowany 10s timeout handshake'u TLS po stronie klienta, bezpieczna deserializacja odpowiedzi serwera, ustrukturyzowane logi UTC klienta oraz reaktywny *Auto-Reconnect* (`1s`, `2s`, `4s`) ponawiający automatycznie wyłącznie bezpieczne operacje `GET`, `LIST` i `PING` (bez cichego retry mutacji `SET`/`DELETE` po rozpoczęciu wysyłki).

> 📸 **Podgląd interaktywnej sesji CLI**  
> ![PUS-Vault Demo CLI](./docs/demo-cli-session.gif)

---

## 2. Architektura i struktura repozytorium

### Diagram komponentów i wdrożenia

```mermaid
flowchart LR
    subgraph ClientHost ["Stacja Klienta (WSL2 / Kontener Docker)"]
        direction TB
        CLI["CliCommandLoop<br/>(REPL CLI i ukryty prompt)"] --> CEngine["PvspClientEngine<br/>(Semafor I/O, Retry i Reconnect)"]
        KA["KeepAliveWorker<br/>(PING co 20s)"] --> CEngine
        CEngine --> CA_Cert[("certs/ca.crt<br/>(Wlasny Root CA)")]
    end

    subgraph CommonLib ["Pus.Vault.Common"]
        direction TB
        Codec["PvspFrameCodec<br/>(12B Big-Endian + ReadExactly)"]
        Crypto["PvspCryptoHelper<br/>(Kanoniczny HMAC, PBKDF2, X.509)"]
    end

    subgraph ServerHost ["Stacja Serwera (WSL2 / Kontener Docker)"]
        direction TB
        Listener["SocketConnectionListener<br/>(Surowy Socket Dual-Stack + SslStream)"] --> Srv_Cert[("certs/server.crt<br/>certs/server.key")]
        Listener --> Session["ClientSessionHandler<br/>(Maszyna Stanow, Anti-Replay, Rate Limit)"]
        Session --> Auth["AuthAndRbacModule<br/>(PBKDF2, Role RBAC, Backoff)"]
        Auth --> Users_File[("config/users.json<br/>(Hashe PBKDF2, 0600)")]
        Session --> Storage["IVaultStorage / VaultStorageEngine<br/>(Atomowy Snapshot na dysk)"]
        Storage <--> DB_File[("data/vault_store.json<br/>(Plaintext MVP, 0600)")]
        Session --> Logger["SecurityAuditLogger<br/>(Oczyszczone logi audytowe)"]
    end

    CEngine <==>|"TCP Port 8443<br/>TLS 1.3 + PVSP v1.0"| Listener
    CEngine -.-> Codec
    CEngine -.-> Crypto
    Session -.-> Codec
    Session -.-> Crypto
```

### Drzewo katalogów i linki do kodu źródłowego

```text
PusVault/
├── PusVault.sln                             # Solucja .NET 8 spinająca wszystkie 4 projekty
├── Dockerfile                               # Wieloetapowy obraz (sdk:8.0 -> lekkie runtime:8.0 server/client)
├── docker-compose.yml                       # Izolowana sieć bridge, nazwane wolumeny, certyfikaty :ro
├── .dockerignore                            # Blokuje dodawanie certyfikatów, sekretów i danych do obrazów
├── .env.example                             # Szablon początkowych haseł dla uruchomienia w Dockerze
├── README.md / README-pl.md                 # Dwujęzyczna dokumentacja projektu (EN / PL)
├── scripts/
│   └── generate_certs.sh                    # Skrypt OpenSSL: Custom Root CA oraz certyfikat serwera (SAN + EKU)
├── src/
│   ├── Pus.Vault.Common/                    # Wspólna biblioteka protokołu PVSP v1.0 i kryptografii
│   │   ├── ErrorCodes.cs                    # Stałe protokołu, typy ramek, stany sesji i kody błędów (100-500)
│   │   ├── PvspModels.cs                    # Modele DTO JSON oraz rygorystyczny walidator UTF-8 (bez odbijania nazw pól)
│   │   ├── PvspFrameCodec.cs                # Kodek 12B Big-Endian i pętla ReadExactlyLoopAsync
│   │   └── PvspCryptoHelper.cs              # Kanoniczny HMAC-SHA256, PBKDF2, 256-bit CSPRNG, CustomRootTrust
│   ├── Pus.Vault.Server/                    # Wielowątkowy serwer magazynu TLS 1.3
│   │   ├── Program.cs                       # Flagi CLI/env (--port, --max-sessions, --max-handshakes), SIGINT/SIGTERM
│   │   ├── SocketConnectionListener.cs      # Surowe gniazdo Dual-Stack TCP + SslStream TLS 1.3 + limitowany handshake
│   │   ├── ClientSessionHandler.cs          # Maszyna stanów, bezwzględne deadline'y, Anti-Replay, izolowany cache duplikatów
│   │   ├── AuthAndRbacModule.cs             # PBKDF2, ochrona timingowa, ścisły nonce, backoff TTL/4096, RBAC
│   │   ├── VaultStorageEngine.cs            # Interfejs IVaultStorage + atomowy snapshot i walidacja null/uszkodzeń
│   │   └── SecurityAuditLogger.cs           # Logger z pełnym escapowaniem znaków sterujących/ANSI i rotacją pliku
│   └── Pus.Vault.Client/                    # Interaktywny klient CLI
│       ├── Program.cs                       # Parser flag startowych (--host, --port, --ca, --diagnostics)
│       ├── CliCommandLoop.cs                # Pętla REPL oraz ukryty odczyt haseł i sekretów bez echa
│       ├── PvspClientEngine.cs              # Semafor I/O, 10s TLS timeout, bezpieczny JSON, logi UTC, Auto-Reconnect
│       └── KeepAliveWorker.cs               # Wątek tła wysyłający PING co 20s bezczynności
└── tests/
    └── Pus.Vault.Tests/                     # Zestaw testów automatycznych xUnit (32 testy: T-01..T-12 + utwardzenie P1–P3)
        ├── ProtocolAndCryptoUnitTests.cs    # Wektory HMAC, CSPRNG, partial reads, framing, walidacja JSON, X.509 (6 testów)
        ├── ServerStorageAndAuthTests.cs     # IVaultStorage, współbieżność, błąd dysku, RBAC, audyt, reguły sesji (12 testów)
        └── PvspEndToEndSessionTests.cs      # Żywe TLS CRUD, T-03/T-05/T-06/T-08, IPv6/KeepAlive, 50 klientów GET+SET (14 testów)
```

| Moduł | Katalog źródłowy | Kluczowe pliki implementacji |
| :--- | :--- | :--- |
| **`Pus.Vault.Common`** | [`src/Pus.Vault.Common/`](./src/Pus.Vault.Common/) | [`ErrorCodes.cs`](./src/Pus.Vault.Common/ErrorCodes.cs), [`PvspModels.cs`](./src/Pus.Vault.Common/PvspModels.cs), [`PvspFrameCodec.cs`](./src/Pus.Vault.Common/PvspFrameCodec.cs), [`PvspCryptoHelper.cs`](./src/Pus.Vault.Common/PvspCryptoHelper.cs) |
| **`Pus.Vault.Server`** | [`src/Pus.Vault.Server/`](./src/Pus.Vault.Server/) | [`Program.cs`](./src/Pus.Vault.Server/Program.cs), [`SocketConnectionListener.cs`](./src/Pus.Vault.Server/SocketConnectionListener.cs), [`ClientSessionHandler.cs`](./src/Pus.Vault.Server/ClientSessionHandler.cs), [`AuthAndRbacModule.cs`](./src/Pus.Vault.Server/AuthAndRbacModule.cs), [`VaultStorageEngine.cs`](./src/Pus.Vault.Server/VaultStorageEngine.cs), [`SecurityAuditLogger.cs`](./src/Pus.Vault.Server/SecurityAuditLogger.cs) |
| **`Pus.Vault.Client`** | [`src/Pus.Vault.Client/`](./src/Pus.Vault.Client/) | [`PvspClientEngine.cs`](./src/Pus.Vault.Client/PvspClientEngine.cs), [`KeepAliveWorker.cs`](./src/Pus.Vault.Client/KeepAliveWorker.cs), [`CliCommandLoop.cs`](./src/Pus.Vault.Client/CliCommandLoop.cs), [`Program.cs`](./src/Pus.Vault.Client/Program.cs) |
| **`Pus.Vault.Tests`** | [`tests/Pus.Vault.Tests/`](./tests/Pus.Vault.Tests/) | [`ProtocolAndCryptoUnitTests.cs`](./tests/Pus.Vault.Tests/ProtocolAndCryptoUnitTests.cs), [`ServerStorageAndAuthTests.cs`](./tests/Pus.Vault.Tests/ServerStorageAndAuthTests.cs), [`PvspEndToEndSessionTests.cs`](./tests/Pus.Vault.Tests/PvspEndToEndSessionTests.cs) |

*(Katalogi robocze `certs/`, `config/`, `data/`, `logs/` oraz plik `.env` są wykluczone z Gita w `.gitignore` i tworzone lokalnie przy uruchomieniu.)*

---

## 3. Protokół PVSP v1.0 w pigułce

Pełna formalna specyfikacja protokołu znajduje się w dokumencie [`Assets/projekt-protokołu.pdf`](../Assets/projekt-protoko%C5%82u.pdf).

### Budowa ramki binarnej (12-bajtowy nagłówek Big-Endian + ładunek UTF-8 JSON)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Magic Bytes (0x5053)     | Version (0x01)|  Message Type |  [Bajty 0..3]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Message ID (uint32, Big-Endian)             |  [Bajty 4..7]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Payload Length (uint32, Big-Endian)           |  [Bajty 8..11]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  JSON Payload (UTF-8, 0..65536 B)             |  [Bajty 12..N]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Maszyna stanów sesji

```mermaid
stateDiagram-v2
    [*] --> DISCONNECTED
    DISCONNECTED --> TLS_CONNECTED : TCP Connect + TLS 1.3 Handshake OK
    TLS_CONNECTED --> HANDSHAKED : Rcv HELLO / Send HELLO_ACK
    TLS_CONNECTED --> CLOSED : Timeout (10s) lub Fatal Frame Error
    HANDSHAKED --> AUTHENTICATED : Rcv AUTH (Valid) / Send AUTH_ACK
    HANDSHAKED --> HANDSHAKED : Rcv AUTH (Invalid, proba < 3) / Send ERROR(201)
    HANDSHAKED --> CLOSED : Rcv AUTH (Invalid, proba == 3) lub Timeout (15s)
    AUTHENTICATED --> AUTHENTICATED : Rcv DATA_REQ / Send DATA_RESP lub ERROR
    AUTHENTICATED --> AUTHENTICATED : Rcv PING / Send PONG
    AUTHENTICATED --> CLOSED : Rcv BYE / Close TLS + Socket
    AUTHENTICATED --> CLOSED : Idle Timeout (60s) lub Krytyczny Blad
    CLOSED --> [*]
```

### Typy wiadomości i kluczowe limity czasowe

| Kod | Typ | Kierunek | Ładunek | Timeout / Polityka |
| :---: | :--- | :---: | :--- | :--- |
| `0x01` / `0x02` | `HELLO` / `HELLO_ACK` | K -> S / S -> K | JSON (`clientName`, `serverNonce`) | Handshake TLS: `10s` (kolejka serwera + klient), bezwzględny deadline HELLO: `10s` |
| `0x03` / `0x04` | `AUTH` / `AUTH_ACK` | K -> S / S -> K | JSON (`username`, `password`, `serverNonceEcho` -> 256-bit `sessionToken`, `hmacSecret`, `role`) | Bezwzględny deadline AUTH: `15s` (maks. 3 próby / połączenie) |
| `0x05` / `0x06` | `DATA_REQ` / `DATA_RESP` | K -> S / S -> K | JSON (`SET`, `GET`, `LIST`, `DELETE` + kanoniczny `hmac`) | Request Timeout klienta: `5s`, Rate Limit: `20 / 10s` |
| `0x07` / `0x08` | `PING` / `PONG` | K -> S / S -> K | Pusty (`0` bajtów) | Interwał `PING`: `20s`, Idle Timeout serwera: `60s` (reset wyłącznie po poprawnych ramkach) |
| `0x09` | `BYE` | K -> S | Pusty (`0` bajtów) | Eleganckie zamknięcie TLS + TCP (bez `BYE_ACK`) |
| `0xFF` | `ERROR` | S -> K | JSON (`errorCode`, `errorName <= 64 B`, `message <= 512 B`, `timestamp`) | Kody krytyczne (`100-103`, `105`, `204`, `301`) zamykają sesję |

---

## 4. Wymagania środowiskowe

Zweryfikowane środowisko referencyjne, na którym zbudowano i przetestowano projekt:

| Składnik | Zweryfikowana wersja | Rola w projekcie |
| :--- | :--- | :--- |
| **System operacyjny** | `Ubuntu 24.04.1 LTS` (WSL2 na Windows 11, 12 CPUs) | Natywne gniazda Linux oraz uprawnienia plików `0600`/`0700` |
| **.NET SDK** | `8.0.134` (Runtime `8.0.34`) | Kompilacja, uruchamianie oraz wykonywanie testów C# |
| **OpenSSL** | `OpenSSL 3.0.13 (30 Jan 2024)` | Generowanie Custom Root CA i certyfikatów X.509 v3 z SAN/EKU |
| **Docker Engine** *(opcjonalnie)* | `28.0.1` | Uruchomienie skonteneryzowane |
| **Docker Compose** *(opcjonalnie)* | `v2.33.1-desktop.1` | Orkiestracja izolowanej sieci i wolumenów serwera/klienta |

---

## 5. Instrukcja uruchomienia

### Krok 1: Wygenerowanie certyfikatów PKI (Wymagane w obu trybach)

Uruchom skrypt [`scripts/generate_certs.sh`](./scripts/generate_certs.sh) z katalogu `PusVault/`, aby utworzyć `certs/ca.crt`, `certs/server.crt` oraz `certs/server.key` (z rozszerzeniami `SAN: localhost, pus-vault-server, 127.0.0.1, ::1`, `EKU: serverAuth` oraz uprawnieniami `chmod 600` na kluczach prywatnych):

```bash
cd PusVault
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh
```

---

### Wariant A: Uruchomienie natywne (.NET 8 SDK w Linux / WSL2)

1. **Kompilacja solucji:**
   ```bash
   dotnet build PusVault.sln --configuration Release
   ```

2. **Uruchomienie Serwera (Terminal 1):**
   Przy pierwszym uruchomieniu, jeśli plik `config/users.json` jeszcze nie istnieje, serwer tworzy konta `admin` (`READ_WRITE`) oraz `reader` (`READ_ONLY`) zapisane jako hashe PBKDF2-HMAC-SHA256 (600 000 iteracji). Hasła startowe można podać w ukrytym promptcie lub przez zmienne środowiskowe:
   ```bash
   # Opcja 1: Interaktywny ukryty prompt przy pierwszym starcie
   dotnet run --project src/Pus.Vault.Server

   # Opcja 2: Automatyczna inicjalizacja z jawnymi limitami współbieżności
   PUS_ADMIN_PASS="AdminPass123!" PUS_READER_PASS="ReaderPass123!" \
     dotnet run --project src/Pus.Vault.Server -- --port 8443 --max-sessions 64 --max-handshakes 32
   ```

3. **Uruchomienie interaktywnego Klienta CLI (Terminal 2):**
   ```bash
   # Standardowe połączenie lokalne (localhost / IPv4)
   dotnet run --project src/Pus.Vault.Client

   # Połączenie natywne po IPv6 Dual-Stack z włączonym trybem diagnostycznym
   dotnet run --project src/Pus.Vault.Client -- --host ::1 --port 8443 --diagnostics
   ```

---

### Wariant B: Uruchomienie w kontenerach (Docker Compose)

Docker Compose buduje lekkie obrazy `.NET 8 Runtime` z wieloetapowego [`Dockerfile`](./Dockerfile) i łączy je w dedykowanej sieci wirtualnej `pus-vault-net`. Zgodnie z zasadą najmniejszych uprawnień serwer montuje tylko `server.crt`/`server.key` (`:ro`), a klient wyłącznie publiczny certyfikat urzędu `ca.crt` (`:ro`).

1. **Utworzenie lokalnego pliku `.env` z szablonu:**
   ```bash
   cp .env.example .env
   # Opcjonalnie edytuj .env, aby ustawić własne hasła początkowe
   ```

2. **Zbudowanie obrazów i start Serwera w tle:**
   ```bash
   docker compose up -d --build
   docker compose logs -f pus-vault-server
   ```

3. **Uruchomienie interaktywnego Klienta CLI wewnątrz sieci `pus-vault-net`:**
   ```bash
   # Standardowa sesja klienta
   docker compose run --rm pus-vault-client

   # Klient z odblokowanym trybem diagnostycznym
   docker compose run --rm pus-vault-client --diagnostics
   ```

4. **Zatrzymanie kontenerów:**
   ```bash
   # Eleganckie zatrzymanie (SIGTERM) z zachowaniem sekretów i kont w wolumenach
   docker compose down

   # Zatrzymanie i usunięcie wolumenów (pełny reset danych)
   docker compose down -v
   ```

---

## 6. Komendy CLI i konfiguracja

### Parametry uruchomieniowe Serwera i Klienta

| Aplikacja | Flaga / Zmienna środowiskowa | Domyślnie | Opis |
| :--- | :--- | :--- | :--- |
| **Serwer** | `--port <int>` | `8443` | Port nasłuchujący TCP Dual-Stack (`[::]:port`, zakres `0..65535`). |
| **Serwer** | `--max-sessions <int>` / `PUS_MAX_SESSIONS` | `64` | Maksymalna liczba jednoczesnych aktywnych sesji klienckich (`>= 1`). |
| **Serwer** | `--max-handshakes <int>` / `PUS_MAX_HANDSHAKES` | `32` | Maksymalna liczba równoległych negocjacji handshake TLS (`>= 1`). |
| **Klient** | `--host <adres>` | `localhost` | Nazwa hosta lub adres IP serwera (`localhost`, `127.0.0.1`, `::1`, `pus-vault-server`). |
| **Klient** | `--port <int>` | `8443` | Docelowy port TCP serwera. |
| **Klient** | `--ca <ścieżka>` | `certs/ca.crt` | Ścieżka do zaufanego certyfikatu Custom Root CA (PEM). |
| **Klient** | `--diagnostics` | *wyłączone* | Włącza komendy testowe bezpieczeństwa/framingu (`diag-hmac`, `diag-replay`, `diag-magic`). |

### Interaktywne polecenia REPL Klienta

| Polecenie | Wymagana rola | Ramka protokołu | Działanie |
| :--- | :---: | :---: | :--- |
| `login <user>` | *Brak* | `HELLO` -> `AUTH` | Pyta o hasło bez echa w terminalu i nawiązuje sesję TLS 1.3. |
| `set <key>` | `READ_WRITE` | `DATA_REQ (SET)` | Pyta o wartość sekretu bez echa; atomowo zapisuje na dysk. |
| `get <key>` | Dowolna | `DATA_REQ (GET)` | Pobiera wartość sekretu; automatycznie ponawiane po awarii sieci. |
| `list` | Dowolna | `DATA_REQ (LIST)` | Zwraca posortowaną listę kluczy (maks. 1 000 / 64 KiB); ponawiane po awarii. |
| `delete <key>` | `READ_WRITE` | `DATA_REQ (DELETE)` | Trwale usuwa sekret z pamięci RAM i pliku `vault_store.json`. |
| `ping` | Dowolna | `PING` -> `PONG` | Wysyła ręczną ramkę kontrolną *Keep-Alive* (`PayloadLength = 0`); przy timeout/zerwie zamyka transport i uruchamia *Auto-Reconnect*. |
| `help` | Dowolna | *Lokalnie* | Wyświetla pomoc z listą dostępnych poleceń. |
| `exit` / `quit` | Dowolna | `BYE` | Zamyka sesję TLS/TCP i czyści poświadczenia z pamięci RAM. |
| `diag-hmac` | `--diagnostics` | `DATA_REQ` (zły HMAC) | Wysyła sfałszowany HMAC -> wymusza `204 ERR_INVALID_HMAC` i rozłączenie. |
| `diag-replay` | `--diagnostics` | `DATA_REQ` (-120s) | Wysyła przeterminowany timestamp -> wymusza `301 ERR_REPLAY_DETECTED`. |
| `diag-magic` | `--diagnostics` | Nagłówek `0x0000` | Wysyła błędne Magic Bytes (z Big-Endian `MsgID`) -> wymusza `100 ERR_BAD_MAGIC` i rozłączenie. |

---

## 7. Testy automatyczne i raport wydajności

Projekt testowy xUnit w [`tests/Pus.Vault.Tests/`](./tests/Pus.Vault.Tests/) zawiera **32 testy automatyczne** w 3 plikach (`6` + `12` + `14`), pokrywających w 100% matrycę `T-01`..`T-12` z dokumentacji Etapu 2 oraz pełny pakiet testów utwardzania bezpieczeństwa i odporności (Priorytety 1–3).

### Uruchomienie pełnej matrycy testowej

```bash
cd PusVault
dotnet test PusVault.sln --configuration Release --logger "console;verbosity=detailed"
```

### Pokrycie matrycy testów (`T-01`..`T-12` + regresje P1–P3)

| ID | Kategoria | Weryfikowany scenariusz | Metoda testowa xUnit | Wynik |
| :---: | :--- | :--- | :--- | :---: |
| **T-01** | Funkcjonalny | Pełny cykl CRUD (`HELLO` -> `AUTH` -> `SET` -> `GET` -> `LIST` -> `PING` -> `DELETE` -> `BYE`) i zapis w `vault_store.json` | `PvspEndToEndSessionTests.T01_T04_ClientEngine_ShouldExecuteFullCrudLifecycle_Ping_AndEnforceRbac` | PASS |
| **T-02** | Funkcjonalny | Persystencja po restarcie serwera (`SET` -> restart -> `GET`) oraz odrzucenie uszkodzonego lub `null` JSON przy starcie | `ServerStorageAndAuthTests.T02_T12_VaultStorage_ShouldPersistAcrossRestarts_AndRejectCorruptedOrNullValueJson`, `PvspEndToEndSessionTests.T09_T02_...` | PASS |
| **T-03** | Bezpieczeństwa | Pozytywna akceptacja Custom CA + odrzucenie na żywym TLS 1.3 i jednostkowo: obce CA, zły SAN oraz brak EKU `serverAuth` (`AuthenticationException`) | `ProtocolAndCryptoUnitTests.T03_CustomCaValidator_...`, `PvspEndToEndSessionTests.T03_TlsHandshake_ShouldThrowAuthenticationException_OnUntrustedCa_WrongSan_AndMissingServerAuthEku` | PASS |
| **T-04** | Bezpieczeństwa | Kontrola RBAC (`READ_ONLY`: `GET` OK, `SET`/`DELETE` -> `203`), ścisła wielkość liter nonce, blokada *brute-force* i zamknięcie po 3 błędach `AUTH` | `ServerStorageAndAuthTests.T04_AuthAndRbac_...`, `T04_SessionHandler_ShouldRejectWrongNonce_AndCloseConnectionAfter3FailedAuthAttempts`, `PvspEndToEndSessionTests.T01_T04_...` | PASS |
| **T-05** | Bezpieczeństwa | 1-bajtowa mutacja HMAC na żywym serwerze i `diag-hmac` -> `204 ERR_INVALID_HMAC`, wpis `[SECURITY]` i natychmiastowy EOF | `PvspEndToEndSessionTests.T05_LiveServer_1ByteHmacMutation_ShouldReturn204_LogSecurity_AndCloseSocket`, `T05_T06_T08_Diagnostics_...` | PASS |
| **T-06** | Bezpieczeństwa | Ochrona Replay: stary timestamp (-120s), `MsgID=0`, stare ID, luka w numeracji i zmodyfikowany duplikat -> `301 ERR_REPLAY_DETECTED` + EOF | `PvspEndToEndSessionTests.T05_T06_T08_Diagnostics_...`, `T06_Server_ShouldRejectMsgIdZero_OldMessageId_Gap_AndModifiedDuplicate_With301AndClose` | PASS |
| **T-07** | Odporności | Pofragmentowany strumień TCP (`56 B` HELLO w paczkach po 3 bajty co `50 ms`) składany przez `ReadExactly` | `ProtocolAndCryptoUnitTests.T07_FrameCodec_...`, `PvspEndToEndSessionTests.T07_LiveServer_ShouldReassembleFragmentedHello_3BytesEvery50ms` | PASS |
| **T-08** | Odporności | Odrzucenie błędów framingu na żywym TLS i jednostkowo: Magic (`100` + echo `MsgID`), wersja (`101`), typ (`102`), > 64 KiB (`103` przed ładunkiem) + EOF | `ProtocolAndCryptoUnitTests.T08_FrameCodec_...`, `PvspEndToEndSessionTests.T08_LiveServer_ShouldRejectAllFramingErrors_100_101_102_103_AndCloseConnection` | PASS |
| **T-09** | Odporności | *Auto-Reconnect* ponawia `GET` po restarcie; zerwanie po wysłaniu `SET` zwraca `IsUnknownMutationOutcome` (bez cichego retry) | `PvspEndToEndSessionTests.T09_T02_...`, `T09_ClientEngine_ShouldNotRetrySetMutation_WhenConnectionDropsAfterSend` | PASS |
| **T-10** | Obciążeniowy | Rate Limiter (20 przechodzi, 5 odrzucone z `429`) + test obciążeniowy **50 równoległych sesji TLS 1.3** (`GET` + `SET`, limity `64`/`32`) | `PvspEndToEndSessionTests.T10_RateLimiter_...`, `T10_LoadTest_50ConcurrentSessions_ShouldMeetLatencyTargetAndReportPercentiles` | PASS |
| **T-11** | Walidacji | Błędny UTF-8/JSON (`104`), nieznane/powtórzone/null pola, limity klucza/wartości > 32 KiB i niepuste `PING`/`BYE` (`106`), zła akcja (`107`), `LIST` > 1 000 kluczy lub > 64 KiB (`108`), nieoczekiwany `PONG` (`202`) | `ProtocolAndCryptoUnitTests.T11_StrictJsonValidator_...`, `ServerStorageAndAuthTests.T11_SessionHandler_...`, `PvspEndToEndSessionTests.T11_LiveServer_...` | PASS |
| **T-12** | Persystencji i logów | Równoległe `SET`/`DELETE`, brak zmiany RAM przy błędzie dysku, zatrzymanie na zepsutym/`null` JSON, escapowanie znaków sterujących/ANSI (`\u001b`) i zero wycieków | `ServerStorageAndAuthTests.T12_VaultStorage_...` (3 testy), `T12_AuditLogger_...`, `ServerListenerAndSession_...` | PASS |
| **P1–P3** | Utwardzenie i E2E | Odporność `timestamp` na overflow (`301`), bezwzględne deadline'y `HELLO`/`AUTH` i `AUTHENTICATED` idle timeout (`105`), monotoniczność `MsgID` + izolowany cache duplikatów + `ERROR <= 512 B`, 256-bit CSPRNG, recovery `PING`, żywy TLS Handshake Timeout + IPv6 `::1` + `KeepAliveWorker` + ustrukturyzowane logi UTC klienta | `ProtocolAndCryptoUnitTests.Priority2_CryptoHelper_...`, `ServerStorageAndAuthTests.Priority1_...` (3 testy), `SessionHandler_ShouldEnforceAuthenticatedIdleTimeout_...`, `PvspEndToEndSessionTests.Priority1_ClientEngine_SendPing_...`, `LiveServer_ShouldEnforceTlsHandshakeTimeout_KeepAliveWorker_Ipv6Loopback_AndStructuredClientLogs` | PASS |

### Zmierzony raport wydajności (`T-10` - 50 równoległych sesji)

- **Zweryfikowany pełny zestaw testów (WSL2 `Ubuntu 24.04.1 LTS`, `.NET 8.0.34`, `12 CPUs`, Release):** `Total tests: 32 | Passed: 32 | Failed: 0 | Total time: 19.07 s` (`0 Warning(s), 0 Error(s)`).
- **Metodologia pomiaru:** 50 równoległych klientów łączy się i uwierzytelnia jednocześnie z żywym serwerem działającym na **produkcyjnych limitach współbieżności (`maxSessions=64, maxHandshakes=32`)** na interfejsie loopback (`TLS_AES_256_GCM_SHA384`). Po rozgrzewce (1 zapytanie per sesja) wszystkie 50 aktywnych sesji wykonuje równolegle **200 operacji `GET` (`50 × 4`)** oraz **50 operacji `SET` (`50 × 1`)**. Mierzone i raportowane są osobno: **czas przetwarzania po stronie serwera (`Server Time`)** oraz **pełny round-trip po stronie klienta (`Client RTT`)** (HMAC, ramkowanie, TLS, wykonanie na serwerze i parsowanie odpowiedzi).

| Operacja i zakres pomiaru | Próbki | `Avg` | `p50` (Mediana) | `p95` | Wymaganie docelowe |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`GET` — Czas przetwarzania serwera** | `200` (`50 × 4`) | **`0.13 ms`** | **`0.09 ms`** | **`0.20 ms`** | `< 15.00 ms` |
| **`GET` — Pełny RTT klienta** | `200` (`50 × 4`) | **`9.20 ms`** | **`6.95 ms`** | **`19.17 ms`** | `< 15.00 ms` |
| **`SET` — Czas przetwarzania serwera** *(atomowy zapis dyskowy)* | `50` (`50 × 1`) | **`3.97 ms`** | **`3.94 ms`** | **`4.82 ms`** | `< 15.00 ms` |
| **`SET` — Pełny RTT klienta** *(atomowy zapis dyskowy)* | `50` (`50 × 1`) | **`4.59 ms`** | **`4.54 ms`** | **`5.39 ms`** | `< 15.00 ms` |

> 📸 **Wynik testów automatycznych xUnit i raportu T-10 *(zrzuty z wersji bazowej 21/21; po utwardzeniu Priorytetów 1–3 pakiet rozszerzony do 32/32)***  
> ![Wynik testów xUnit bazowy](./docs/tests-output.png)
> ![Wynik testów xUnit bazowy V2](./docs/tests-output-2.png)

---

## 8. Scenariusze demonstracyjne na żywo

Poniższe 4 scenariusze pokrywają i rozszerzają wymagania demonstracji końcowej z Etapu 3 (poprawna sesja, awaria sieci i recovery, odrzucenie incydentów bezpieczeństwa oraz obsługa IPv6 Dual-Stack).

### Scenariusz 1: Poprawna sesja CRUD oraz persystencja po restarcie
1. **Terminal 1 (Serwer):** `PUS_ADMIN_PASS="Admin123!" PUS_READER_PASS="Reader123!" dotnet run --project src/Pus.Vault.Server`
2. **Terminal 2 (Klient):** `dotnet run --project src/Pus.Vault.Client`
3. Wykonaj po kolei: `login admin` *(hasło `Admin123!` w ukrytym promptcie)* -> `set STRIPE_API_KEY` *(wartość w ukrytym promptcie)* -> `get STRIPE_API_KEY` -> `list` -> `ping` -> `exit`.
4. **Weryfikacja persystencji:** Zatrzymaj serwer (`Ctrl+C`), uruchom go ponownie, zaloguj się jako `admin` i wpisz `get STRIPE_API_KEY` - sekret zostaje odczytany z `data/vault_store.json`.

### Scenariusz 2: Awaria sieci i automatyczne odzyskiwanie sesji (*Auto-Reconnect*)
1. Pozostaw klienta zalogowanego jako `admin` (`pus-vault [AUTH:READ_WRITE]>`) przy zapisanym kluczu `STRIPE_API_KEY`.
2. W **Terminalu 1** ubij serwer (`Ctrl+C`), odczekaj 1 sekundę i uruchom go ponownie.
3. W **Terminalu 2** wywołaj `get STRIPE_API_KEY`.
4. **Oczekiwany efekt:** Klient wypisuje ustrukturyzowany log UTC `[YYYY-MM-DD HH:mm:ss UTC] [WARN] [Session:localhost:8443] Connection lost during GET (...). Starting Auto-Reconnect...`, ponawia połączenie z wykładniczym opóźnieniem (`1s`, `2s`, `4s`), automatycznie wykonuje nowy handshake TLS 1.3 + `HELLO`/`AUTH` i zwraca wartość sekretu.

### Scenariusz 3: Scenariusze bezpieczeństwa (RBAC, sfałszowany HMAC, Replay, błędny nagłówek)
1. **Odmowa uprawnień RBAC (`203 ERR_FORBIDDEN`):** Zaloguj się na konto `reader` (`Reader123!`). Wywołaj `get STRIPE_API_KEY` (sukces), a następnie `delete STRIPE_API_KEY` -> Serwer zwraca `[SERVER ERROR 203 ERR_FORBIDDEN]` i zapisuje log `[SECURITY] RBAC Forbidden`.
2. **Tryb diagnostyczny:** Uruchom klienta z flagą `dotnet run --project src/Pus.Vault.Client -- --diagnostics` i zaloguj się jako `admin`:
    - Wpisz `diag-hmac` -> Serwer odrzuca pakiet kodem `204 ERR_INVALID_HMAC`, loguje `[SECURITY] HMAC verification failed` i zamyka połączenie.
    - Zaloguj się ponownie i wpisz `diag-replay` -> Serwer zwraca `301 ERR_REPLAY_DETECTED` i zamyka sesję.
    - Zaloguj się ponownie i wpisz `diag-magic` -> Serwer zwraca `100 ERR_BAD_MAGIC` i zamyka sesję.

> 📸 **Diagnostyka bezpieczeństwa i logi audytowe serwera**  
> ![Demo bezpieczeństwa](./docs/diagnostics-security.png)
> ![Demo bezpieczeństwa V2](./docs/diagnostics-security-2.png)
> ![Demo bezpieczeństwa V3](./docs/diagnostics-security-3.png)

### Scenariusz 4: Weryfikacja natywnego IPv6 (Dual-Stack)
1. Gdy serwer nasłuchuje na `[::]:8443` (`DualMode = true`), połącz klienta jawnie przez adres pętli zwrotnej IPv6:
   ```bash
   dotnet run --project src/Pus.Vault.Client -- --host ::1 --port 8443
   ```
2. Zaloguj się i potwierdź w logach serwera poprawną walidację SAN (`IP:::1`) obok sesji IPv4 (`[::ffff:127.0.0.1]`).

---

## 9. Znane ograniczenia

Zgodnie z zakresem MVP określonym w dokumentacji Etapu 1 i Etapu 2, system posiada następujące jawne ograniczenia:

1. **Przechowywanie sekretów w postaci jawnej na dysku (`data/vault_store.json`):** Protokół PVSP zabezpiecza dane w transmisji (TLS 1.3 + HMAC-SHA256) oraz wymusza uwierzytelnianie i RBAC, jednak plik magazynu `data/vault_store.json` jest zapisywany jako jawny JSON (*plaintext at rest*). Kompromitacja hosta lub systemu plików pozostaje poza zakresem zagrożeń MVP. Zastosowano podstawowe środki ochrony lokalnej (uprawnienia `0700` dla `data/`, `0600` dla `vault_store.json`, wykluczenie z Gita i obrazów Docker). Dzięki wydzieleniu interfejsu `IVaultStorage`, szyfrowanie AEAD (np. AES-GCM z zewnętrznym kluczem głównym) można dodać poza MVP bez modyfikacji warstwy sieciowej i protokołu.
2. **Brak paginacji dla `LIST`:** Operacja `LIST` zwraca wszystkie klucze w pojedynczej ramce z limitem **1 000 kluczy** oraz **64 KiB** zserializowanego ładunku UTF-8 (przekroczenie zwraca `108 ERR_RESPONSE_TOO_LARGE`).
3. **Maksymalnie jedno żądanie w locie na sesję:** W obrębie jednego połączenia TCP klient wysyła kolejne żądanie aplikacyjne dopiero po otrzymaniu odpowiedzi na poprzednie (brak pipeliningu i równoległych zapytań w ramach jednego gniazda).
4. **Brak automatycznego ponawiania mutacji (`SET`/`DELETE`):** Izolowany bufor deduplikacji `DATA_REQ` odsyła zapisaną odpowiedź (`DATA_RESP` lub błąd biznesowy `ERROR`) dla identycznych powtórzeń w obrębie jednej aktywnej sesji TCP bez ponownego wykonywania mutacji. Po rozpoczęciu wysyłania ramki `SET` lub `DELETE` (`onWriteStarted`) utrata połączenia nie powoduje cichego retry po reconnectcie, lecz zwrócenie wyniku nieznanego.
5. **Tymczasowe buforowanie poświadczeń w pamięci RAM klienta:** Na potrzeby reaktywnego *Auto-Reconnect* klient przechowuje w pamięci procesu login i hasło zalogowanego użytkownika do czasu wyjścia (`exit`) lub zniszczenia obiektu (bez zapisu na dysk i bez logowania).
6. **Plikowy rejestr kont użytkowników:** Konta (`admin`, `reader`) wczytywane są przy starcie serwera z `config/users.json` (hashe PBKDF2); dynamiczne zarządzanie kontami przez protokół nie wchodzi w zakres MVP.

---

## 10. Autorzy i dokumentacja powiązana

### Zespół projektowy

| Autor | Profil GitHub | Główny zakres prac (zgodnie z Etapem 2) |
| :--- | :--- | :--- |
| **Kacper Gumulak** | [![GitHub](https://img.shields.io/badge/zephir--x-181717?logo=github&logoColor=white)](https://github.com/zephir-x) | Serwer (`Pus.Vault.Server`), kodek binarny (`Pus.Vault.Common`), infrastruktura PKI OpenSSL, konteneryzacja Docker, specyfikacja protokołu |
| **Damian Judka** | [![GitHub](https://img.shields.io/badge/geniuszmath75-181717?logo=github&logoColor=white)](https://github.com/geniuszmath75) | Klient CLI (`Pus.Vault.Client`), moduł kryptograficzny (`Pus.Vault.Common`), testy automatyczne xUnit (`T-01`..`T-12`), projekt aplikacji i dokumentacja |

### Dokumentacja powiązana (`../Assets/`)
- 📄 **Etap 1 - Specyfikacja techniczna protokołu PVSP v1.0:** [`projekt-protokołu.pdf`](../Assets/projekt-protoko%C5%82u.pdf) ([Markdown](../Assets/projekt-protoko%C5%82u.md))
- 📄 **Etap 2 - Projekt aplikacji sieciowej PUS-Vault:** [`projekt-aplikacji.pdf`](../Assets/projekt-aplikacji.pdf) ([Markdown](../Assets/projekt-aplikacji.md))
- 📄 **Regulamin i zasady zaliczenia przedmiotu:** [`zasady-zaliczenia.pdf`](../Assets/zasady-zaliczenia.pdf)