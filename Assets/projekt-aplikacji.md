# Programowanie Usług Sieciowych - Projekt Grupowy (Etap 2)

## Projekt Aplikacji Sieciowej: **PUS-Vault (Bezpieczny Menedżer Sekretów i Konfiguracji)**

* **Przedmiot:** Programowanie Usług Sieciowych (PUS)
* **Wykorzystywany protokół:** `PVSP v1.0 (PUS-Vault Secret Protocol)` (zdefiniowany w Etapie 1)
* **Zespół projektowy:**
  * Kacper Gumulak
  * Damian Judka

---

## 1. Opis funkcjonalny aplikacji

### 1.1. Co aplikacja robi?
**PUS-Vault** to rozproszony system sieciowy działający w architekturze Klient-Serwer, służący do bezpiecznego, scentralizowanego przechowywania, dystrybucji oraz zarządzania poufnymi danymi konfiguracyjnymi (tzw. sekretami), takimi jak klucze API, hasła bazodanowe, tokeny dostępowe czy parametry środowiskowe.

System składa się z wielowątkowego serwera usługowego (**PUS-Vault Server**) utrzymującego magazyn danych typu klucz-wartość (*Key-Value*) oraz interaktywnej aplikacji klienckiej wiersza poleceń (**PUS-Vault CLI Client**). Komunikacja pomiędzy komponentami odbywa się wyłącznie za pomocą zaprojektowanego w Etapie 1 autorskiego protokołu aplikacyjnego **PVSP (PUS-Vault Secret Protocol)**, wykorzystującego niskopoziomowe gniazda strumieniowe TCP (`System.Net.Sockets.Socket`), szyfrowanie kanału TLS 1.3 (z własnym Urzędem Certyfikacji - Custom CA) oraz kryptograficzne uwierzytelnianie komunikatów kodem `HMAC-SHA256`.

Podstawowe funkcje użytkowe aplikacji obejmują:
* nawiązywanie szyfrowanej sesji z weryfikacją tożsamości serwera i dwuetapowym logowaniem użytkownika (`HELLO` $\rightarrow$ `AUTH`),
* dodawanie nowych oraz aktualizację istniejących sekretów (`SET`),
* bezpieczne pobieranie wartości wskazanego sekretu na żądanie (`GET`),
* przeglądanie listy dostępnych identyfikatorów (kluczy) sekretów bez ujawniania ich wartości (`LIST`),
* trwałe usuwanie wycofanych sekretów z magazynu (`DELETE`),
* automatyczne podtrzymywanie sesji (`PING`/`PONG`) oraz reaktywne wznawianie połączenia po awarii sieci (*Auto-Reconnect*). W MVP automatycznie ponawiane są tylko bezpieczne odczyty `GET` i `LIST`.

### 1.2. Jaki problem użytkownika rozwiązuje?
W zespołach programistycznych i administracyjnych (DevOps) powszechnym problemem bezpieczeństwa jest przechowywanie haseł oraz kluczy API w postaci jawnego tekstu w plikach lokalnych (np. `.env`, `appsettings.json`), repozytoriach kodu Git lub przesyłanie ich przez niezabezpieczone komunikatory. Prowadzi to do:
1. **Ryzyka wycieku poświadczeń** w przypadku kompromitacji stacji roboczej lub repozytorium.
2. **Braku centralnej kontroli dostępu** (brak rozróżnienia, kto może modyfikować sekrety, a kto jedynie je odczytywać).
3. **Braku audytu i integralności** podczas przesyłania konfiguracji przez sieć lokalną lub Internet.

Aplikacja **PUS-Vault** eliminuje te problemy, wprowadzając jeden centralny punkt prawdy (*Single Source of Truth*), w którym sekrety są pobierane przez uprawnione podmioty w czasie rzeczywistym przez podwójnie zabezpieczony kanał sieciowy (TLS 1.3 + HMAC-SHA256), z pełnym wymuszeniem ról autoryzacyjnych (RBAC) oraz logowaniem zdarzeń bezpieczeństwa.

### 1.3. Kto jest użytkownikiem (Aktorzy)?
System definiuje dwóch głównych aktorów zewnętrznych oraz komponenty wewnętrzne:

| Aktor | Przypisana rola w PVSP | Charakterystyka i uprawnienia w aplikacji |
| :--- | :--- | :--- |
| **1. Administrator Bezpieczeństwa / DevOps** | `READ_WRITE` (konto np. `admin`) | Użytkownik zarządzający cyklem życia sekretów. Posiada pełne uprawnienia do odczytu (`GET`, `LIST`) oraz modyfikacji stanu magazynu (`SET`, `DELETE`). |
| **2. Programista / Aplikacja Kliencka (Konsument)** | `READ_ONLY` (konto np. `reader`) | Użytkownik lub skrypt pobierający konfigurację niezbędną do pracy. Posiada uprawnienia wyłącznie do listowania kluczy (`LIST`) oraz odczytu wartości sekretów (`GET`). Próba zapisu lub usunięcia danych jest blokowana przez serwer. |
| **3. Komponenty wewnętrzne serwera** | *Nie jest aktorem zewnętrznym* | `ClientSessionHandler`, rate limiter, worker timeoutów oraz `VaultStorageEngine` realizują odpowiednio cykl życia sesji, limity i persystencję. |

---

## 2. Architektura rozwiązania

### 2.1. Model architektoniczny
Rozwiązanie zostało zaprojektowane w modelu **Klient-Serwer (Client-Server)** z wielowątkowym, asynchronicznym serwerem obsługującym wielu równoległych klientów jednocześnie oraz lekkim klientem konsolowym (CLI). W warstwie kodu źródłowego (.NET 8 / C#) system podzielony jest na trzy wyraźnie odseparowane moduły (projekty w solucji `PusMainProject.sln`):
1. **`Pus.Vault.Common`** - współdzielona biblioteka klas implementująca specyfikację protokołu PVSP.
2. **`Pus.Vault.Server`** - aplikacja serwera nasłuchująca na gniazdach sieciowych i zarządzająca magazynem.
3. **`Pus.Vault.Client`** - aplikacja kliencka realizująca interfejs użytkownika oraz mechanizmy odporności połączenia.

### 2.2. Opis komponentów systemu

#### A. Komponenty biblioteki wspólnej (`Pus.Vault.Common`)
* **`PvspFrameCodec` (Serializator/Deserializator Ramek):** Moduł odpowiedzialny za kodowanie i dekodowanie 12-bajtowego nagłówka binarnego w porządku *Big-Endian* (`Magic=0x5053`, `Version=0x01`, `Type`, `MessageId`, `PayloadLength`) oraz bezpieczne odczytywanie strumienia TCP za pomocą pętli `ReadExactly` (eliminacja problemu *Partial Reads*).
* **`PvspCryptoHelper` (Moduł Kryptograficzny):** Komponent wyliczający i weryfikujący podpisy `HMAC-SHA256` z kanonicznych, długościowanych bajtów, generujący kryptograficznie bezpieczne wartości (`serverNonce` - 16 bajtów CSPRNG, `sessionToken`, `hmacSecret`) oraz konfigurujący walidację X.509 (`CustomRootTrust` dla `ca.crt`) z kontrolą SAN/EKU i nazwy hosta.
* **`PvspModels` & `ErrorCodes`:** Zestaw klas DTO (Data Transfer Objects) reprezentujących ładunki JSON poszczególnych komunikatów oraz słownik kodów błędów protokołu (`100`-`500`).

#### B. Komponenty serwera (`Pus.Vault.Server`)
* **`SocketConnectionListener` (Warstwa Transportowa i TLS):** Zarządza surowym gniazdem nasłuchującym `System.Net.Sockets.Socket` w trybie **Dual-Stack (IPv6 + IPv4-mapped)**. Dla każdego zaakceptowanego klienta (`AcceptAsync`) nakłada strumień `SslStream`, wymusza TLS 1.3 i deadline handshake’u, używając certyfikatu z SAN/EKU `serverAuth` oraz chronionego `server.key`.
* **`ClientSessionHandler` (Maszyna Stanów i Ochrona Anti-Replay):** Utrzymuje kontekst pojedynczego połączenia klienta (`DISCONNECTED` $\rightarrow$ `TLS_CONNECTED` $\rightarrow$ `HANDSHAKED` $\rightarrow$ `AUTHENTICATED` $\rightarrow$ `CLOSED`). Wymaga kolejnych `Message ID`, sprawdza okno czasowe `timestamp` ($\pm 30\text{s}$), zapamiętuje digest i ostatnią odpowiedź w bieżącej sesji oraz egzekwuje limit `20 DATA_REQ / 10s`.
* **`AuthAndRbacModule` (Moduł Uwierzytelniania i Autoryzacji):** Weryfikuje hasła względem PBKDF2-HMAC-SHA256 z losową solą 16 bajtów i konfigurowalną liczbą iteracji (minimum 600 000) (`username`, `password`, `serverNonceEcho`), zlicza nieudane próby (maks. 3 na połączenie plus backoff per konto/IP), generuje tokeny sesyjne oraz sprawdza role `READ_WRITE`/`READ_ONLY`. W MVP konta są konfigurowane w pliku poza repozytorium; brak domyślnego hasła w kodzie.
* **`VaultStorageEngine` (Silnik Magazynu i Persystencji):** Wątkowo bezpieczny magazyn klucz-wartość z jednym krytycznym obszarem obejmującym zmianę modelu, snapshot i zapis pliku. Po udanym commicie `SET`/`DELETE` wykonuje atomową podmianę pliku tymczasowego, a plik plaintext `data/vault_store.json` jest ograniczeniem MVP i ma uprawnienia `0600`. Brakujący plik oznacza pusty magazyn; uszkodzony JSON powoduje bezpieczne zatrzymanie serwera z komunikatem administracyjnym, bez uruchamiania na częściowych danych.
* **`SecurityAuditLogger` (Moduł Logowania i Diagnostyki):** Rejestruje zredagowane zdarzenia sesji, błędy protokołu i incydenty bezpieczeństwa (np. odrzucony HMAC, próba replay). Nie zapisuje haseł, sekretów, tokenów, nonce, `hmacSecret`, payloadów ani surowych argumentów użytkownika.

#### C. Komponenty klienta (`Pus.Vault.Client`)
* **`CliCommandLoop` (Interfejs REPL / CLI):** Interaktywny parser poleceń (`login <user>`, `set <key>`, `get <key>`, `list`, `delete <key>`, `ping`, `exit`). Hasło i wartość `SET` są pobierane przez prompt bez echa, a wartości nie trafiają do argumentów procesu ani logów.
* **`PvspClientEngine` (Silnik Komunikacji i Auto-Recovery):** Zarządza aktywnym gniazdem `Socket` i strumieniem `SslStream`, serializuje zapisy przez jedną kolejkę writer’a, automatycznie inkrementuje licznik `Message ID`, podpisuje `DATA_REQ` kanonicznym HMAC oraz realizuje do 3 prób reconnectu (`1s`, `2s`, `4s`). Po reconnect automatycznie ponawia tylko `GET` i `LIST`.
* **`KeepAliveWorker` (Zadanie Tła Keep-Alive):** Asynchroniczny timer wysyłający przez wspólną kolejkę ramkę `PING (0x07)` co 20 sekund bezczynności, wyłącznie gdy nie trwa żądanie biznesowe.

### 2.3. Diagram komponentów i wdrożenia

```mermaid
flowchart TB
    subgraph ClientHost ["Stacja Klienta (Linux WSL2 / Container)"]
        CLI["CliCommandLoop<br/>(Parser komend CLI / REPL)"]
        CEngine["PvspClientEngine<br/>(Zarządzanie sesją, Retry & Auto-Reconnect)"]
        KA["KeepAliveWorker<br/>(Timer PING co 20s)"]
        CA_Cert[("certs/ca.crt<br/>(Zaufany Root CA)")]
    end

    subgraph CommonLib ["Wspólna Biblioteka (Pus.Vault.Common)"]
        Codec["PvspFrameCodec<br/>(12B Big-Endian Header + JSON)"]
        Crypto["PvspCryptoHelper<br/>(HMAC-SHA256, Nonce, CustomRootTrust)"]
    end

    subgraph ServerHost ["Stacja Serwera (Linux WSL2 / Docker Container)"]
        Listener["SocketConnectionListener<br/>(Raw Socket Dual-Stack IPv6/IPv4 + SslStream)"]
        Session["ClientSessionHandler<br/>(Maszyna Stanów, Anti-Replay, Rate Limit)"]
        Auth["AuthAndRbacModule<br/>(Weryfikacja kont, Ról i Tokenów)"]
        Storage["VaultStorageEngine<br/>(Serialized Commit + Atomic Snapshot)"]
        Logger["SecurityAuditLogger<br/>(Logi diagnostyczne i audytowe)"]
        
        Srv_Cert[("certs/server.crt<br/>certs/server.key")]
        Users_File[("config/users.json<br/>(hashy haseł, poza repo)")]
        DB_File[("data/vault_store.json<br/>(Plaintext MVP, 0600)")]
    end

    CLI --> CEngine
    KA --> CEngine
    CEngine -.-> Codec
    CEngine -.-> Crypto
    CEngine --> CA_Cert

    CEngine <==>|"Strumień TCP (Port 8443)<br/>Szyfrowany TLS 1.3 + Ramki PVSP"| Listener

    Listener --> Srv_Cert
    Listener --> Session
    Session -.-> Codec
    Session -.-> Crypto
    Session --> Auth
        Auth --> Users_File
    Session --> Storage
    Session --> Logger
    Storage <--> DB_File
```

### 2.4. Przepływ danych między komponentami (Data Flow)
Przepływ danych podczas realizacji typowego żądania (np. zapisu sekretu przez `set DB_PASS` i ukryty prompt wartości) przebiega następująco:
1. **Wejście użytkownika:** Użytkownik wpisuje komendę w `CliCommandLoop`. Parser weryfikuje poprawność argumentów (czy klucz nie jest pusty i nie przekracza 128 znaków).
2. **Konstrukcja i podpisanie pakietu:** `PvspClientEngine` pobiera z pamięci sesji `sessionToken` oraz `hmacSecret`, przydziela kolejne `Message ID` i za pomocą `PvspCryptoHelper` oblicza podpis `HMAC-SHA256` z kanonicznego, długościowanego formatu binarnego opisanego w Etapie 1.
3. **Serializacja binarna:** `PvspFrameCodec` serializuje obiekt żądania do UTF-8 JSON, wylicza jego długość w bajtach (`Payload Length`), buduje 12-bajtowy nagłówek binarny i zapisuje całość do szyfrowanego strumienia `SslStream` na gnieździe `Socket`.
4. **Odbiór i deszyfracja na serwerze:** `SocketConnectionListener` odbiera zaszyfrowane rekordy TLS i przekazuje odszyfrowany strumień bajtów do `ClientSessionHandler`.
5. **Walidacja warstwy protokołu i bezpieczeństwa:**
   * `PvspFrameCodec` odczytuje dokładnie 12 bajtów nagłówka, weryfikuje `Magic Bytes (0x5053)`, wersję (`0x01`) oraz limit rozmiaru (`<= 64 KiB`), a następnie odczytuje dokładnie `Payload Length` bajtów ładunku JSON.
   * `ClientSessionHandler` sprawdza stan sesji, limit payloadu i pól, kolejność `Message ID` (`last + 1` albo identyczny digest ostatniego żądania), okno $\pm 30\text{s}$ oraz limit 20 `DATA_REQ` na 10 sekund.
   * `PvspCryptoHelper` weryfikuje zgodność podpisu `HMAC-SHA256`.
   * `AuthAndRbacModule` sprawdza tożsamość sesji i uprawnienia roli zapisane po stronie serwera; klient nie może nadać sobie roli przez payload.
6. **Wykonanie operacji i persystencja:** `VaultStorageEngine` wykonuje operację pod wspólną blokadą, zapisuje snapshot do pliku tymczasowego, wykonuje flush i atomową podmianę. Dopiero po udanym commicie serwer zwraca `DATA_RESP OK`. Awaria zapisu daje `ERROR (500)` bez potwierdzenia zmiany.
7. **Odpowiedź:** Serwer buduje ramkę `DATA_RESP (0x06)` z tym samym numerem `Message ID`, koduje ją przez `PvspFrameCodec` i odsyła przez `SslStream` do klienta, który wyświetla potwierdzenie w terminalu.

---

## 3. Przypadki użycia (Use Cases)

Poniżej zdefiniowano **6 kompletnych przypadków użycia**, które wyczerpują wszystkie wymagania funkcjonalne oraz mechanizmy bezpieczeństwa i niezawodności protokołu PVSP.

### UC-01: Nawiązanie bezpiecznej sesji i uwierzytelnienie użytkownika
* **i. Cel:** Zestawienie szyfrowanego kanału TLS 1.3, weryfikacja certyfikatu serwera oraz zalogowanie użytkownika w celu uzyskania tokenu sesyjnego i klucza HMAC.
* **ii. Aktor:** Administrator (`READ_WRITE`) lub Programista (`READ_ONLY`).
* **iii. Warunki wstępne:** Serwer `Pus.Vault.Server` nasłuchuje na porcie `8443/TCP`. Klient posiada plik certyfikatu urzędu `ca.crt` oraz poprawne poświadczenia konta.
* **iv. Scenariusz główny:**
  1. Użytkownik uruchamia klienta i wydaje polecenie logowania (`login admin`), a następnie podaje hasło w ukrytym promptcie.
  2. Klient otwiera gniazdo TCP, inicjuje handshake TLS 1.3 i weryfikuje certyfikat serwera względem `ca.crt` (`CustomRootTrust`). Sesja osiąga stan `TLS_CONNECTED`.
  3. Klient wysyła ramkę `HELLO (0x01)` z `MsgID=1`, nazwą klienta i znacznikiem czasu.
  4. Serwer odsyła ramkę `HELLO_ACK (0x02)` z wygenerowanym 16-bajtowym `serverNonce` zapisanym jako 32 znaki HEX i zmienia stan sesji na `HANDSHAKED`.
  5. Klient wysyła ramkę `AUTH (0x03)` z `MsgID=2`, podając `username`, `password` oraz `serverNonceEcho`.
  6. Serwer pozytywnie weryfikuje dane, generuje `sessionToken` oraz klucz `hmacSecret`, zmienia stan na `AUTHENTICATED` i odsyła ramkę `AUTH_ACK (0x04)` wraz z rolą przypisaną do konta (`READ_WRITE` albo `READ_ONLY`).
* **v. Scenariusze alternatywne / błędy:**
  * *5a. Nieprawidłowy certyfikat serwera (Atak MitM):* Walidacja `CustomRootTrust` w kroku 2 kończy się niepowodzeniem. Klient natychmiast przerywa połączenie i zgłasza błąd bezpieczeństwa TLS.
  * *6a. Błędne hasło lub login:* Serwer odsyła ramkę `ERROR (201 ERR_AUTH_FAILED)` i inkrementuje licznik nieudanych prób. Po 3 nieudanej próbie serwer zamyka gniazdo TCP.
  * *6b. Przekroczenie czasu na `AUTH` (>15 s od `HELLO_ACK`):* Serwer odsyła `ERROR (105 ERR_TIMEOUT)` i zamyka połączenie.
* **vi. Wynik końcowy:** Sesja na serwerze jest w stanie `AUTHENTICATED`, a klient przechowuje w pamięci `sessionToken` oraz `hmacSecret`, gotowy do wykonywania operacji na danych.

### UC-02: Zapisanie lub aktualizacja sekretu w magazynie (`SET`)
* **i. Cel:** Bezpieczne umieszczenie nowego sekretu lub nadpisanie istniejącej wartości w magazynie serwera.
* **ii. Aktor:** Administrator (`READ_WRITE`).
* **iii. Warunki wstępne:** Aktor jest uwierzytelniony (stan sesji `AUTHENTICATED`, rola `READ_WRITE`).
* **iv. Scenariusz główny:**
  1. Administrator wpisuje w CLI `set STRIPE_API_KEY`, a następnie podaje wartość w promptcie bez echa.
  2. Klient buduje komunikat `DATA_REQ (0x05)` z akcją `"SET"`, przydziela kolejne `Message ID`, wylicza kanoniczny podpis `HMAC-SHA256` i wysyła ramkę do serwera.
  3. Serwer weryfikuje stan sesji, świeżość wiadomości (`Message ID`, `timestamp`), poprawność podpisu `HMAC` oraz uprawnienia roli `READ_WRITE`.
  4. Serwer pod wspólną blokadą aktualizuje model i atomowo utrwala snapshot w pliku `vault_store.json`.
  5. Dopiero po udanym commicie serwer odsyła `DATA_RESP (0x06)` ze statusem `"OK"` i potwierdzeniem nazwy klucza. Błąd persystencji daje `ERROR (500)` i nie jest raportowany jako sukces.
* **v. Scenariusze alternatywne / błędy:**
  * *3a. Brak uprawnień (wywołanie przez aktora `READ_ONLY`):* Serwer odrzuca operację i zwraca `ERROR (203 ERR_FORBIDDEN)`. Połączenie pozostaje otwarte.
  * *3b. Nieprawidłowy podpis HMAC (modyfikacja pakietu w locie):* Serwer wykrywa niezgodność skrótu, zwraca `ERROR (204 ERR_INVALID_HMAC)`, unieważnia sesję i zamyka gniazdo.
  * *3c. Zbyt duży ładunek (>64 KiB):* Serwer odrzuca ramkę kodem `ERROR (103 ERR_PAYLOAD_TOO_LARGE)` i zamyka połączenie.
* **vi. Wynik końcowy:** Sekret jest trwale zapisany na serwerze i dostępny do odczytu dla uprawnionych klientów.

### UC-03: Pobranie wartości sekretu po kluczu (`GET`)
* **i. Cel:** Odczytanie poufnej wartości sekretu przypisanej do podanego klucza.
* **ii. Aktor:** Administrator (`READ_WRITE`) lub Programista (`READ_ONLY`).
* **iii. Warunki wstępne:** Sesja znajduje się w stanie `AUTHENTICATED`.
* **iv. Scenariusz główny:**
  1. Aktor wydaje polecenie `get STRIPE_API_KEY`.
  2. Klient wysyła podpisaną kodem HMAC ramkę `DATA_REQ (0x05)` z polem `"action": "GET"` oraz `"key": "STRIPE_API_KEY"`.
  3. Serwer weryfikuje podpis HMAC, świeżość wiadomości oraz obecność klucza w `VaultStorageEngine`.
  4. Serwer odsyła ramkę `DATA_RESP (0x06)` zawierającą `status="OK"`, `action="GET"`, `key`, `value` oraz `timestamp`.
  5. Klient wyświetla pobraną wartość sekretu na ekranie terminala.
* **v. Scenariusze alternatywne / błędy:**
  * *3a. Klucz nie istnieje w magazynie:* Serwer odsyła ramkę `ERROR (404 ERR_KEY_NOT_FOUND)` z komunikatem diagnostycznym. Sesja pozostaje aktywna.
  * *3b. Wykrycie ataku powtórzeniowego (Replay Attack - stary `Message ID` lub `timestamp` spoza okna $\pm 30\text{s}$):* Serwer zwraca `ERROR (301 ERR_REPLAY_DETECTED)` i natychmiast zrywa połączenie.
* **vi. Wynik końcowy:** Aktor otrzymuje aktualną wartość sekretu bez naruszenia jej poufności w sieci.

### UC-04: Pobranie listy dostępnych kluczy sekretów (`LIST`)
* **i. Cel:** Uzyskanie wykazu wszystkich identyfikatorów sekretów przechowywanych aktualnie w magazynie (bez przesyłania ich poufnych wartości).
* **ii. Aktor:** Administrator (`READ_WRITE`) lub Programista (`READ_ONLY`).
* **iii. Warunki wstępne:** Sesja znajduje się w stanie `AUTHENTICATED`.
* **iv. Scenariusz główny:**
  1. Aktor wydaje polecenie `list`.
  2. Klient wysyła ramkę `DATA_REQ (0x05)` z akcją `"LIST"` i wyliczonym podpisem HMAC.
  3. Serwer weryfikuje żądanie, pobiera kolekcję kluczy ze słownika `VaultStorageEngine` i zwraca ramkę `DATA_RESP (0x06)` z `status`, `action`, `keys` i `timestamp`, np. `"keys": ["DB_HOST", "STRIPE_API_KEY"]`.
  4. Klient formatuje i wypisuje listę kluczy w konsoli.
* **v. Scenariusze alternatywne / błędy:**
  * *3a. Magazyn jest pusty:* Serwer zwraca `DATA_RESP (0x06)` z pustą tablicą `"keys": []`.
  * *3b. Przekroczenie limitu zapytań (>20 żądań w 10s):* Serwer blokuje wykonanie akcji i odsyła `ERROR (429 ERR_RATE_LIMIT)`.
  * *3c. Odpowiedź przekroczyłaby 64 KiB:* Serwer odsyła `ERROR (108 ERR_RESPONSE_TOO_LARGE)` i nie wysyła częściowej ramki. MVP ogranicza dodatkowo listę do 1 000 nazw.
* **vi. Wynik końcowy:** Aktor poznaje strukturę kluczy dostępnych w magazynie.

### UC-05: Usunięcie sekretu z magazynu (`DELETE`)
* **i. Cel:** Trwałe skasowanie wybranego sekretu z pamięci serwera oraz pliku persystencji.
* **ii. Aktor:** Administrator (`READ_WRITE`).
* **iii. Warunki wstępne:** Sesja znajduje się w stanie `AUTHENTICATED` z rolą `READ_WRITE`, a usuwany klucz istnieje w magazynie.
* **iv. Scenariusz główny:**
  1. Administrator wpisuje komendę `delete STRIPE_API_KEY`.
  2. Klient wysyła podpisaną ramkę `DATA_REQ (0x05)` z akcją `"DELETE"` oraz kluczem `"STRIPE_API_KEY"`.
  3. Serwer weryfikuje podpis HMAC oraz rolę `READ_WRITE`, pod wspólną blokadą usuwa wpis z modelu i aktualizuje plik `vault_store.json`.
  4. Po udanym commicie serwer odsyła `DATA_RESP (0x06)` ze statusem `"OK"`. Błąd zapisu daje `ERROR (500)`.
* **v. Scenariusze alternatywne / błędy:**
  * *3a. Próba usunięcia przez użytkownika `READ_ONLY`:* Serwer zwraca `ERROR (203 ERR_FORBIDDEN)` - dane pozostają nienaruszone.
  * *3b. Próba usunięcia nieistniejącego klucza:* Serwer zwraca `ERROR (404 ERR_KEY_NOT_FOUND)`.
* **vi. Wynik końcowy:** Sekret zostaje bezpowrotnie usunięty z systemu.

### UC-06: Utrzymanie sesji (*Keep-Alive*) oraz reaktywny reconnect
* **i. Cel:** Zapewnienie ciągłości pracy klienta podczas bezczynności oraz odtworzenie sesji po przejściowej awarii połączenia TCP, bez ryzykownego automatycznego powtarzania mutacji.
* **ii. Aktor:** Klient (`PvspClientEngine` / `KeepAliveWorker`) oraz Serwer (`ClientSessionHandler`).
* **iii. Warunki wstępne:** Sesja jest w stanie `AUTHENTICATED`.
* **iv. Scenariusz główny (Keep-Alive):**
  1. Użytkownik nie wpisuje żadnej komendy przez 20 sekund.
  2. Komponent `KeepAliveWorker` automatycznie wysyła ramkę `PING (0x07)` z `Payload Length = 0`.
  3. Serwer resetuje zegar bezczynności sesji (*Idle Timer*) i natychmiast odsyła ramkę `PONG (0x08)`.
* **v. Scenariusz alternatywny (Utrata połączenia i Auto-Reconnect podczas żądania):**
  1. Użytkownik wydaje komendę `get DB_HOST`, ale połączenie sieciowe ulega zerwaniu (lub mija 5-sekundowy `Request Timeout`).
  2. `PvspClientEngine` przechwytuje wyjątek sieciowy, zamyka uszkodzone gniazdo i informuje użytkownika w konsoli o rozpoczęciu procedury *Auto-Reconnect*.
  3. Klient wykonuje do 3 prób połączenia z opóźnieniem *Exponential Backoff* (`1s`, `2s`, `4s`).
  4. Po odzyskaniu łączności klient automatycznie zestawia nowy kanał TLS 1.3 i wykonuje `HELLO` $\rightarrow$ `AUTH`. Hasło może być użyte wyłącznie z pamięci procesu do czasu zakończenia klienta; jeśli nie jest dostępne, klient ponownie prosi o nie przez ukryty prompt. Następnie pobiera nowy `sessionToken` oraz `hmacSecret` i ponawia `get DB_HOST`.
  5. Jeśli przerwane żądanie było `SET` albo `DELETE`, klient nie ponawia go. Informuje użytkownika, że wynik jest nieznany i zaleca weryfikację przez `GET`/`LIST`.
* **vi. Wynik końcowy:** Keep-alive działa przez wspólną kolejkę zapisu, a reaktywny reconnect maskuje przejściowe awarie tylko dla bezpiecznych operacji odczytu.

---

## 4. Mapowanie aplikacji na protokół PVSP

### 4.1. Powiązanie funkcji aplikacji z komunikatami i stanami protokołu

Wszystkie funkcje biznesowe oraz techniczne aplikacji `PUS-Vault` mapują się bezpośrednio (1:1) na typy wiadomości oraz maszynę stanów zdefiniowaną w specyfikacji protokołu **PVSP (Etap 1)**:

| Funkcja aplikacji / Komenda CLI | Wymagany stan sesji przed akcją | Wysyłany komunikat (Klient $\rightarrow$ Serwer) | Oczekiwana odpowiedź (Serwer $\rightarrow$ Klient) | Stan sesji po pomyślnym wykonaniu | Powiązany przypadek użycia |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Nawiązanie połączenia TCP + TLS | `DISCONNECTED` | Handshake TCP + TLS 1.3 | Certyfikat X.509 (`server.crt`) | `TLS_CONNECTED` | UC-01 |
| Inicjalizacja sesji (automatycznie przy `login`) | `TLS_CONNECTED` | `0x01 HELLO` | `0x02 HELLO_ACK` (zwraca `serverNonce`) | `HANDSHAKED` | UC-01 |
| Logowanie użytkownika (`login <user>` + ukryty prompt hasła) | `HANDSHAKED` | `0x03 AUTH` | `0x04 AUTH_ACK` (lub `0xFF ERROR 201`) | `AUTHENTICATED` | UC-01 |
| Zapis sekretu (`set <key>` + prompt wartości) | `AUTHENTICATED` (rola `READ_WRITE`) | `0x05 DATA_REQ` (`action="SET"`, +HMAC) | `0x06 DATA_RESP` (`status`, `action`, `key`, `timestamp`) lub `0xFF ERROR` | `AUTHENTICATED` | UC-02 |
| Pobranie sekretu (`get <key>`) | `AUTHENTICATED` (dowolna rola) | `0x05 DATA_REQ` (`action="GET"`, +HMAC) | `0x06 DATA_RESP` (`status`, `action`, `key`, `value`, `timestamp`) lub `0xFF ERROR 404` | `AUTHENTICATED` | UC-03 |
| Wylistowanie kluczy (`list`) | `AUTHENTICATED` (dowolna rola) | `0x05 DATA_REQ` (`action="LIST"`, +HMAC) | `0x06 DATA_RESP` (`status`, `action`, `keys`, `timestamp`) | `AUTHENTICATED` | UC-04 |
| Usunięcie sekretu (`delete <key>`) | `AUTHENTICATED` (rola `READ_WRITE`) | `0x05 DATA_REQ` (`action="DELETE"`, +HMAC) | `0x06 DATA_RESP` (`status`, `action`, `key`, `timestamp`) lub `0xFF ERROR 203/404` | `AUTHENTICATED` | UC-05 |
| Podtrzymanie sesji (`ping` lub timer tła) | `AUTHENTICATED` | `0x07 PING` (`Len=0`) | `0x08 PONG` (`Len=0`) | `AUTHENTICATED` | UC-06 |
| Zamknięcie aplikacji (`exit`) | Dowolny aktywny | `0x09 BYE` (`Len=0`) | Zamknięcie TLS i gniazda TCP (`FIN`) | `CLOSED` | UC-01..06 |

### 4.2. Jak protokół wspiera realizację przypadków użycia?
1. **Bezproblemowa obsługa strumienia TCP:** Dzięki umieszczeniu pola `Payload Length` na bajtach `8..11` nagłówka binarnego, aplikacja kliencka i serwerowa mogą przesyłać wartości sekretów o dowolnym rozmiarze (do 64 KiB payloadu), zawierające znaki nowej linii, spacje czy dane zakodowane w Base64, bez ryzyka błędnego pocięcia wiadomości przez bufor karty sieciowej.
2. **Korelacja i odporność na duplikaty:** Pole `Message ID` (bajty `4..7`) pozwala silnikowi klienta (`PvspClientEngine`) jednoznacznie dopasować odpowiedź serwera do wysłanego polecenia CLI. W tej wersji serwer zwraca zbuforowany wynik (`302 ERR_DUPLICATE_MSG`) tylko dla identycznego duplikatu w bieżącej sesji; reconnect nie służy do retry mutacji.
3. **Wbudowana kontrola uprawnień (RBAC):** Przekazanie pola `role` w komunikacie `AUTH_ACK (0x04)` pozwala aplikacji klienckiej od razu poinformować użytkownika o poziomie jego uprawnień, natomiast weryfikacja `sessionToken` po stronie serwera przy każdym `DATA_REQ (0x05)` gwarantuje egzekwowanie bezpieczeństwa niezależnie od klienta.

### 4.3. Ewentualne rozszerzenia protokołu (z uzasadnieniem)
Specyfikacja protokołu PVSP z Etapu 1 została dostosowana do zakresu MVP. Rozszerzenia pozostają opcjonalne i nie są wymagane do podstawowego działania:
* **Osobny tryb diagnostyczny (`--diagnostics`):** Test harness, a nie zwykły tryb klienta, może celowo wysłać ramkę z uszkodzonym HMAC (`ERR_INVALID_HMAC 204`), starym timestampem (`ERR_REPLAY_DETECTED 301`) lub błędnym `Magic Bytes` (`ERR_BAD_MAGIC 100`). Tryb wymaga jawnego przełącznika, nie loguje sekretów i służy do testów/prezentacji.
* **Szyfrowanie at rest i paginacja `LIST`:** Mogą zostać dodane bez zmiany podstawowego framingu; nie są wymagane w MVP.

---

## 5. Wymagania niefunkcjonalne

### 5.1. Bezpieczeństwo (Security)
* **Brak transmisji jawnej:** Całość ruchu sieciowego musi odbywać się wyłącznie wewnątrz TLS 1.3 (`SslStream`). Cipher suite jest negocjowany przez środowisko; projekt nie zakłada na sztywno `AES-256-GCM`. Połączenia niezaszyfrowane są odrzucane na poziomie handshake'u.
* **Własna infrastruktura PKI (Custom CA):** Klient nie ufa globalnemu magazynowi systemu operacyjnego dla domeny lokalnej, lecz jawnie weryfikuje `ca.crt`, łańcuch, SAN, EKU `serverAuth`, nazwę hosta/adres IP oraz ważność certyfikatu.
* **Integralność aplikacyjna i Anti-Replay:** Każda operacja na sekretach (`DATA_REQ`) musi posiadać HMAC-SHA256 z kanonicznego wejścia, aktualny `timestamp` ($\pm 30\text{s}$) i kolejne `Message ID`. Porównanie HMAC jest stałoczasowe.
* **Uwierzytelnianie:** Serwer przechowuje wyłącznie hashe haseł z solą, a klient pobiera hasło przez ukryty prompt. `sessionToken`, `hmacSecret`, nonce i hasła nie są zapisywane ani logowane.
* **Bezpieczna obsługa błędów i logów:** Komunikaty `ERROR (0xFF)` oraz logi serwera nigdy nie mogą zawierać wartości sekretów, haseł, tokenów, kluczy HMAC, nonce, surowych payloadów ani nieescapowanych danych użytkownika.
* **Zakres MVP at rest:** `data/vault_store.json` pozostaje plaintext jako jawne ograniczenie projektu. Katalog ma uprawnienia `0700`, plik `0600`, a szyfrowanie magazynu jest rozszerzeniem poza MVP.

### 5.2. Wydajność (Performance)
* **Współbieżność:** Serwer musi obsługiwać minimum **50 jednoczesnych sesji klienckich** bez blokowania wątku akceptującego, z asynchronicznym I/O. Pojedyncza sesja obsługuje jedno żądanie aplikacyjne naraz.
* **Czas odpowiedzi (Latency):** Dla rozgrzanego połączenia loopback średnie przetworzenie `GET`/`SET` po stronie serwera nie powinno przekraczać **15 ms**; raport powinien podać liczbę próbek oraz p50/p95.
* **Narzut protokołu:** Stały narzut binarnego nagłówka PVSP wynosi dokładnie **12 bajtów** na wiadomość, co zapewnia minimalne obciążenie pasma sieciowego.

### 5.3. Niezawodność i Odporność (Reliability & Resilience)
* **Atomowość zapisu danych:** Jedna blokada obejmuje zmianę modelu, utworzenie snapshotu, zapis i flush pliku tymczasowego (`vault_store.json.tmp`) oraz podmianę pliku. Odpowiedź `OK` jest wysyłana dopiero po commicie. Awaria zapisu nie może potwierdzić nieutrwalonej zmiany; pełna gwarancja po awarii zasilania zależy od systemu plików.
* **Izolacja awarii klientów:** Krytyczny błąd protokołu, nieobsłużony wyjątek lub nagłe rozłączenie jednego klienta powoduje zamknięcie wyłącznie jego gniazda i zwolnienie jego sesji, bez żadnego wpływu na pracę serwera oraz pozostałych podłączonych klientów.
* **Samonaprawa połączenia (Self-Healing):** Klient automatycznie wykrywa zerwanie połączenia i przeprowadza do 3 prób rekonfiguracji sesji z algorytmem *Exponential Backoff*. Automatycznie ponawia tylko `GET` i `LIST`; `SET`/`DELETE` kończą się komunikatem o nieznanym wyniku.

### 5.4. Skalowalność (Scalability)
* **Architektura Dual-Stack:** Zastosowanie gniazd IPv6 w trybie `DualMode = true` pozwala na jednoczesną obsługę nowoczesnych sieci IPv6 oraz klasycznych sieci IPv4 na jednym deskryptorze gniazda.
* **Separacja warstwy składowania:** Wydzielenie logiki magazynu do klasy `VaultStorageEngine` (za interfejsem repozytorium) pozwala w przyszłości na łatwe zastąpienie lokalnego pliku JSON zewnętrznym klastrem (np. Redis lub PostgreSQL) bez modyfikacji ani jednej linijki kodu obsługującego protokół PVSP.

### 5.5. Logowanie i Diagnostyka (Logging & Monitoring)
* Serwer oraz klient generują ustrukturyzowane logi w języku angielskim, zawierające znacznik czasu UTC, poziom zdarzenia, identyfikator sesji/adres IP oraz typ ramki. Logi nie zawierają wartości kluczy ani payloadów; przykład: `[2026-11-12 14:20:05 UTC] [INFO] [Session:127.0.0.1:54321] Rcv MsgID=3 Type=DATA_REQ Action=SET -> Status=OK`. Dane użytkownika są escapowane, a plik logu ma rotację i ograniczone uprawnienia.

---

## 6. Plan implementacji i testowania

### 6.1. Zakres MVP (Minimum Viable Product) oraz elementy dodatkowe (Bonusowe)

#### Zakres podstawowy (MVP projektu):
1. Skrypt `scripts/generate_certs.sh` generujący strukturę PKI (własny Root CA `ca.crt` oraz certyfikaty `server.crt` i `server.key` w formacie PEM).
2. Biblioteka `Pus.Vault.Common` z pełną implementacją 12-bajtowego kodeka ramek (`PvspFrameCodec`), obsługą `ReadExactly`, kalkulatorem `HMAC-SHA256` oraz modelami JSON.
3. Wielowątkowy serwer `Pus.Vault.Server` obsługujący gniazda TCP Dual-Stack, TLS 1.3, maszynę stanów sesji, konta o rolach `READ_WRITE` i `READ_ONLY`, ochronę Anti-Replay, *Rate Limiting*, timeouty oraz persystencję do pliku JSON.
4. Klient `Pus.Vault.Client` (CLI) umożliwiający wykonanie wszystkich 6 przypadków użycia (logowanie, `SET`, `GET`, `LIST`, `DELETE`, `PING`, `BYE`), reaktywny *Reconnect* z retry tylko dla `GET`/`LIST` oraz osobny tryb diagnostyczny uruchamiany flagą.

#### Zakres rozszerzony (Pod punkty bonusowe z regulaminu):
1. **Zestaw testów automatycznych (`Pus.Vault.Tests` - xUnit):** Projekt testów jednostkowych i integracyjnych automatycznie weryfikujący poprawność serializacji nagłówków binarnych, obsługę pofragmentowanych strumieni TCP, wykrywanie manipulacji HMAC oraz odrzucanie ataków Replay.
2. **Konteneryzacja (`Dockerfile` + `docker-compose.yml`):** Przygotowanie konfiguracji pozwalającej na uruchomienie serwera i klienta w izolowanych kontenerach Docker w dedykowanej sieci wirtualnej.

### 6.2. Plan testów (Funkcjonalne, Błędów, Bezpieczeństwa, Obciążeniowe)

Weryfikacja systemu w Etapie 3 zostanie przeprowadzona według poniższej matrycy testowej:

| ID Testu | Kategoria | Nazwa i opis scenariusza testowego | Oczekiwany rezultat (Kryterium zaliczenia) |
| :--- | :--- | :--- | :--- |
| **T-01** | **Funkcjonalny** | Pełny cykl życia sesji i operacji CRUD (`HELLO` $\rightarrow$ `AUTH` jako `admin` $\rightarrow$ `SET` $\rightarrow$ `GET` $\rightarrow$ `LIST` $\rightarrow$ `DELETE` $\rightarrow$ `BYE`). | Wszystkie operacje zwracają `DATA_RESP (OK)`, a zmiany są widoczne w pliku `vault_store.json`. |
| **T-02** | **Funkcjonalny** | Test persystencji po restarcie serwera: zapis sekretu `SET`, wyłączenie procesu serwera, ponowne uruchomienie i wywołanie `GET`. | Serwer po starcie wczytuje `vault_store.json` i poprawnie zwraca wcześniej zapisany sekret. |
| **T-03** | **Bezpieczeństwa** | Próba połączenia z niezaufanym CA, błędnym SAN/nazwą hosta albo certyfikatem bez `serverAuth`. | Handshake TLS 1.3 zostaje przerwany wyjątkiem `AuthenticationException`; klient nie przechodzi do PVSP. |
| **T-04** | **Bezpieczeństwa** | Weryfikacja RBAC: zalogowanie na konto `reader` (`READ_ONLY`), wykonanie poprawnego `GET`, a następnie próba wywołania `SET` oraz `DELETE`. | Operacja `GET` zwraca dane; operacje `SET` i `DELETE` zostają zablokowane kodem `203 ERR_FORBIDDEN`. |
| **T-05** | **Bezpieczeństwa** | Naruszenie integralności danych: celowa zmiana 1 bajtu w podpisie `hmac` wysyłanej ramki `DATA_REQ`. | Serwer odrzuca pakiet kodem `204 ERR_INVALID_HMAC`, loguje zredagowany incydent `[SECURITY]` i zamyka połączenie. |
| **T-06** | **Bezpieczeństwa** | Symulacja replay: wysłanie starego `Message ID`, ID z luką albo timestampu starszego niż 30 sekund. | Serwer zwraca `301 ERR_REPLAY_DETECTED`, nie wykonuje operacji i zamyka sesję. |
| **T-07** | **Błędów i Odporności** | Test pofragmentowanego strumienia TCP (*Partial Reads*): wysłanie ramki `HELLO` (payload 56 bajtów) w porcjach po 3 bajty z opóźnieniem `50 ms`. | Pętla `ReadExactly` na serwerze bezbłędnie składa nagłówek i payload w ramach deadline’u oraz zwraca `HELLO_ACK`. |
| **T-08** | **Błędów i Odporności** | Uszkodzona ramka binarna: błędne `Magic Bytes` (np. `0x00 0x00`) albo `Payload Length > 64 KiB`. | Serwer zwraca odpowiednio `100 ERR_BAD_MAGIC` lub `103 ERR_PAYLOAD_TOO_LARGE` tylko po odczytaniu pełnego nagłówka, nie alokuje nadmiarowego bufora i zamyka gniazdo. |
| **T-09** | **Błędów i Odporności** | Reconnect po zerwaniu podczas `GET` oraz utrata odpowiedzi podczas `SET`. | Dla `GET` klient wykonuje do 3 prób, ponownie uwierzytelnia sesję i powtarza odczyt. Dla `SET` nie wykonuje automatycznego retry i pokazuje „wynik nieznany”. |
| **T-10** | **Obciążeniowy / Limitów** | Wysłanie 25 `DATA_REQ` w ciągu 1 sekundy oraz równoległe podłączenie **50 klientów** wysyłających żądania. | Pierwsze 20 żądań w oknie przechodzi, kolejne otrzymują `429 ERR_RATE_LIMIT`. Serwer stabilnie obsługuje 50 sesji, a rozgrzany loopback spełnia średnią `<15 ms`; raport podaje p50/p95. |
| **T-11** | **Walidacji** | Niepoprawny UTF-8/JSON, brakujące i nieznane pola, zły typ, duplikat klucza JSON, `action` z niepasującymi polami oraz odpowiedź `LIST` ponad limit. | Serwer zwraca właściwie `104`, `106`, `107` albo `108`, zachowuje synchronizację po zużyciu payloadu i nie wykonuje operacji. |
| **T-12** | **Persystencji i logów** | Dwa równoległe `SET`/`DELETE`, nieudany zapis pliku, restart z uszkodzonym magazynem oraz przegląd logów po operacjach na sekretach. | Snapshoty są spójne, błąd zapisu nie daje `OK`, uszkodzony plik jest obsłużony bez uruchomienia na nieznanym stanie, a logi nie zawierają sekretów, haseł, tokenów, nonce ani payloadów. |

Pomiar wydajności wykonuje się po rozgrzaniu procesu i połączenia TLS, osobno dla 50 aktywnych sesji. Raport podaje liczbę próbek, p50, p95, średnią, środowisko oraz rozróżnia czas przetwarzania po stronie serwera od pełnego round-trip.

#### Kryteria zakończenia implementacji (Definition of Done):
Projekt uznaje się za gotowy do obrony (Etap 3), gdy 100% testów z tabeli `T-01`..`T-12` kończy się wynikiem pozytywnym, kod kompiluje się bez ostrzeżeń w środowisku Linux (.NET 8 SDK), a repozytorium zawiera kompletną instrukcję uruchomienia (`README.md`) z opisem ograniczenia plaintext storage.

Przed oddaniem Etapu 1 i Etapu 2 pliki Markdown zostaną wyeksportowane do PDF zgodnie z regulaminem. PDF musi zawierać wyrenderowane diagramy i te same kontrakty PVSP, a każdy członek zespołu przesyła wymagane materiały na Deltę.

### 6.3. Podział pracy w zespole

Prace projektowe, analityczne, implementacyjne oraz weryfikacyjne zostały podzielone pomiędzy członków zespołu w sposób zapewniający spójność architektury i niezależną weryfikację jakości rozwiązania:

| Członek zespołu | Główny obszar odpowiedzialności | Szczegółowy zakres realizowanych zadań |
| :--- | :--- | :--- |
| **Damian Judka** | **Analiza wymagań, Projektowanie funkcjonalne, Testy i Weryfikacja Jakości (QA) oraz Dokumentacja** | 1. Analiza wymagań funkcjonalnych i niefunkcjonalnych systemu `PUS-Vault` oraz opracowanie przypadków użycia (`UC-01`..`UC-06`).<br/>2. Opracowanie modelu zagrożeń bezpieczeństwa (STRIDE) oraz reguł kontroli dostępu (RBAC).<br/>3. Przygotowanie planu testów oraz realizacja testów manualnych, scenariuszy błędnych, testów bezpieczeństwa i testów obciążeniowych (`T-01`..`T-12`).<br/>4. Redakcja techniczna dokumentacji projektowej (Etap 1, Etap 2) oraz przygotowanie instrukcji uruchomienia i materiałów do prezentacji końcowej (Etap 3). |
| **Kacper Gumulak** | **Architektura techniczna, Implementacja niskopoziomowa (.NET 8 / C#), Kryptografia oraz Konteneryzacja** | 1. Implementacja biblioteki wspólnej `Pus.Vault.Common` (binarny kodek ramek `PvspFrameCodec`, obsługa `ReadExactly`, wyliczanie podpisów `HMAC-SHA256`, modele JSON).<br/>2. Implementacja wielowątkowego serwera `Pus.Vault.Server` (surowe gniazda TCP Dual-Stack, integracja TLS 1.3 `SslStream` z Custom CA, maszyna stanów sesji, silnik `VaultStorageEngine`).<br/>3. Implementacja klienta `Pus.Vault.Client` (interfejs CLI/REPL, obsługa *Keep-Alive* oraz mechanizmu *Auto-Reconnect*).<br/>4. Przygotowanie skryptów OpenSSL (`generate_certs.sh`), testów jednostkowych `xUnit` oraz konfiguracji kontenerów Docker. |