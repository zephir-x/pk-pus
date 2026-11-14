# Review dokumentów projektu PUS-Vault

**Przedmiot:** Programowanie Usług Sieciowych
**Dokumenty poddane review:**

- `Assets/zasady-zaliczenia.pdf`
- `Assets/specyfikacja.md` — Etap 1, PVSP v1.0
- `Assets/projekt-aplikacji.md` — Etap 2, PUS-Vault

**Cel review:** wykrycie problemów przed implementacją, ze szczególnym uwzględnieniem implementowalności protokołu wire-level, bezpieczeństwa, zgodności obu etapów, odporności na błędy oraz zgodności z wymaganiami zaliczenia.

## Wniosek ogólny

Dokumenty mają dobrą strukturę i obejmują praktycznie wszystkie punkty wymagane dla Etapu 1 i Etapu 2. Pomysł aplikacji jest adekwatny do przedmiotu, a zakres funkcjonalny jest wystarczający do zademonstrowania własnego protokołu klient–serwer.

W obecnej postaci dokumentacja **nie jest jeszcze gotowa do bezpiecznej implementacji**. Najważniejsze elementy protokołu nie tworzą jednoznacznego kontraktu:

1. nie jest określone, jak dokładnie działają `Message ID`, duplikaty, odpowiedzi i równoległe żądania;
2. sposób obliczania HMAC jest niejednoznaczny i podatny na różne interpretacje implementacyjne;
3. automatyczny retry po reconnect może wykonać `SET` albo `DELETE` ponownie po tym, jak pierwsza operacja już się udała;
4. występują sprzeczne timeouty i kody błędów;
5. wiele przykładowych wartości `Payload Length` jest niepoprawnych;
6. zapis do `vault_store.json` nie zapewnia jeszcze poprawnej atomowości przy współbieżnych żądaniach i przechowuje sekrety jawnie na dysku;
7. klient i worker keep-alive mogą równocześnie pisać do tego samego `SslStream`.

Przed rozpoczęciem implementacji należy najpierw zamknąć kontrakt protokołu i poprawić przykłady. Inaczej istnieje wysokie ryzyko, że klient, serwer i testy będą zgodne z trzema różnymi interpretacjami specyfikacji.

## Priorytety

- **BLOKER** — problem uniemożliwiający jednoznaczną implementację albo powodujący błędne/niebezpieczne działanie.
- **WYSOKI** — problem bezpieczeństwa, współbieżności lub niezawodności, który powinien zostać rozwiązany przed implementacją danej funkcji.
- **ŚREDNI** — brak doprecyzowania albo niespójność utrudniająca testowanie, dokumentację lub prezentację.
- **NISKI** — jakość dokumentacji, ergonomia albo usprawnienie niewpływające na podstawowy kontrakt.

## Co jest zrobione dobrze

- Zakres Etapu 1 pokrywa wymagane przez regulamin obszary: cel, transport, format ramek, stany, bezpieczeństwo, błędy i scenariusze.
- Etap 2 zawiera architekturę klient–serwer, diagramy, sześć przypadków użycia, mapowanie funkcji na protokół, wymagania niefunkcjonalne oraz plan testów.
- TCP jest używany jako transport strumieniowy, a framing przez stały nagłówek z długością payloadu jest właściwym rozwiązaniem problemu partial reads.
- Użycie TLS, własnego CA, RBAC, limitów, timeoutów i testów błędnych scenariuszy dobrze odpowiada wymaganiom projektu grupowego.
- Zdefiniowano scenariusze `SET`, `GET`, `LIST`, `DELETE`, błędny HMAC, replay, fragmentację danych i reconnect.
- Podział pracy oraz zakres MVP są opisane wystarczająco konkretnie, choć zakres MVP jest ambitny.

## Problemy blokujące przed implementacją

### B-01. Niepełna semantyka `Message ID`, kierunków i odpowiedzi

**Miejsce:** Etap 1, sekcje 3.1–3.3, 4.2, 4.3, 6.4; Etap 2, sekcja 4.1.

`Message ID` jest opisany jako numer nadawany przez klienta, ale jednocześnie `PING`, `PONG` i `BYE` są oznaczone jako komunikaty obu kierunków. Nie wiadomo:

- czy serwer może wysłać własny `PING`;
- kto nadaje `Message ID`, gdy serwer inicjuje komunikat;
- czy `PONG` zawsze kopiuje ID `PING`;
- czy `BYE` wymaga odpowiedzi, czy obie strony po prostu zamykają połączenie;
- czy `Message ID` jest liczone osobno dla każdego połączenia, sesji uwierzytelnionej czy globalnie;
- czy dozwolone są równoległe żądania;
- co oznacza luka w numeracji, na przykład `1, 2, 4`;
- co dzieje się po przepełnieniu `uint32`.

Jest to również niespójne z opisem „ściśle rosnącego” ID oraz z obsługą duplikatu o tym samym ID.

**Zalecana poprawka dla MVP:**

- Klient jest jedynym nadawcą `HELLO`, `AUTH`, `DATA_REQ`, `PING` i `BYE`.
- Serwer odpowiada odpowiednio `HELLO_ACK`, `AUTH_ACK`, `DATA_RESP`, `PONG` albo `ERROR`.
- `Message ID` jest liczone od `1` osobno dla każdego połączenia TCP/TLS. Wartość `0` jest zarezerwowana.
- Każda odpowiedź kopiuje ID żądania.
- W MVP należy zakazać więcej niż jednego oczekującego żądania aplikacyjnego albo dokładnie opisać korelację i obsługę odpowiedzi poza kolejnością.
- `BYE` nie wymaga osobnego `BYE_ACK`: po poprawnym odebraniu strony zamykają sesję. Jeśli ma istnieć odpowiedź, trzeba dodać jej typ i opisać timeout.
- Po osiągnięciu `uint32.MaxValue` klient nie wysyła kolejnej ramki w tej sesji i zestawia nowe połączenie.

Jeżeli w przyszłości serwer ma inicjować `PING` albo `BYE`, należy dodać osobne ID nadawcy/kierunku lub jasno zdefiniować osobny licznik serwera.

### B-02. Brak pełnej maszyny stanów i macierzy dozwolonych komunikatów

Diagram pokazuje główne przejścia, ale nie definiuje zachowania dla wielu realnych przypadków:

- `HELLO` otrzymany drugi raz;
- `AUTH` przed `HELLO`;
- `DATA_REQ` przed `AUTH`;
- `PING` przed uwierzytelnieniem;
- `PONG` otrzymany jako samodzielny komunikat;
- `DATA_REQ` po `BYE`;
- `HELLO` po przejściu do `AUTHENTICATED`;
- nieznany typ komunikatu w każdym stanie;
- kolejny błędny JSON po wcześniejszym błędnym JSON;
- otrzymanie `BYE` w trakcie `TLS_CONNECTED` albo `HANDSHAKED`;
- rozłączenie klienta w połowie nagłówka lub payloadu.

Należy dodać tabelę lub formalną listę:

- stan;
- dozwolone typy komunikatów;
- oczekiwany kierunek;
- akcja po poprawnym komunikacie;
- kod błędu po komunikacie niedozwolonym;
- czy po błędzie połączenie pozostaje otwarte.

Warto również rozdzielić `CLOSING` od `CLOSED`, aby opisać okres pomiędzy wysłaniem `BYE`/`ERROR` a zamknięciem TLS.

### B-03. HMAC ma niejednoznaczny i niebezpieczny format wejściowy

Wzór:

`HMAC_SHA256(hmacSecret, "{MessageID}|{sessionToken}|{action}|{key}|{value}|{timestamp}")`

nie definiuje jednoznacznych bajtów wejściowych. Problemy:

- `key` lub `value` mogą zawierać znak `|`;
- nie wiadomo, jak reprezentować brak pola, pusty string i `null`;
- nie wiadomo, czy liczba jest zapisywana jako tekst, jaki jest format znaku minus i kodowanie timestampu;
- nie wiadomo, czy tekst jest kodowany UTF-8;
- `MessageID` jest w nagłówku, a nie w JSON;
- nie jest podpisany `Message Type`, wersja ani kontekst protokołu;
- nie jest określone, czy `hmacSecret` z Base64/HEX jest dekodowany do bajtów, czy traktowany jako tekst;
- nie jest określone, czy wielkość liter w HEX ma znaczenie;
- nie jest określone użycie porównania stałoczasowego;
- nie ma wektora testowego zawierającego klucz, dokładne bajty wejściowe i oczekiwany wynik.

**Zalecenie:** nie podpisywać konkatenacji z separatorem. Zdefiniować wersjonowany, długościowany format binarny, na przykład:

```text
context = "PVSP-HMAC-v1"
         || version (uint8)
         || messageType (uint8)
         || messageId (uint32, Big-Endian)
         || sessionTokenLength (uint32, Big-Endian)
         || UTF-8(sessionToken)
         || keyPresent (uint8)
         || keyLength (uint32, Big-Endian, jeśli obecny)
         || UTF-8(key, jeśli obecny)
         || valuePresent (uint8)
         || valueLength (uint32, Big-Endian, jeśli obecny)
         || UTF-8(value, jeśli obecny)
         || timestamp (int64, Big-Endian)
```

`hmac` powinien być dokładnie 32-bajtowym wynikiem, kodowanym w jednym ustalonym formacie, najlepiej HEX albo Base64, ale nie „HEX/Base64”. Należy użyć porównania stałoczasowego i opisać kolejność walidacji.

Alternatywnie można zdefiniować kanoniczny JSON, ale wtedy trzeba opisać sortowanie pól, reprezentację liczb, brakujące pola, Unicode, escaping i duplikaty kluczy. Samo `JsonSerializer` bez takiej reguły nie jest wystarczającym kontraktem między implementacjami.

### B-04. Anti-replay i retry nie rozwiązują tego samego problemu

Obecny cache `LastResponseBytes` działa wyłącznie w jednej sesji TCP. Po reconnect:

1. klient dostaje nowy `sessionToken` i nowy `hmacSecret`;
2. licznik `Message ID` zaczyna się od `1`;
3. serwer nie ma informacji, że żądanie z poprzedniej sesji zostało już wykonane;
4. utracona odpowiedź może oznaczać, że `SET` albo `DELETE` zostały wykonane, ale klient ponowi operację.

To tworzy klasyczny stan „wynik nieznany”. Dla `SET` ponowienie może być pozornie nieszkodliwe, ale dla `DELETE` druga próba może dostać `KEY_NOT_FOUND`, mimo że pierwsza operacja zakończyła się sukcesem. Dla innych operacji również może zmienić się wynik pomiędzy próbami.

**Należy wybrać jedną z dwóch strategii:**

1. **Prostsza i zalecana dla MVP:** automatycznie ponawiać tylko `GET` i `LIST`. Po utracie odpowiedzi dla `SET`/`DELETE` zgłaszać użytkownikowi „wynik nieznany” i nie wykonywać cichego retry.
2. **Pełne retry mutacji:** dodać stabilne `operationId` generowane przed pierwszym wysłaniem i używane ponownie po reconnect. Serwer musi przechowywać wynik operacji pod kluczem obejmującym tożsamość użytkownika i `operationId`, a zapis wyniku oraz zmiany magazynu musi być spójny. Sam cache ostatniej odpowiedzi w kontekście sesji nie wystarczy.

Jeżeli deduplikacja ma działać po restarcie serwera, jej dane muszą być również utrwalane. W przeciwnym razie należy jasno ograniczyć gwarancję do czasu życia jednego procesu serwera.

### B-05. Sprzeczne timeouty

W dokumentach występują jednocześnie:

- 10 sekund na `HELLO` w opisie stanu i diagramie;
- 15 sekund na ukończenie `HELLO` oraz `AUTH` w tabeli timeoutów;
- 15 sekund na autoryzację w Etapie 2;
- 5 sekund timeoutu żądania klienta;
- 60 sekund idle timeoutu serwera;
- `PING` co 20 sekund.

Nie wiadomo, czy 15 sekund jest:

- całym deadline’em od zakończenia TLS do `AUTH`;
- osobnym timeoutem na `AUTH` po `HELLO`;
- zamiennikiem wcześniejszych 10 sekund.

**Proponowana jednoznaczna wersja:**

- TLS handshake: 10 sekund;
- od zakończenia TLS do odebrania pełnego `HELLO`: 10 sekund;
- od wysłania `HELLO_ACK` do odebrania pełnego `AUTH`: 15 sekund;
- odebranie nagłówka i payloadu: wspólny deadline odczytu, np. 5 sekund, z wyjątkiem bardzo wolnego testu fragmentacji;
- odpowiedź na żądanie klienta: 5 sekund;
- po `PING`: 5 sekund na `PONG`;
- idle timeout: 60 sekund bez jakiejkolwiek poprawnej ramki.

W implementacji opartej na `SslStream` nie należy polegać wyłącznie na `Socket.ReceiveTimeout`. Timeouty trzeba egzekwować przez `CancellationToken`/deadline wokół `AuthenticateAsServerAsync`, `ReadAsync` i `WriteAsync`, ponieważ asynchroniczne operacje strumienia nie muszą zachowywać się tak jak synchroniczne `Socket.Receive`.

Do pomiaru deadline’ów używać monotonicznego zegara. Zegar ścienny UTC może służyć do walidacji `timestamp`, ale jego przestawienie przez NTP nie powinno zawieszać timerów sesji.

### B-06. Kontrakt błędów nie jest zamknięty

W sekcji walidacji występuje `ERR_MISSING_FIELD`, którego nie ma w tabeli kodów. Ponadto `ERR_INVALID_JSON` oznacza jednocześnie niepoprawny JSON i brak wymaganych pól.

Brakuje jednoznacznej decyzji dla:

- poprawnego JSON-a z brakującym polem;
- poprawnego JSON-a z nieznanym polem;
- `null` zamiast stringa;
- liczby poza zakresem `int64`;
- złej wartości `action`;
- `key` podanego dla `LIST`;
- `key` pominiętego dla `GET`;
- `value` podanego dla `GET`;
- pustego payloadu dla typu wymagającego JSON;
- duplikatów kluczy w obiekcie JSON;
- niepoprawnego UTF-8;
- odpowiedzi większej niż limit;
- poprawnego nagłówka, ale złego kierunku komunikatu.

Należy:

1. rozdzielić błędy framingu, UTF-8/JSON, schematu, stanu, autoryzacji i logiki biznesowej;
2. dopisać wszystkie kody do jednej tabeli;
3. określić, czy nieznane pola są odrzucane, czy ignorowane;
4. zastąpić „TAK (Albo ostrzeżenie)” jedną, deterministyczną decyzją;
5. opisać kolejność walidacji;
6. określić, kiedy `ERROR` jest wysyłany, a kiedy połączenie jest zamykane bez odpowiedzi.

Przykładowy podział:

- `ERR_INVALID_JSON` — tylko niepoprawne UTF-8 albo JSON;
- `ERR_INVALID_PAYLOAD` — poprawny JSON, ale zły schemat/typ/pole;
- `ERR_INVALID_ACTION` — nieznana lub niedozwolona kombinacja akcji i pól;
- `ERR_INVALID_HMAC` — zawsze zamknięcie sesji;
- `ERR_REPLAY_DETECTED` — jednoznacznie zdefiniowane dla starego ID/timestampu;
- `ERR_DUPLICATE_MSG` — wyłącznie dla tego samego ID i tego samego digestu żądania.

### B-07. Przykładowe długości payloadów są błędne

`Payload Length` musi oznaczać liczbę bajtów dokładnie wysłanego payloadu UTF-8. Dla pokazanych zwartych JSON-ów ASCII wartości powinny wynosić:

- Etap 1, sekcja 3.4, `DATA_REQ GET`: `187`, nie `189`;
- Etap 1, sekcja 7, `HELLO`: `56`, nie `58`;
- `HELLO_ACK`: `95`, nie `98`;
- `AUTH`: `110`, nie `106`;
- `AUTH_ACK`: `135`, nie `126`;
- `DATA_REQ SET`: `218`, nie `216`;
- `DATA_RESP SET`: `76`, nie `78`;
- `DATA_REQ GET`: `190`, nie `188`;
- `DATA_RESP GET`: `104`, nie `106`;
- scenariusz 2A, `DATA_REQ`: `72`, nie `82`;
- scenariusz 2A, `ERROR`: około `150` dla zwartego JSON-a, nie `128`;
- scenariusz 2B, `ERROR`: `144` dla podanego tekstu, nie `119`;
- scenariusz 2C, `ERROR`: `155` dla podanego tekstu, nie `122`.

Jeżeli intencją jest przesyłanie formatowanego JSON-a z białymi znakami, należy liczyć bajty tej dokładnej wersji, a nie wersji zwartej. Najlepsza poprawka to:

- usunąć ręcznie wpisane długości z przykładów do czasu ich wygenerowania;
- albo wygenerować całe przykłady z jednego serializatora;
- dodać test, który serializuje payload, liczy `Encoding.UTF8.GetByteCount` i sprawdza wartość w nagłówku.

Błędna długość nie jest kosmetyką — odbiorca odczyta za mało albo za dużo bajtów i straci synchronizację strumienia.

Dodatkowo przykład `serverNonce` `4F8A9C12E3B07165` ma 16 znaków HEX, czyli 8 bajtów. Jeżeli nonce ma mieć 16 bajtów, powinien mieć 32 znaki HEX.

## Problemy wysokiego priorytetu

### W-01. Równoczesne zapisy do `SslStream`

Etap 2 przewiduje jednocześnie `CliCommandLoop` i `KeepAliveWorker`. Oba komponenty mogą próbować pisać do tego samego `SslStream`. Bez serializacji całe ramki mogą zostać przeplecione:

```text
header(PING) + część header(DATA_REQ) + payload(PING) + reszta DATA_REQ
```

Należy zastosować jeden writer na połączenie, na przykład kolejkę `Channel<Frame>` albo `SemaphoreSlim` obejmujący cały zapis ramki, a nie tylko pojedyncze wywołanie `WriteAsync`.

Najprostszy wariant MVP:

- jeden reader odbiera ramki;
- jeden writer wysyła ramki;
- klient ma maksymalnie jedno oczekujące żądanie biznesowe;
- worker keep-alive korzysta z tej samej kolejki;
- odpowiedzi są dopasowywane po `Message ID`.

Jeżeli mają istnieć równoległe żądania, potrzebny jest dispatcher odpowiedzi i mapowanie `Message ID -> TaskCompletionSource`.

### W-02. `ConcurrentDictionary` nie zapewnia atomowej persystencji

`ConcurrentDictionary` chroni pojedyncze operacje w pamięci, ale nie gwarantuje spójnego snapshotu z późniejszym zapisem do pliku. Przykładowy wyścig:

1. sesja A modyfikuje słownik i tworzy snapshot A;
2. sesja B modyfikuje słownik i tworzy snapshot B;
3. snapshot A zostaje zapisany po snapshotcie B;
4. na dysku ląduje starszy stan.

Dodatkowo aktualizacja pamięci przed nieudanym zapisem pliku powoduje rozbieżność między pamięcią i persystencją.

Należy zdefiniować jednego właściciela operacji mutujących albo wspólną blokadę obejmującą:

1. zmianę modelu;
2. utworzenie snapshotu;
3. zapis pliku tymczasowego;
4. flush;
5. atomową podmianę;
6. dopiero wtedy potwierdzenie operacji klientowi.

Trzeba również opisać:

- co dzieje się po błędzie zapisu;
- czy pamięć jest wycofywana;
- jak odzyskiwany jest plik `.tmp`;
- co dzieje się przy uszkodzonym `vault_store.json`;
- czy kolejność kluczy jest stabilna;
- gdzie znajduje się plik względem katalogu procesu.

`File.Move(..., overwrite: true)` samo w sobie nie jest pełną gwarancją trwałości po awarii zasilania. Jeżeli atomowość i trwałość są wymaganiem, należy użyć odpowiedniego flushowania pliku i opisać ograniczenia systemu plików.

### W-03. Sekrety są przechowywane jawnie na dysku

Opis aplikacji mówi o bezpiecznym menedżerze sekretów, ale `data/vault_store.json` zawiera wartości wprost. TLS chroni transmisję, lecz nie chroni przed:

- odczytem pliku przez innego użytkownika systemu;
- kopią zapasową;
- przypadkowym dodaniem pliku do repozytorium;
- wyciekiem w obrazie kontenera;
- odczytem po przejęciu serwera.

Należy wybrać i udokumentować zakres:

1. **Zabezpieczony MVP:** szyfrowanie pliku AEAD, np. AES-GCM, unikalny nonce dla zapisu, klucz dostarczany spoza repozytorium, uprawnienia pliku `0600`.
2. **Świadome ograniczenie:** jawny plik pozostaje poza zakresem zagrożeń, a dokumentacja mówi wprost, że projekt chroni transport i autoryzację, ale nie kompromitację hosta. W takim przypadku nie należy sugerować pełnej ochrony sekretów at rest.

Nie wolno przechowywać klucza szyfrującego obok pliku danych ani w repozytorium.

### W-04. TLS jest opisany zbyt kategorycznie

Dokument stwierdza, że cały ruch używa `AES-256-GCM`. TLS 1.3 negocjuje cipher suite; zależnie od systemu/OpenSSL może zostać wybrany AES-128-GCM albo ChaCha20-Poly1305. Samo ustawienie TLS 1.3 nie gwarantuje AES-256-GCM.

Lepsze sformułowanie:

- wymagany jest TLS 1.3;
- używany cipher suite jest negocjowany przez bibliotekę i musi być zgodny z polityką środowiska;
- implementacja loguje nazwę cipher suite bez ujawniania sekretów;
- test sprawdza, że nie jest możliwy fallback do TLS 1.2 lub niższego.

Jeżeli wymagany jest konkretny cipher suite, trzeba sprawdzić, czy `.NET 8` i OpenSSL w docelowym środowisku pozwalają go wymusić, oraz dodać test.

Brakuje też wymagań dla certyfikatu:

- SAN zawierający nazwę hosta albo adres IP używany przez klienta;
- EKU `serverAuth`;
- data ważności;
- minimalny algorytm/rozmiar klucza;
- ochrona `server.key` i uprawnienia pliku;
- brak callbacka akceptującego dowolny certyfikat;
- obsługa błędów certyfikatu bez przejścia do protokołu PVSP.

`ca.crt` w `CustomRootTrust` rozwiązuje zaufanie do własnego CA, ale nie zastępuje walidacji nazwy hosta. Należy dopisać to do README i testu certyfikatu.

### W-05. Uwierzytelnianie eksponuje hasła

W przykładach i use case pojawia się:

```text
login admin SecretAdminPassword!
```

To może ujawnić hasło w historii shell-a, logach terminala albo argumentach procesu. Auto-reconnect dodatkowo wymaga przechowywania poświadczeń w pamięci.

Zalecenie:

- `login admin`, a następnie ukryty prompt hasła;
- nie logować komendy ani argumentów;
- nie umieszczać hasła w przykładach jako realnie wyglądającego sekretu;
- hasła po stronie serwera przechowywać jako hash z solą, np. Argon2id, bcrypt albo odpowiednio skonfigurowany PBKDF2;
- dodać limit prób per konto i adres/IP, nie tylko per połączenie;
- zdefiniować, czy połączenie po reconnect wymaga ponownego promptu, czy klient tymczasowo przechowuje sekret w pamięci;
- nie zapisywać poświadczeń do pliku konfiguracyjnego.

`clientNonce` jest nazwą mylącą, ponieważ w aktualnym protokole klient kopiuje `serverNonce`, a nie generuje własny nonce. Należy zmienić nazwę na `serverNonceEcho` albo rzeczywiście dodać nonce generowany przez klienta i opisać, jak jest używany.

Serwer powinien oznaczać nonce jako jednorazowy i wiązać go z konkretnym połączeniem. Należy również określić TTL sesji, sposób unieważniania `sessionToken` oraz to, czy token jest tylko identyfikatorem lookupu, czy ma własną entropię kryptograficzną.

### W-06. Ochrona przed DoS i brute force jest tylko per sesja

Rate limit `20 żądań / 10 s` działa na sesję, a trzy próby `AUTH` są liczone na połączenie. Atakujący może otwierać wiele nowych połączeń i za każdym razem wykonywać trzy próby.

Należy rozważyć:

- limit połączeń równoległych;
- limit trwających handshake’ów TLS;
- timeout handshake’u TLS;
- limit połączeń przed uwierzytelnieniem;
- rate limit per IP i per konto;
- backoff po kolejnych nieudanych logowaniach;
- limit rozmiaru i liczby oczekujących operacji;
- limit liczby kluczy i całkowitego rozmiaru magazynu;
- limit wielkości logów i rotację.

Należy wybrać konkretny model rate limitera. Sformułowanie „Sliding Window / Token Bucket” oznacza dwa różne algorytmy, nie jedną implementację.

### W-07. Limit odpowiedzi i `LIST`

Limit 64 KiB dotyczy wszystkich payloadów, a `LIST` zwraca tablicę dowolnej liczby kluczy. Przy większym magazynie odpowiedź może przekroczyć limit.

Trzeba dodać jedną z możliwości:

- limit liczby kluczy i jawny błąd `ERR_RESPONSE_TOO_LARGE`;
- paginację `LIST` przez `limit`, `cursor`, `nextCursor`;
- osobny limit liczby i długości nazw kluczy.

Limity wartości i kluczy muszą być liczone w bajtach UTF-8 po serializacji, a nie tylko w liczbie znaków. Wartość 32 768 znaków może zajmować więcej niż 32 KiB.

### W-08. HMAC nie pokrywa wszystkich ramek mimo deklaracji

W celu protokołu i opisie bezpieczeństwa pojawia się stwierdzenie o integralności każdej ramki, ale HMAC jest wymagany tylko dla `DATA_REQ`. `HELLO`, `AUTH`, `PING`, `PONG`, `BYE` i odpowiedzi nie mają HMAC.

TLS zapewnia integralność wszystkich danych w aktywnym kanale, więc dodatkowy HMAC na samych żądaniach może być uzasadniony jako dodatkowe uwierzytelnienie aplikacyjne. Dokument powinien jednak zmienić sformułowanie na:

> TLS chroni cały kanał; HMAC dodatkowo uwierzytelnia żądania operacji na magazynie.

Jeżeli zamiarem jest rzeczywiście podpisywanie każdej ramki PVSP, należy rozszerzyć format wszystkich typów. W przeciwnym razie aktualna deklaracja jest niezgodna z implementacją.

### W-09. Kolejność sprawdzania sesji, ID, HMAC i RBAC

Dokument wymienia wiele kontroli, ale nie definiuje ich kolejności. Jest to ważne zarówno dla bezpieczeństwa, jak i dla przewidywalnych kodów błędów.

Przykładowa kolejność dla `DATA_REQ`:

1. odebranie całej ramki i limit rozmiaru;
2. dekodowanie UTF-8 i JSON;
3. walidacja schematu i limitów pól;
4. sprawdzenie stanu sesji;
5. sprawdzenie `Message ID` i timestampu;
6. odtworzenie kanonicznych bajtów HMAC;
7. porównanie HMAC;
8. lookup sesji/tokena;
9. sprawdzenie RBAC;
10. rate limit;
11. operacja biznesowa.

Można wybrać inną kolejność, ale musi być stała i opisana. W szczególności nie należy używać danych z niepoprawnego payloadu do logowania ani zwracać różnych informacji, które ułatwiają enumerację kont.

## Niespójności między Etapem 1 i Etapem 2

### N-01. `DATA_RESP` ma wymagane pola, których część opisów nie pokazuje

Etap 1 wymaga dla `DATA_RESP` pól `status`, `action` i `timestamp`, natomiast Etap 2 w opisach `GET`, `LIST` i tabeli mapowania mówi skrótowo o `value` albo `keys`.

Należy dodać pełne schematy odpowiedzi:

- `SET`: `status`, `action`, `key`, `timestamp`;
- `GET`: `status`, `action`, `key`, `value`, `timestamp`;
- `LIST`: `status`, `action`, `keys`, `timestamp`;
- `DELETE`: `status`, `action`, `key`, `timestamp`.

Trzeba też określić, czy `key` jest wymagany dla odpowiedzi `DELETE`, czy tylko opcjonalny.

### N-02. `LastProcessedMessageId` i `LastMessageId`

W różnych miejscach używane są różne nazwy. Należy ustalić jeden model, najlepiej:

- `lastAcceptedMessageId`;
- `requestDigestByMessageId`;
- `responseByMessageId`.

Sam jeden `LastMessageId` nie obsłuży równoległych żądań ani starszych duplikatów.

### N-03. Duplikat, replay i zmieniony payload

Obecnie:

- `Message ID < LastProcessedMessageId` oznacza replay;
- `Message ID == LastProcessedMessageId` oznacza duplicate;
- tabela błędów mówi o zwróceniu ostatniego wyniku;
- nie ma wymagania, by payload duplikatu był identyczny.

Dla tego samego ID trzeba porównać digest całego żądania. Jeśli digest jest inny, należy zwrócić błąd protokołu i nie wykonywać operacji. Nie wolno zwracać cache’owanej odpowiedzi tylko na podstawie samego ID.

Należy też ustalić, czy ID muszą być kolejne (`last + 1`), czy tylko rosnące (`id > last`). Wybrana reguła musi obowiązywać w klientach i testach.

### N-04. Kategorie kodów błędów

Sekcja 6.1 mówi o kategoriach 1xx–4xx, ale zawiera kod `500`. To nie musi być błędem technicznym, ale opis kategorii jest niezgodny z tabelą. Należy albo:

- zmienić opis kategorii na „kody grupowane tematycznie”;
- albo przenieść błędy do spójnego zakresu.

Nie należy zmieniać kodów bez potrzeby, jeżeli są już użyte w scenariuszach; ważniejsza jest jednoznaczność i kompletność.

### N-05. Timeout handshake’u

Etap 1 opisuje osobne 10 i 15 sekund, a Etap 2 traktuje 15 sekund jako czas na cały handshake `HELLO` + `AUTH`. Oba dokumenty muszą używać tej samej definicji deadline’u.

### N-06. Wymóg 50 sesji a test 20 klientów

Etap 2 deklaruje minimum 50 jednoczesnych sesji, natomiast test T-10 sprawdza 20 klientów. Test powinien sprawdzać co najmniej 50 klientów albo wymaganie należy obniżyć do 20. W przeciwnym razie Definition of Done nie dowodzi własnego wymagania niefunkcjonalnego.

### N-07. „Przezroczysty” reconnect

Dokument opisuje reconnect jako przezroczysty, ale T-09 sprawdza go dopiero przy kolejnej komendzie użytkownika. Należy wybrać:

- reconnect reaktywny, uruchamiany przy kolejnym żądaniu;
- reconnect w tle;
- albo reconnect po błędzie aktualnego żądania.

Trzeba też określić, co użytkownik widzi w konsoli i jak zachowuje się `KeepAliveWorker` w trakcie reconnectu.

## Braki w architekturze aplikacji

### A-01. Brak projektu kont użytkowników

Opis wskazuje `admin` i `reader`, ale nie określa:

- gdzie przechowywane są konta;
- jak przechowywane są hashe haseł;
- jak przyznawane są role;
- jak tworzony jest pierwszy administrator;
- czy konta są stałe, czy konfigurowalne;
- co dzieje się przy braku pliku użytkowników;
- jak zapobiec uruchomieniu serwera z domyślnym znanym hasłem.

Należy dodać `UserRepository`/konfigurację albo jasno oznaczyć listę kont jako stałą demonstracyjną i opisać, że jest to ograniczenie projektu.

### A-02. Brak osobnego modelu stanu persystencji

`VaultStorageEngine` powinien mieć jawnie zdefiniowane rezultaty:

- `Committed`;
- `NotFound`;
- `InvalidKey`;
- `PersistenceFailed`;
- `StorageUnavailable`.

Nie wolno zwracać `DATA_RESP OK`, jeżeli zmiana jest tylko w pamięci, a zapis pliku się nie udał.

### A-03. Brak polityki dla wrażliwych nazw kluczy

Wartość sekretu nie jest logowana, ale przykładowe logi zawierają `Key=STRIPE_API_KEY`. Sama nazwa klucza może ujawniać informacje. Należy określić, czy nazwy kluczy:

- są logowane w całości;
- są maskowane;
- są hashowane ze stabilnym digestem;
- podlegają osobnej polityce audytu.

Logowanie musi również zabezpieczać przed log injection przez znaki nowej linii w danych wejściowych.

### A-04. CLI nie obsługuje bezpiecznie wartości opisanych w protokole

Protokół dopuszcza wartości ze spacjami, znakami nowej linii i danymi Base64, ale komenda `set <key> <val>` nie określa quoting/escaping. Wartość zawierająca spacje zostanie rozbita na argumenty, a wartość zawierająca nową linię jest jeszcze bardziej problematyczna.

Należy zdefiniować:

- parser z quotingiem i escapingiem;
- komendę odczytującą wartość ze stdin;
- albo tryb `set <key>` z ukrytym promptem;
- zachowanie dla EOF, pustej wartości i zbyt długiej wartości.

Wartości sekretów nie powinny trafiać do historii shell-a.

### A-05. Komendy diagnostyczne nie powinny być domyślną funkcją produkcyjnego klienta

`raw-corrupt` i `raw-replay` są przydatne na prezentacji, ale umożliwiają celowe wysyłanie uszkodzonych ramek. Należy:

- umieścić je w osobnym test harnessie albo trybie `--diagnostics`;
- jasno ostrzec, że mogą zamknąć sesję;
- nie udostępniać ich bezpośrednio w normalnym trybie;
- dodać testy automatyczne, które nie wymagają interaktywnego CLI.

## Review bezpieczeństwa

### S-01. TLS i aplikacyjne HMAC mają różne role

TLS chroni poufność i integralność kanału, a HMAC może dodatkowo potwierdzać, że `DATA_REQ` został utworzony przez klienta posiadającego klucz sesyjny. Dokument powinien unikać sugerowania, że HMAC naprawia błędną konfigurację TLS albo zastępuje weryfikację certyfikatu.

### S-02. HMAC nie zastępuje bezpiecznego przechowywania haseł

`hmacSecret` jest kluczem sesyjnym, nie hashem hasła. Hasła użytkowników powinny być weryfikowane względem bezpiecznego hasha z solą. Nie wolno przechowywać ich w plaintext ani logować.

### S-03. Brak limitu długości pól po stronie serwera

Limity opisane w sekcji 6.5 muszą być egzekwowane po stronie serwera niezależnie od walidacji CLI. Należy określić limity także dla:

- `clientName`;
- `serverVersion`;
- `username`;
- `password`;
- `sessionToken`;
- `serverNonce`;
- `hmac`;
- `errorName`;
- `message`;
- liczby elementów `keys`;
- całkowitej liczby wpisów magazynu.

### S-04. Informacje w błędach i timing

Komunikaty typu „konto nie istnieje” i „hasło niepoprawne” mogą umożliwić enumerację użytkowników. Zalecany jest jeden komunikat zewnętrzny `ERR_AUTH_FAILED`, przy zachowaniu szczegółów wyłącznie w bezpiecznym, zredagowanym audycie.

Należy również unikać ujawniania, czy klucz istnieje, jeżeli taka informacja jest w danym modelu zagrożeń wrażliwa.

### S-05. Token sesyjny i klucz HMAC

Trzeba dopisać:

- źródło entropii;
- minimalny rozmiar;
- format i dekodowanie;
- czas życia;
- unieważnianie po `BYE`, timeoutcie, błędzie HMAC i restarcie;
- wiązanie z użytkownikiem i połączeniem;
- zakaz logowania i zapisu do pliku.

UUID powinien być losowym UUID v4 z CSPRNG albo tokenem o jawnie określonej entropii. Sam napis „GUID” nie jest wystarczającą specyfikacją bezpieczeństwa.

## Review planu testów

Obecna macierz T-01–T-10 jest dobrym szkieletem, ale nie dowodzi jeszcze wszystkich krytycznych własności. Należy dodać co najmniej:

- test dokładnych długości payloadów UTF-8, w tym znaków wielobajtowych;
- test `ReadExactly` dla fragmentacji nagłówka i payloadu;
- test pustego payloadu oraz payloadu większego niż 64 KiB bez alokowania deklarowanego rozmiaru;
- test niepoprawnego UTF-8, JSON-a, typu pola, brakującego pola i nieznanego pola;
- test `Message ID` równego, mniejszego, większego i z luką;
- test tego samego ID z innym payloadem;
- test przekroczenia `uint32`;
- test PING wysłanego w trakcie oczekiwania na odpowiedź;
- test korelacji odpowiedzi przy dwóch równoległych żądaniach, jeżeli równoległość zostanie dopuszczona;
- test utraty odpowiedzi po wykonaniu `SET`/`DELETE`;
- test reconnectu i wyraźnej polityki retry;
- test dwóch równoległych zapisów do magazynu;
- test nieudanego zapisu pliku i zgodności stanu RAM z dyskiem;
- test startu z pustym, brakującym i uszkodzonym plikiem magazynu;
- test uprawnień pliku i szyfrowania at rest, jeśli zostanie wybrane;
- test braku sekretów, haseł, tokenów, nonce i surowych payloadów w logach;
- test certyfikatu z poprawnym CA, ale błędną nazwą/SAN;
- test wymuszenia TLS 1.3 i braku fallbacku;
- test IPv4 oraz IPv6;
- test limitu minimum 50 sesji, a nie tylko 20;
- test limitu nieudanych logowań z wielu nowych połączeń;
- test odpowiedzi `LIST` przekraczającej limit payloadu.

### Uwagi do obecnych testów

- **T-05:** warto sprawdzić zarówno kod `ERROR`, jak i gwarancję zamknięcia po wysłaniu odpowiedzi.
- **T-06:** trzeba zdefiniować, czy stary timestamp i stare ID dają ten sam kod oraz czy serwer zamyka połączenie w obu przypadkach.
- **T-07:** wysyłanie co 3 bajty z opóźnieniem 50 ms powinno używać payloadu o określonym rozmiarze, aby nie przekroczyć innych timeoutów przypadkiem.
- **T-08:** należy opisać, jak serwer tworzy `ERROR`, gdy nie ufa `Magic Bytes` albo wersji. Jeśli nie da się bezpiecznie skorelować odpowiedzi, dopuszczalne może być zamknięcie bez ramki PVSP.
- **T-09:** trzeba określić, czy retry dotyczy tylko następnej komendy, czy bieżącego żądania.
- **T-10:** deklarowane `<15 ms` wymaga metodologii: warm-up, liczba próbek, p50/p95/p99, zakres pomiaru, obciążenie, loopback vs sieć oraz wyłączenie kosztu pierwszego TLS handshake’u.

## Uwagi formalne względem regulaminu

Regulamin wymaga dla Etapu 1 i Etapu 2 dokumentu w formacie PDF. Pliki Markdown mogą być źródłem dokumentacji i review, ale przed oddaniem należy:

- wygenerować finalny PDF;
- sprawdzić renderowanie diagramów Mermaid i tabel;
- upewnić się, że przykłady kodu nie są łamane przez eksport;
- dołączyć spójną wersję dokumentu, a nie wersję Etapu 1 i Etapu 2 z różnymi kontraktami;
- pamiętać, że każdy członek zespołu musi wysłać wymagane materiały na Deltę.

Zakres merytoryczny obecnych plików odpowiada sekcjom z regulaminu, ale niespójności obniżają ocenę za kompletność, formalizację oraz zgodność projektu z protokołem.

## Zalecana kolejność poprawek

1. Ustalić ograniczony kontrakt MVP: kierunki, stany, ID, równoległość, `BYE`, `PING/PONG`.
2. Ustalić schematy JSON, reguły nieznanych pól, limity i pełny katalog błędów.
3. Zdefiniować kanoniczne wejście HMAC, kodowanie kluczy oraz wektory testowe.
4. Wybrać politykę retry mutacji: brak automatycznego retry albo `operationId` z deduplikacją.
5. Ujednolicić timeouty, zachowanie po każdym błędzie i zasady zamykania.
6. Wygenerować wszystkie przykładowe ramki automatycznie i poprawić `Payload Length`.
7. Zaprojektować pojedynczy writer/read-dispatcher dla każdego połączenia.
8. Zaprojektować transakcyjną persystencję oraz decyzję o szyfrowaniu danych at rest.
9. Doprecyzować TLS, certyfikaty, hasła, tokeny, limity połączeń i logowanie.
10. Zaktualizować use case’y, mapowanie i testy tak, aby dokładnie odzwierciedlały zamknięty protokół.
11. Dopiero potem implementować `Pus.Vault.Common`, zaczynając od testów kodeka i HMAC.
12. Na końcu wygenerować PDF-y i README z wymaganiami środowiskowymi oraz znanymi ograniczeniami.

## Minimalne kryteria gotowości do rozpoczęcia kodowania

Implementację można rozpocząć dopiero, gdy dokumentacja odpowiada jednoznacznie na wszystkie pytania:

- Jaki komunikat może wysłać każda strona w każdym stanie?
- Kto nadaje `Message ID` i jaki jest jego zakres?
- Czy dozwolone są równoległe żądania?
- Jak rozpoznać prawdziwy duplikat?
- Jakie dokładnie bajty są podpisywane HMAC?
- Jakie są reprezentacje `null`, brakujących pól, liczb i Unicode?
- Co dzieje się po utracie odpowiedzi po `SET` albo `DELETE`?
- Kiedy timeout zamyka sesję?
- Kiedy serwer odpowiada `ERROR`, a kiedy zamyka połączenie bez odpowiedzi?
- Jakie pola i wartości są logowane, a jakie zawsze redagowane?
- Czy dane magazynu są chronione na dysku?
- Jak działa persystencja przy dwóch równoległych modyfikacjach?
- Jak odpowiedź `LIST` mieści się w limicie 64 KiB?
- Jak zweryfikować certyfikat serwera dla nazwy i adresu IP?

Po zamknięciu tych punktów projekt będzie miał spójny, testowalny fundament zarówno dla Etapu 3, jak i dla prezentacji oraz pytań kontrolnych.
