# Security Hub

Monitoraggio della **security posture** su più aree (e-mail, DNS, Proofpoint, WAF, EDR, identità SAP, accessi privilegiati, Zero Trust), con un unico comando e un unico portale:

| Area | Modulo | Cosa valuta | Sorgente dati |
|------|--------|-------------|---------------|
| **WAF** | `securityhub waf` (WAFGuard) | Configurazione Imperva Cloud WAF: onboarding, regole OWASP in blocco, eccezioni, allow-list, bot, DDoS (soglia confrontata con il traffico reale, salvo soglia adattiva), TLS, esposizione dell'origin | API Imperva (sola lettura) o snapshot JSON |
| **E-mail** | `securityhub email` (MailGuard) | MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, report DMARC aggregati (BIMI solo su richiesta: `--checks all,bimi`) | DNS live (+ HTTPS per MTA-STS) |
| **DNS** | `securityhub dns` (MailGuard) | DNSSEC, CAA, takeover delle dipendenze, scadenza registrazioni, zone transfer (AXFR, opt-in), coerenza resolver, lookalike | DNS live (+ RDAP) |
| **Proofpoint** | `securityhub proofpoint` (PPGuard) | Posta che passa davvero da Proofpoint (MX, MX di bypass, consegna diretta a Microsoft 365, SPF) e, da TAP, minacce consegnate, click malevoli permessi, URL Defense, Very Attacked People e top clicker | DNS pubblico + API TAP (sola lettura) o snapshot JSON |
| **EDR** | `securityhub edr` (EDRGuard) | SentinelOne: salute e versione degli agent, Protect vs Detect, anti-tamper, motori, snapshot, minacce aperte e SLA, esclusioni rischiose, copertura rispetto all'inventario | API SentinelOne v2.1 (sola lettura) o snapshot JSON |
| **Identità SAP** | `securityhub sap-ias` (IASGuard) | SAP Cloud Identity Services: utenti con password IAS locale invece dell'IdP aziendale, privilegiati con password, MFA, igiene password, account inattivi, scaduti o con e-mail condivisa | SCIM 2.0 (sola lettura) o snapshot JSON |
| **Accessi privilegiati** | `securityhub pra` (PRAGuard) | BeyondTrust PRA: MFA di utenti, amministratori e fornitori, scadenza delle utenze fornitori, asset senza policy o registrazione, Telnet e certificati RDP non verificati, gateway, account API senza restrizione di rete o con permessi di scrittura, rotazione e checkout del vault, sessioni non registrate | Configuration API (solo GET) e Reporting API |
| **Zero Trust** | `securityhub zta` (ZTAGuard) | Risultati del Microsoft Zero Trust Assessment per pilastro, priorità, quick win | `ZeroTrustAssessmentReport.json` |
| **Portale** | `securityhub portal` (GuardHub) | Un solo file HTML con stato per area, KPI, piano d'azione trasversale, **vista per asset**, trend storici e i report navigabili | Report HTML generati dai moduli |

Il comando **`securityhub run`** esegue tutti i moduli abilitati da un file di configurazione, confronta ogni
modulo con l'esecuzione precedente, aggiorna il portale e scrive `posture.json`, un riepilogo machine-readable
pensato per monitoraggio, SIEM e gate di CI.

Tutti i report sono file HTML autocontenuti: funzionano offline e non inviano dati da nessuna parte.

## Installazione

Richiede Python 3.9+.

```bash
pip install .            # dipendenza: dnspython
pip install ".[full]"    # + PyYAML (config YAML), idna, defusedxml, tldextract (consigliato)
```

## Avvio rapido

```bash
securityhub init                     # crea securityhub.yaml di esempio
# modifica securityhub.yaml (domini, account Imperva, cartella Zero Trust)
export IMPERVA_API_ID=12345 IMPERVA_API_KEY=xxxxxxxx
securityhub run                      # esegue i moduli, aggiorna portale e posture.json
securityhub status reports           # stampa la posture corrente
securityhub doctor                   # verifica credenziali, API e input di ogni modulo (una lettura per modulo)
```

Output di `securityhub run`:

```
reports/
  runs/2026-10-31T080000Z/   dati di ogni modulo: <modulo>.report.json, .json, .csv, .log (nessuna pagina HTML)
  runs/2026-11-07T080000Z/   ...
  security_hub.html          <- portale: ultima esecuzione navigabile, le precedenti diventano trend dei KPI
  posture.json               <- riepilogo per monitoraggio / SIEM / CI
```

Esempio di output a console (su un terminale l'avanzamento si aggiorna sul posto, con colori e link cliccabili;
nei log di cron/CI è testo semplice, una riga per evento):

```
Security Hub run 2026-10-31T104144Z  ·  3 modules, up to 3 in parallel  ·  reports/runs/2026-10-31T104144Z
  ✔ Microsoft Zero Trust (ZTAGuard)          done                 0s
  ✔ Imperva Cloud WAF (WAFGuard)             done                 2s
  ✔ DNS / e-mail security (MailGuard DNS)    done                41s

SECURITY POSTURE   AT RISK   1 at risk · 2 need attention
▲ Incomplete picture - stale: Microsoft Zero Trust
────────────────────────────────────────────────────────────────────────
1 of 3 areas at risk, 2 need attention. Largest exposure: 3 of 5 verified websites (60%) are not effectively protected by the WAF.

  Email and DNS security      C  67  Attention    2026-10-31, today
                             1 of 3 verified domains (33%) can be impersonated by email
                             · Domains protected against spoofing: 67%
  Imperva Cloud WAF           F  49  At risk      2026-10-31, today
                             3 of 5 verified websites (60%) are not effectively protected by the WAF
                             · Websites effectively protected by the WAF: 40%
  Microsoft Zero Trust        D  54  Attention    2026-10-01, 30 days old ▲ stale (limit 20 days)
                             1 high-risk Zero Trust controls are failing
                             · Zero Trust controls passed: 54/100

Assets  4 assets · 3 at risk · 1 coverage gap · 2 expiring
  ✖ contoso.example              legacy.contoso.example: WAF in bypass, traffic is not inspected
  ✖ fabrikam.example             www.fabrikam.example is not effectively protected by the WAF and fabrikam.example can be impersonated by e-mail (DMARC none)
  ✖ northwind.example            portal.northwind.example: certificate expired 669 days ago

Top actions
  critical Email and DNS security   Zone transfer (AXFR) allowed to anyone
  critical Imperva Cloud WAF        Core WAF rule set to Ignore / disabled
  critical Microsoft Zero Trust     Privileged accounts use phishing-resistant MFA
  critical Email and DNS security   Policy p=none - monitoring only, no protection

Portal   reports/security_hub.html
Summary  reports/posture.json
Logs     reports/runs/2026-10-31T104144Z
```

## Vista per asset

Nel portale, **Assets** (tasto `a`) riunisce per dominio organizzativo tutto ciò che i report sanno di un asset:
domini di posta (DMARC, SPF, MTA-STS, DNSSEC), siti protetti dal WAF (modalità, blocco attacchi, certificato),
scadenze di certificati e registrazioni, tenant Microsoft collegato. I siti si agganciano al dominio più specifico
presente nell'assessment DNS; quelli senza dominio corrispondente diventano un asset a sé.

Per ogni asset vengono calcolati **segnali trasversali**, visibili solo incrociando le aree:

| Segnale | Quando |
|---|---|
| Sito e posta esposti | il sito non è protetto efficacemente dal WAF **e** il dominio è impersonabile via e-mail (DMARC non in enforcement) |
| WAF in bypass / origin esposto / attacchi non bloccati | per ogni sito dell'asset |
| Takeover | una dipendenza DNS (include SPF, MX, NS, CNAME) è registrabile da terzi |
| Dominio impersonabile | DMARC `none` o assente (critico per i domini di tier critical/high) |
| Scadenze | certificato entro 30 giorni (critico entro 7) o scaduto; registrazione entro 60 giorni (critico entro 14) |
| Lacuna di copertura | il dominio ospita siti protetti dal WAF ma non è nell'assessment DNS / e-mail |
| Zone transfer aperto | un name server del dominio consegna l'intera zona a chiunque (controllo `axfr`) |
| Siti senza CAA | il dominio ospita siti ma non limita le CA che possono emettere certificati |
| Dati non verificati (info) | controlli non eseguiti o falliti: l'asset non risulta mai "on track" su dati parziali |

Filtri rapidi (a rischio, attenzione, lacune di copertura, in scadenza, non verificati), ricerca, colonne ordinabili,
paginazione (50 righe), scheda di dettaglio con link diretti
alle righe dei report, card "Assets needing attention" nella panoramica e ricerca globale (`Ctrl K`).
Lo stesso inventario è in `posture.json` (`assets.summary`, `assets.items`).

## Configurazione

Vedi [`examples/securityhub.example.yaml`](examples/securityhub.example.yaml) (generato anche da `securityhub init`).

```yaml
title: "Contoso - Security posture"
output_dir: reports
keep_runs: 12            # esecuzioni conservate per ogni modulo, per i trend (0 = tutte)
fail_under: 70           # opzionale: exit code 2 se un'area/asset scende sotto la soglia
auto_baseline: true      # ogni modulo viene confrontato con la sua esecuzione precedente

modules:
  dns:
    input: domains.csv
    options: { checks: "all,takeover", csv: true, dmarc_reports: [./rua] }
  waf:
    options: { account_id: 1234567, include_subaccounts: true, probe: true }
  zta:
    input: ./ZeroTrustReport
```

- **Elenco dei domini** (`modules.email.input` / `modules.dns.input`): basta una lista semplice, un dominio per riga (anche più domini per
  riga separati da virgola o spazio; `#` per i commenti), qualunque sia l'estensione del file. Le informazioni
  aggiuntive sono facoltative: CSV con intestazione (`domain`/`dominio` più, in qualsiasi ordine, `tier`, `owner`,
  `bu`, `tags`) oppure senza intestazione, per posizione: `dominio;tier;owner;bu;tag1|tag2`, lasciando vuoti i campi
  che non servono. Il tier (`critical`, `high`, `medium`, `low`; default `medium`) pesa sulle priorità.
- `options` accetta **le stesse opzioni della riga di comando** del modulo (`securityhub <modulo> --help`),
  con `_` o `-`: `true/false` per gli switch, liste per valori multipli. Le opzioni sconosciute sono un errore.
- I percorsi relativi sono risolti rispetto alla cartella del file di configurazione.
- `output` è gestito dall'hub; `--json` è sempre attivo perché l'export JSON fa da baseline per l'esecuzione successiva.
- **Le credenziali non vanno nel file**: `api_key` viene rifiutata. Usa `IMPERVA_API_ID` / `IMPERVA_API_KEY`
  oppure `api_key_file`.
- È accettato anche JSON (`securityhub run -c hub.json`), senza bisogno di PyYAML.

**Un solo modulo nel report complessivo:** `securityhub run pra` (o più moduli: `securityhub run pra waf`, equivalente a
`--only pra,waf`) esegue solo quei moduli con la configurazione, poi ricostruisce e pubblica il portale con i loro report
nuovi e gli ultimi report di tutte le altre aree. `keep_runs` vale per modulo, quindi lanciare spesso un solo modulo non
cancella gli ultimi report delle altre aree. Il comando diretto (`securityhub pra -o file.html`) produce invece un report
isolato, che il portale non vede.

Opzioni utili di `run`: `--only dns,zta`, `--dry-run` (mostra i comandi senza eseguirli), `-q` (solo la posture),
`-v` (mostra anche l'output dei moduli, con il prefisso `[dns]`, `[waf]`, `[zta]`), `-p N` (moduli in parallelo),
`--timeout SECONDI`, `-o` (cartella di output alternativa).

### Esecuzione parallela

Ogni modulo gira **in un processo separato**: un errore o un blocco in un modulo non coinvolge gli altri. I moduli
partono insieme (`max_parallel`, default: tutti; `1` = in sequenza) e l'output di ciascuno va in `runs/<data>/<modulo>.log`.
Con `module_timeout` (o `timeout` per singolo modulo) un modulo che supera il tempo viene fermato e segnalato.
Se un modulo fallisce, la console mostra le ultime righe del suo log.

## Un solo file HTML

Con `securityhub run` l'unico HTML prodotto è il **portale** (`security_hub.html`, pubblicato come `index.html`): contiene
tutte le aree (Email, DNS, WAF, Zero Trust) con i rispettivi report navigabili. Nelle cartelle delle esecuzioni ogni modulo
lascia solo dati (`<modulo>.report.json` più export JSON/CSV e log); il portale ricostruisce le pagine dei report da quei
dati con la grafica corrente (identiche a quelle che il modulo scriverebbe). Le esecuzioni precedenti che contengono ancora
pagine HTML vengono convertite automaticamente al primo `run`. I comandi singoli (`securityhub email|dns|waf|zta`) continuano a
scrivere il proprio report HTML.

## Report e-mail e report DNS

Quattro comandi, un report ciascuno: `securityhub email`, `securityhub dns`, `securityhub waf`, `securityhub zta`.
I report e-mail e DNS hanno ciascuno i propri controlli, finding, punteggio, correzioni suggerite, export JSON/CSV e area
nel portale:

| Report | Comando / modulo | Controlli | Punteggio |
|---|---|---|---|
| **Email security** | `securityhub email` | MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, report DMARC; requisiti Gmail/Yahoo e Microsoft; BIMI solo su richiesta | SPF 25, DKIM 25, DMARC 35, MTA-STS 7, TLS-RPT 3 (normalizzato a 100) |
| **DNS security** | `securityhub dns` | DNSSEC, CAA, takeover e scadenza registrazioni; opzionali: zone transfer (`axfr`), coerenza, lookalike | DNSSEC 30, CAA 25, takeover 30, zone transfer 15; i controlli non misurabili sono esclusi dal massimo |

Ciascun comando accetta solo i propri controlli (`securityhub email --checks caa` suggerisce `securityhub dns`).
`securityhub dns --combined` produce un unico report con tutti i controlli, come nelle versioni precedenti.

**Una sola scansione in `securityhub run`.** Nella configurazione `email` e `dns` sono due moduli; se usano lo stesso
`input` e non hanno opzioni in conflitto (es. resolver o timeout diversi), vengono valutati con **una sola scansione**
che produce entrambi i report: il controllo di takeover usa i dati di SPF, DKIM e DMARC e due scansioni
raddoppierebbero il traffico DNS. Una configurazione con il solo modulo `dns` (versioni precedenti) continua a produrre
entrambi i report. Il primo confronto con una baseline combinata (versione 3) confronta solo i finding, non i punteggi.

## Controlli DNS aggiuntivi

- **CAA** (attivo di default, peso 0 sul punteggio): verifica quali certificate authority possono emettere certificati
  per il dominio (RFC 8659, con risalita ai domini padre), la presenza di `iodef` e record malformati o con tag critici
  sconosciuti. Suggerisce i record da pubblicare (`0 issue ";"` per i domini che non servono certificati).
- **Zone transfer / AXFR** (opt-in: `--checks all,axfr`): chiede a ogni name server autoritativo una copia della zona.
  È un test attivo verso server di terzi: va abilitato consapevolmente. Viene letta solo la prima risposta, la zona non
  viene scaricata né salvata. Un server che la consegna genera il finding critico `AXFR_OPEN`.

## Tema chiaro / scuro

Portale e report hanno tre modalità, scelte dal selettore in fondo alla barra laterale (su mobile: icone a fine barra)
o dalla ricerca (`Ctrl K` → "Theme"):

- **System**, il default: segue il tema del sistema operativo e si aggiorna se cambia mentre la pagina è aperta;
- **Light** e **Dark**: fissi, indipendenti dal sistema.

La scelta è una sola per il portale e per tutti i report, viene ricordata dal browser, si propaga alle altre
schede aperte ed è applicata prima del primo rendering, senza flash. Nel portale i report incorporati seguono il
tema del portale. La stampa e il PDF executive usano sempre la versione chiara.

## Prestazioni e dispositivi piccoli (Raspberry Pi)

- **DKIM a due giri** (default): prima i selettori del provider di posta rilevato, quelli da report DMARC o
  `--selectors` e i più diffusi; se c'è una chiave valida la ricerca si ferma, altrimenti si provano tutti i
  selettori noti (quindi "DKIM non trovato" resta affidabile). Sui domini senza posta si cerca solo il primo giro
  (CNAME orfani). Su 900 domini: −56% di query DNS, stessi risultati. `full_dkim: true` per l'audit completo.
- **Record DKIM propri (`dkim.csv`)**: un file `dkim.csv` accanto alla lista domini (o `dkim_file:` nella
  configurazione, `--dkim-file` da riga di comando) elenca i record DKIM di ogni dominio come righe di zona DNS
  (`1m-mm._domainkey.uk.example.com.  1  IN  TXT  "v=DKIM1;k=rsa;p=..."`; accettati anche CNAME e `dominio;selettore`).
  Con il file presente si verificano in DNS solo quei record (più i selettori visti nei report DMARC), senza
  tentare selettori comuni; un dominio di posta non elencato risulta "non verificato" e non pesa sullo score.
  Il DKIM è valutato nel report email (non in quello DNS). Se un record non è pubblicato il report lo segnala
  (`DKIM_DECLARED_MISSING`); se `p=` contiene la chiave reale e quella pubblicata è diversa, `DKIM_KEY_MISMATCH`
  (nel report finisce solo un'impronta della chiave). Esempio in `examples/dkim.example.csv`; `--dkim-file none` lo ignora.
- **Query contemporanee limitate** (`max_inflight`, default 32) e limite al secondo opzionale (`qps`): il traffico
  resta gestibile anche per router domestici e tabelle NAT piccole.
- **Storico leggero**: per i trend il portale usa solo i KPI delle esecuzioni precedenti, i report completi sono caricati
  solo per l'ultima. Con 30 esecuzioni da 900 domini: picco di memoria da 722 MB a 65 MB.
- **Cache delle scoperte** (`~/.cache/securityhub/`, un file per modulo, permessi 0600): ciò che cambia lentamente
  si rifà al massimo una volta al giorno, la configurazione valutata si legge sempre a ogni run.
  - *DNS/email* (`cache_max_age`, default 24 ore): la ricerca completa dei selettori DKIM; nei run successivi si
    riprovano solo i selettori trovati, e per i domini senza DKIM basta una query su `_domainkey` (RFC 8020). Se una
    chiave sparisce, la ricerca completa riparte subito. Anche RDAP (solo i domini registrati: "non registrato",
    segnale di takeover, si verifica sempre), lookalike, coerenza tra name server, zone transfer e policy MTA-STS
    (per lo stesso `id`). Su 900 domini il secondo run passa da 25.936 a 10.456 query DNS (−60%), con risultati
    identici.
  - *Proofpoint*: le ore SIEM già consolidate si riusano per 12 ore (`siem_reuse_hours`), poi si rileggono per
    raccogliere i verdetti cambiati (minaccia ripulita, falso positivo); People API una volta al giorno. Con run ogni
    4 ore: 5 chiamate SIEM invece di 24.
  - *SentinelOne*: l'elenco delle versioni GA degli agent una volta al giorno.
  - `--no-cache` su ogni modulo per disattivarla.
- **Traffico di rete non sommato**: i moduli che generano molto traffico (scansione DNS/email, Proofpoint, sonde WAF)
  girano uno alla volta (`max_parallel_network`, default 1); quelli che fanno solo poche chiamate API restano in
  parallelo.
- **WAF: dati lenti in cache** (`~/.cache/securityhub/waf-<account>.json`): le statistiche di traffico (90 giorni,
  servono solo a tarare la soglia DDoS, e non si scaricano per i siti con soglia DDoS adattiva) e la parte pesante delle sonde (handshake TLS 1.0/1.1, connessioni dirette
  agli origin) si rifanno al massimo una volta ogni `traffic_max_age` / `probe_max_age` ore (default 24); la sonda
  si rifà subito se cambiano dominio o origin del sito. Configurazione, policy, instradamento DNS e HTTPS si leggono
  a ogni run. Con 4 run al giorno: download delle statistiche −75%, connessioni delle sonde circa −65%. Default più
  prudenti: 4 chiamate API in parallelo a max 5 al secondo, 4 siti sondati alla volta. `--no-cache` per disattivarla.
- **Servizio a bassa priorità** (`deploy/raspberry-pi/securityhub.service`): `Nice`, `CPUWeight`, I/O `idle` e
  `MemoryHigh`, così SSH e gli altri servizi restano reattivi durante la scansione.

## Pubblicazione su un web server

Con `publish` nella configurazione, al termine di ogni `run` il portale viene copiato come `index.html` nella cartella
del web server (scrittura atomica: chi apre la pagina non vede mai un file a metà):

```yaml
publish: /var/www/html/securityhub
# oppure: publish: {dir: /var/www/html/securityhub, posture: true, mode: "0640"}
```

Viene pubblicato **solo il portale** (e `posture.json` se `posture: true`): mai le cartelle delle esecuzioni, gli export
JSON/CSV o i log. La cartella deve esistere ed essere scrivibile dall'utente che esegue `run`. Il portale descrive i
punti deboli dell'organizzazione: va protetto con autenticazione e, se possibile, limitato alla rete di gestione.
In `deploy/raspberry-pi/` ci sono unità systemd (servizio + timer: 4 esecuzioni al giorno, verso le 6, 10, 14 e 18),
il controllo giornaliero delle credenziali (`securityhub-doctor.service` + `.timer`, verso le 05:40, prima della prima
esecuzione) e la configurazione nginx d'esempio.

## Monitoraggio continuo

`securityhub run` è pensato per girare a intervalli regolari. Gli exit code sono uguali per tutti i comandi:

| Code | Significato |
|------|-------------|
| 0 | OK |
| 1 | Errore di uso / input / API (anche se un solo modulo fallisce: gli altri vengono comunque eseguiti e il portale aggiornato) |
| 2 | Punteggio sotto `fail_under` (di un modulo o di un'area) |
| 3 | Solo `securityhub status --fail-stale`: i dati di un'area sono più vecchi del limite |
| 130 | Interrotto |

**cron** (ogni lunedì alle 07:40):

```cron
40 7 * * 1  cd /opt/securityhub && . ./.env && securityhub run -q >> run.log 2>&1
```

**Windows Task Scheduler**: esegui prima `Invoke-ZtAssessment` (modulo PowerShell `ZeroTrustAssessment`),
poi `securityhub run`, puntando `modules.zta.input` alla cartella del report.

**posture.json** (`"schema": 2`) contiene lo stato complessivo, lo stato per area (`good` / `warn` / `bad` /
`unknown`), età dei dati e flag `stale`, KPI (es. % domini protetti da spoofing, % siti realmente protetti dal WAF,
% sign-in con MFA), inventario asset, azioni prioritarie e l'esito di ogni modulo dell'ultima esecuzione: può essere
inviato a un SIEM o a una dashboard.

### Come leggere i numeri

- **Non verificato non vuol dire esposto.** Un controllo non eseguito (es. `--checks spf`) o fallito (resolver DNS
  irraggiungibile, errore API) rende il dato *non verificato*: è escluso dai KPI e dai titoli, segnalato a parte
  ("N not verified") e un'area senza dati verificati risulta `unknown`, mai "a rischio" né "on track".
- **Nessun voto medio fra aree.** I tre strumenti hanno scale diverse: lo stato complessivo (`overall.status`) è lo
  stato peggiore fra le aree verificate, con i conteggi per stato; `overall.complete` è `false` se un'area non è
  verificata o ha dati vecchi. *(Fino allo schema 1 c'era un `overall_score` medio: è stato rimosso.)*
- **Freschezza.** Ogni area ha un limite di età dei dati (default: DNS e WAF 2 giorni, Zero Trust 35), configurabile
  con `max_age_days` nella configurazione o `--max-age dns=1,zta=30`. Oltre il limite il portale mostra un avviso e
  `securityhub status --fail-stale` termina con codice 3: utile per Nagios/Zabbix o come "dead man's switch".
- **Esecuzioni sovrapposte.** Un lock sulla cartella di output impedisce due `run` contemporanei (il secondo termina
  con un errore che indica chi tiene il lock); portale e `posture.json` sono scritti in modo atomico.

## Proofpoint

`securityhub proofpoint` (alias `pp`, `tap`) valuta ogni **dominio di posta** su due fronti:

1. **Instradamento, dal DNS pubblico** (nessuna credenziale): la posta passa davvero da Proofpoint?
2. **Esposizione, dall'API TAP** (sola lettura): cosa è arrivato agli utenti e chi ha cliccato.

```bash
export PROOFPOINT_PRINCIPAL=...  PROOFPOINT_SECRET=...      # service principal TAP (oppure --secret-file)
export PROOFPOINT_TP_KEY=...  PROOFPOINT_TP_SECRET=...       # Threat Protection API key (report: Threat Response, URL rewrite, BEC, email bombing)
export PROOFPOINT_POD_CLUSTER=...  PROOFPOINT_POD_TOKEN=...   # PoD Log API (autenticazione mittenti, spoofing, TLS, audit console); token dedicato
securityhub proofpoint --domains domains.csv -o proofpoint.html --json --csv
securityhub proofpoint --domains domains.csv --no-tap       # solo controlli DNS, senza credenziali
securityhub proofpoint --save-raw pp.json                   # snapshot senza oggetti, corpi, IP dei click o URL malevoli
securityhub proofpoint --from-json pp.json --baseline prev.json
```

La lista domini è la stessa del modulo email (semplice elenco o CSV con tier/owner/bu/tags).

| Controllo | Peso | Cosa verifica |
|-----------|-----:|---------------|
| `routing` | 40 | Ogni MX è Proofpoint (per nome `*.pphosted.com`, per CNAME o per reverse DNS: riconosce anche MX con nome aziendale). MX alternativi = **bypass** (critico se preferito) |
| `direct` | 10 | L'endpoint Microsoft 365 del dominio (`dominio-tld.mail.protection.outlook.com`) risponde: chi lo conosce invia direttamente e salta Proofpoint, a meno che Exchange Online accetti solo dal connettore Proofpoint. Da fuori non si vede: è un *da verificare* |
| `spf` | 5 | SPF presente e, se la posta passa da Proofpoint, che lo autorizzi (anche tramite include annidati) |
| `threats` | 25 | Messaggi malevoli (malware, phish) **consegnati** nella finestra TAP; consegne tramite safelist/allow; impostor (BEC) |
| `clicks` | 20 | Click su URL malevoli **permessi**: utenti potenzialmente compromessi |
| `rewrite`, `people` | info | Messaggi con URL non riscritti da URL Defense; Very Attacked People (VIP segnalati) |

Profili: *Not routed via Proofpoint*, *MX bypass*, *Malicious click permitted*, *Threat delivered*, *Protected*.
La pagina **People and threats** riporta i totali della finestra (bloccati / consegnati / click), le minacce arrivate agli
utenti con il link al TAP dashboard, i Very Attacked People, i top clicker, i domini visti da TAP ma non in lista e
quelli senza MX (non valutati). Le minacce su domini che non passano da Proofpoint sono *non applicabili*, non
"pulite": TAP non le vede. Nel portale un click malevolo permesso rende l'area *At risk* e guida il piano d'azione.

Il service principal si crea in TAP > Settings > Connected Applications. La finestra `--hours` (default 24, max 168)
conviene sia pari all'intervallo tra due run; le chiamate SIEM sono una per ora (24 al giorno con il default).

## Identità SAP (Cloud Identity Services)

`securityhub sap-ias` (alias `ias`, modulo `ias` nella configurazione) legge utenti e gruppi del tenant IAS con le
API SCIM 2.0 **in sola lettura** e valuta ogni utente attivo.

```bash
export IAS_TENANT_URL=https://<tenant>.accounts.ondemand.com IAS_CLIENT_ID=... IAS_CLIENT_SECRET=...
securityhub sap-ias --privileged-groups "IAS Admins" --password-types partner -o ias.html --json --csv
securityhub sap-ias --save-raw ias.json      # snapshot senza telefoni, indirizzi o password
```

Credenziali: un'utenza tecnica dedicata con sole autorizzazioni di lettura (utenti e gruppi), con segreto
(`IAS_CLIENT_SECRET` o `secret_file`) o certificato client (`client_cert` / `client_key`); mai nel file di
configurazione (`client_secret` è rifiutato).

| Controllo | Peso | Cosa verifica |
|-----------|-----:|---------------|
| `signin` | 40 | L'utente può entrare con una **password IAS locale**, cioè senza l'IdP aziendale (e senza la sua MFA). Critico per i membri di `--privileged-groups`; atteso per i tipi in `--password-types` (es. fornitori), di cui si valuta solo l'igiene |
| `mfa` | 25 | Password locale senza secondo fattore, se il tenant espone l'informazione |
| `password` | 15 | Password più vecchia di `--password-max-days` (365), password iniziale mai cambiata, policy Standard invece di Enterprise, molti tentativi falliti |
| `activity` | 15 | Nessun accesso da `--inactive-days` (90) o mai usato, se il tenant espone l'ultimo accesso |
| `lifecycle` | 5 | Validità scaduta ma account ancora attivo |
| `email` | info | E-mail non verificata o condivisa da più account |

Un dato che il tenant non espone (ultimo accesso, MFA) rende il controllo *non verificato*, non fallito, e la
pagina **Directory** lo dichiara. Gli account disattivati sono contati ma non valutati. Sopra 5.000 utenti attivi
il report elenca solo quelli con rilievi, mentre i totali coprono tutti. Nel portale l'area è *At risk* se un
utente privilegiato ha una password IAS locale.

## BeyondTrust PRA

`securityhub pra` (alias `beyondtrust`, modulo `pra` nella configurazione) legge il site PRA e valuta **un oggetto
per riga**: utenti, utenti dei fornitori, asset (jump item), gateway, account API e account del vault, con i controlli
che valgono per il suo tipo. Le impostazioni globali (security provider, group policy, vendor group) e le statistiche
delle sessioni sono rilievi a livello di site.

```bash
export PRA_SITE_URL=https://<site> PRA_CLIENT_ID=... PRA_CLIENT_SECRET=...
securityhub pra -o pra.html --json --csv --session-days 7
securityhub pra --save-raw pra.json           # snapshot senza e-mail, IP degli utenti, password o registrazioni
```

**Account API** (/login > Management > API Configuration): Command API *Deny*; Configuration API *Allow Access* senza
*Manage Vault Accounts*; Reporting API: report delle sessioni e attività del vault; *Network Restrictions* con l'IP
pubblico della macchina. La Configuration API di PRA non ha un'opzione di sola lettura: il tool garantisce la sola
lettura da sé (solo `GET` su un elenco chiuso di endpoint, più la richiesta del token OAuth), e i test lo verificano.
Il tool segnala anche i permessi del proprio account che non usa.

| Controllo | Peso | Su | Cosa verifica |
|-----------|-----:|----|---------------|
| `authentication` | 30 | utenti, fornitori, account API | MFA (non per gli utenti SAML, gestita dall'IdP), amministratori locali, account API senza allow list di rete |
| `privileges` | 15 | utenti, fornitori, account API, vault | Amministratori, permessi API di scrittura o sensibili, credenziali del vault visibili (checkout) |
| `lifecycle` | 15 | utenti, fornitori, vault | Inattivi o mai usati, fornitori senza scadenza, rotazione delle password del vault |
| `access_policy` | 25 | asset | Asset senza asset policy, sessioni non registrate, nessuna approvazione, nessun orario, nessun MFA all'avvio, asset personali |
| `exposure` | 15 | asset, gateway | Telnet, RDP che ignora certificati non attendibili, tunnel, gateway offline o senza cluster, proxy senza restrizioni |

Nel portale l'area è *At risk* se c'è un amministratore senza MFA o un account API con permessi di scrittura
utilizzabile da qualunque indirizzo. Su PRA SaaS gli aggiornamenti del software sono gestiti da BeyondTrust, quindi
la versione non è valutata (richiederebbe la Command API).

## SentinelOne EDR

`securityhub edr` (alias `s1`, `sentinelone`) legge la console SentinelOne con le API v2.1 **in sola lettura** e
valuta ogni endpoint (agent attivo) e la configurazione della console.

**Credenziali**: mai nel file di configurazione (il `run` rifiuta `api_token`). Usa un **API token di un utente di
servizio con ruolo Viewer** (sola lettura) e passalo con variabili d'ambiente o con un file leggibile solo
dall'utente che esegue il tool:

```bash
export S1_CONSOLE_URL=https://contoso.sentinelone.net
export S1_API_TOKEN=...                                   # oppure --api-token-file /etc/securityhub/s1.token
securityhub edr -o edr.html --json --csv --inventory hosts.csv
securityhub edr --save-raw s1.json                        # salva lo snapshot (senza credenziali, IP o utenti)
securityhub edr --from-json s1.json --baseline prev.json  # analisi offline
```

| Controllo | Peso | Cosa verifica |
|-----------|-----:|---------------|
| `health` | 20 | Agent attivo, visto negli ultimi `--stale-days` giorni (14), senza azioni pendenti (riavvio, permessi macOS) |
| `protection` | 30 | Mitigazione in **Protect** (blocca, non solo Detect) per le minacce malevole; le sospette in Detect sono solo informative |
| `policy` | 25 | Policy effettiva (sito, o gruppo che non eredita): anti-tamper, motori di rilevamento attivi, snapshot VSS per il rollback, mitigazione automatica oltre il solo kill |
| `version` | 10 | Agent allineato all'ultima release GA; 2+ major indietro limita il punteggio a 70 |
| `threats` | 15 | Minacce non mitigate (punteggio max 20), minacce aperte oltre `--threat-sla-days` (7) |
| `vulnerabilities`, `scan` | info | Applicazioni vulnerabili note all'agent, full disk scan mai completato |

Profili endpoint: *Active threat*, *Agent disabled*, *Not seen recently*, *Detect mode only*, *Protected*.
La pagina **Policies and exclusions** riporta i rilievi di console: esclusioni troppo ampie (wildcard iniziali,
interi dischi, cartelle scrivibili dagli utenti come Temp/AppData/Downloads, tipi di file eseguibili), esclusioni
che disattivano tutti i monitor o senza descrizione, policy in Detect o con anti-tamper spento, agent duplicati,
agent fermi da oltre 90 giorni e **host dell'inventario senza agent** (`--inventory`: CSV con colonna
hostname o semplice elenco). `--metadata` aggiunge tier/owner/bu/tag per hostname, gruppo o sito.

Una policy non leggibile (token con scope ristretto) è *non verificata*, non un fallimento. Nel portale l'area
è *At risk* se c'è una minaccia non mitigata, che guida sempre il piano d'azione.

## Uso dei singoli moduli

Ogni modulo resta utilizzabile da solo, con le stesse opzioni degli script originali:

```bash
securityhub email domains.csv -o email.html --json --csv --dmarc-reports ./rua
securityhub dns domains.csv -o dns.html --json --csv --checks all,axfr
securityhub waf --account-id 1234567 --include-subaccounts --probe --json
securityhub waf --from-json snapshot.json --baseline last.json           # offline, da snapshot
securityhub edr -o edr.html --json --inventory hosts.csv                # SentinelOne (S1_CONSOLE_URL, S1_API_TOKEN)
securityhub proofpoint --domains domains.csv --json                     # Proofpoint (PROOFPOINT_PRINCIPAL/SECRET)
securityhub zta ./ZeroTrustReport -o zta.html --json --baseline prev.json
securityhub portal ./q1 ./q2 ./q3 -o security_hub.html --summary-json posture.json
```

Corrispondenza con gli script originali:

| Prima | Ora |
|-------|-----|
| `python MailGuardDNS.py ...` | `securityhub email ...` (alias `mail`) per i controlli e-mail, `securityhub dns ...` per quelli DNS, `securityhub dns --combined` per un report unico |
| `python WAFGuard.py ...` | `securityhub waf ...` |
| `python ZTAGuard.py ...` | `securityhub zta ...` (alias `zt`) |
| `python GuardHub.py ...` | `securityhub portal ...` (alias `hub`) |

I report prodotti sono identici a quelli degli script originali.

## Struttura del progetto

```
securityhub/
  cli.py               entry point `securityhub`
  orchestrator.py      run / status / init: config, esecuzione parallela con timeout e log, baseline, retention, posture.json
  console.py           output del terminale: avanzamento, colori (NO_COLOR / FORCE_COLOR), riepilogo
  portal.py            GuardHub: portale unificato, metriche executive, storico KPI
  inventory.py         vista per asset: correlazione DNS / WAF / certificati / tenant e segnali trasversali
  common.py            helper condivisi (export CSV sicuro, JSON in HTML, rate limiter, exit code, grade)
  ui/                  design system condiviso di report e portale (assemblato in file HTML singoli e offline)
    base.css             token, layout e componenti comuni a tutte le pagine
    core.js, theme.js, report-core.js, asset-report.js   funzioni condivise (tutte le pagine / i 3 report / DNS e WAF)
    dns|waf|edr|proofpoint|ias|pra|zta|portal.css|js, report.html, portal.html   parti specifiche
  scanners/
    dns_email/         MailGuard DNS: constants, models, domains, dnsclient, rdap, fetch,
                       analyzer + checks_auth / checks_transport / checks_exposure / scoring,
                       lookalikes, dmarc_reports, remediation, baseline, inputs, exports, report, cli
    waf/               WAFGuard: constants, models, api, probe, checks, scoring, remediation, analysis, exports, report, cli
    proofpoint/        PPGuard (Proofpoint): constants, models, routing (DNS), api (TAP), checks, analysis, exports, report, cli
    pra/               PRAGuard (BeyondTrust PRA): constants, models, api, analysis, exports, report, cli
    sap_ias/           IASGuard (SAP Cloud Identity): constants, models, api (SCIM), analysis, exports, report, cli
    edr/               EDRGuard (SentinelOne): constants, models, api, checks, analysis, exports, report, cli
    zero_trust.py      ZTAGuard (Microsoft)
tests/                 test automatici (pytest) con fixture sintetiche e DNS simulato (tests/fakedns.py)
examples/              configurazione e lista domini di esempio
```

Una modifica grafica fatta in `ui/base.css` o in un file JS condiviso arriva a tutti i report e al portale
alla generazione successiva: i file in `ui/` contengono righe `/* @include nome */` che vengono sostituite dal
contenuto del file indicato.

## Note di sicurezza

- Tutti i moduli sono **in sola lettura**: WAFGuard usa solo endpoint list/status/get, EDRGuard solo GET (token Viewer), PPGuard solo le API SIEM e People di TAP.
- Le credenziali (Imperva, SentinelOne, Proofpoint, SAP IAS, BeyondTrust) non sono accettate nel file di configurazione: variabili d'ambiente o file di chiave.
- I CSV sono protetti da formula injection; i dati inseriti nei report HTML sono escapati e le pagine hanno una CSP restrittiva.
- Il fetch MTA-STS è protetto da SSRF (solo IP pubblici, salvo `--allow-private`).
- `reports/`, snapshot e `securityhub.yaml` sono in `.gitignore`: descrivono la tua posture e non vanno pubblicati.

## Sviluppo

```bash
pip install -e ".[full,dev]"
python -m pyflakes securityhub tests
python -m pytest -q
```


## Stato e diagnostica (`securityhub doctor`)

`securityhub doctor` controlla ogni modulo abilitato come lo userebbe una scansione (stesse opzioni e variabili
d'ambiente) con **una sola chiamata in lettura**: credenziali presenti, accettate e con i permessi necessari, input
(lista domini, `dkim.csv`, export Zero Trust) e resolver DNS. Per Proofpoint verifica TAP (SIEM, ultimo minuto),
la Threat Protection API (solo il token: i report hanno una quota giornaliera) e la PoD Log API (apre e chiude lo
stream). In caso di errore indica la causa probabile (credenziale rifiutata o problema di rete).

Il risultato va in `<output_dir>/health.json` e nella pagina **Status** del portale, che mostra anche per ogni area:
esito dell'ultima esecuzione, età dei dati, elementi realmente valutati, controlli non valutabili ed errori API.
Codice di uscita 1 se un controllo fallisce (utilizzabile dal monitoraggio).
Con `securityhub-doctor.timer` il controllo gira da solo una volta al giorno; se una credenziale fallisce, la card
dell'area nel portale mostra un badge **Credentials** che porta alla pagina Status. La colonna *Errori di lettura*
conta i controlli non valutati per un errore API o DNS; *Non verificabili* quelli che per definizione non hanno dati
(es. DKIM di un dominio non elencato in `dkim.csv`, agent non visti da settimane).

## Igiene ed esposizione attiva

Ogni area del portale mostra, oltre allo score complessivo, due cifre separate:
- **Igiene** (/100): solo i controlli di configurazione, senza i limiti imposti dalle esposizioni;
- **Esposizione attiva**: elementi con una minaccia, un click consentito, un account senza MFA, un bypass, un nome
  dirottabile... (più quelle a livello di organizzazione). Sono anche in `posture.json` e nei trend.
