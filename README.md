# Security Hub

Monitoraggio della **security posture** su tre aree, con un unico comando e un unico portale:

| Area | Modulo | Cosa valuta | Sorgente dati |
|------|--------|-------------|---------------|
| **WAF** | `securityhub waf` (WAFGuard) | Configurazione Imperva Cloud WAF: onboarding, regole OWASP in blocco, eccezioni, allow-list, bot, DDoS, TLS, esposizione dell'origin | API Imperva (sola lettura) o snapshot JSON |
| **DNS / E-mail** | `securityhub dns` (MailGuard DNS) | MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, takeover, zone transfer (AXFR, opt-in), lookalike, report DMARC aggregati | DNS live (+ RDAP, HTTPS per MTA-STS) |
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
```

Output di `securityhub run`:

```
reports/
  runs/2026-10-31T080000Z/   dns.html dns.json dns.csv dns.log  waf.* waf.log  zta.* zta.log
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
keep_runs: 12            # esecuzioni conservate per i trend (0 = tutte)
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

- `options` accetta **le stesse opzioni della riga di comando** del modulo (`securityhub <modulo> --help`),
  con `_` o `-`: `true/false` per gli switch, liste per valori multipli. Le opzioni sconosciute sono un errore.
- I percorsi relativi sono risolti rispetto alla cartella del file di configurazione.
- `output` è gestito dall'hub; `--json` è sempre attivo perché l'export JSON fa da baseline per l'esecuzione successiva.
- **Le credenziali non vanno nel file**: `api_key` viene rifiutata. Usa `IMPERVA_API_ID` / `IMPERVA_API_KEY`
  oppure `api_key_file`.
- È accettato anche JSON (`securityhub run -c hub.json`), senza bisogno di PyYAML.

Opzioni utili di `run`: `--only dns,zta`, `--dry-run` (mostra i comandi senza eseguirli), `-q` (solo la posture),
`-v` (mostra anche l'output dei moduli, con il prefisso `[dns]`, `[waf]`, `[zta]`), `-p N` (moduli in parallelo),
`--timeout SECONDI`, `-o` (cartella di output alternativa).

### Esecuzione parallela

Ogni modulo gira **in un processo separato**: un errore o un blocco in un modulo non coinvolge gli altri. I moduli
partono insieme (`max_parallel`, default: tutti; `1` = in sequenza) e l'output di ciascuno va in `runs/<data>/<modulo>.log`.
Con `module_timeout` (o `timeout` per singolo modulo) un modulo che supera il tempo viene fermato e segnalato.
Se un modulo fallisce, la console mostra le ultime righe del suo log.

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

## Uso dei singoli moduli

Ogni modulo resta utilizzabile da solo, con le stesse opzioni degli script originali:

```bash
securityhub dns domains.csv -o dns.html --json --csv --checks all,takeover
securityhub waf --account-id 1234567 --include-subaccounts --probe --json
securityhub waf --from-json snapshot.json --baseline last.json           # offline, da snapshot
securityhub zta ./ZeroTrustReport -o zta.html --json --baseline prev.json
securityhub portal ./q1 ./q2 ./q3 -o security_hub.html --summary-json posture.json
```

Corrispondenza con gli script originali:

| Prima | Ora |
|-------|-----|
| `python MailGuardDNS.py ...` | `securityhub dns ...` (alias `mail`, `email`) |
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
    dns|waf|zta|portal.css|js, report.html, portal.html   parti specifiche
  scanners/
    dns_email/         MailGuard DNS: constants, models, domains, dnsclient, rdap, fetch,
                       analyzer + checks_auth / checks_transport / checks_exposure / scoring,
                       lookalikes, dmarc_reports, remediation, baseline, inputs, exports, report, cli
    waf/               WAFGuard: constants, models, api, probe, checks, scoring, remediation, analysis, exports, report, cli
    zero_trust.py      ZTAGuard (Microsoft)
tests/                 test automatici (pytest) con fixture sintetiche e DNS simulato (tests/fakedns.py)
examples/              configurazione e lista domini di esempio
```

Una modifica grafica fatta in `ui/base.css` o in un file JS condiviso arriva a tutti i report e al portale
alla generazione successiva: i file in `ui/` contengono righe `/* @include nome */` che vengono sostituite dal
contenuto del file indicato.

## Note di sicurezza

- Tutti i moduli sono **in sola lettura**: WAFGuard usa solo endpoint list/status/get.
- I CSV sono protetti da formula injection; i dati inseriti nei report HTML sono escapati e le pagine hanno una CSP restrittiva.
- Il fetch MTA-STS è protetto da SSRF (solo IP pubblici, salvo `--allow-private`).
- `reports/`, snapshot e `securityhub.yaml` sono in `.gitignore`: descrivono la tua posture e non vanno pubblicati.

## Sviluppo

```bash
pip install -e ".[full,dev]"
python -m pyflakes securityhub tests
python -m pytest -q
```
