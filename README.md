# Security Hub

Monitoraggio della **security posture** su tre aree, con un unico comando e un unico portale:

| Area | Modulo | Cosa valuta | Sorgente dati |
|------|--------|-------------|---------------|
| **WAF** | `securityhub waf` (WAFGuard) | Configurazione Imperva Cloud WAF: onboarding, regole OWASP in blocco, eccezioni, allow-list, bot, DDoS, TLS, esposizione dell'origin | API Imperva (sola lettura) o snapshot JSON |
| **DNS / E-mail** | `securityhub dns` (MailGuard DNS) | MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, takeover, lookalike, report DMARC aggregati | DNS live (+ RDAP, HTTPS per MTA-STS) |
| **Zero Trust** | `securityhub zta` (ZTAGuard) | Risultati del Microsoft Zero Trust Assessment per pilastro, priorità, quick win | `ZeroTrustAssessmentReport.json` |
| **Portale** | `securityhub portal` (GuardHub) | Un solo file HTML con stato per area, KPI, piano d'azione trasversale, trend storici e i report navigabili | Report HTML generati dai moduli |

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
  runs/2026-10-31T080000Z/   dns.html dns.json dns.csv  waf.html waf.json waf.csv  zta.html zta.json zta.csv
  runs/2026-11-07T080000Z/   ...
  security_hub.html          <- portale: ultima esecuzione navigabile, le precedenti diventano trend dei KPI
  posture.json               <- riepilogo per monitoraggio / SIEM / CI
```

Esempio di output a console:

```
================================================================
SECURITY POSTURE  D  (52/100)
================================================================
2 need attention. Largest exposure: 2 of 3 websites (67%) are not effectively protected by the WAF.
  Imperva Cloud WAF         D   50  ATTENTION  2026-10-31  2 of 3 websites (67%) are not effectively protected by the WAF
      - Websites effectively protected by the WAF: 33%
  Microsoft Zero Trust      D   54  ATTENTION  2026-10-01  1 high-risk Zero Trust controls are failing
      - Zero Trust controls passed: 54/100
Top actions:
  [critical] Microsoft Zero Trust     Privileged accounts use phishing-resistant MFA
  [critical] Imperva Cloud WAF        No WAF rules policy protects this website
```

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
`-o` (cartella di output alternativa).

## Monitoraggio continuo

`securityhub run` è pensato per girare a intervalli regolari. Gli exit code sono uguali per tutti i comandi:

| Code | Significato |
|------|-------------|
| 0 | OK |
| 1 | Errore di uso / input / API (anche se un solo modulo fallisce: gli altri vengono comunque eseguiti e il portale aggiornato) |
| 2 | Punteggio sotto `fail_under` |
| 130 | Interrotto |

**cron** (ogni lunedì alle 07:40):

```cron
40 7 * * 1  cd /opt/securityhub && . ./.env && securityhub run -q >> run.log 2>&1
```

**Windows Task Scheduler**: esegui prima `Invoke-ZtAssessment` (modulo PowerShell `ZeroTrustAssessment`),
poi `securityhub run`, puntando `modules.zta.input` alla cartella del report.

**posture.json** contiene punteggio e grado complessivi, stato per area (`good` / `warn` / `bad`), KPI
(es. % domini protetti da spoofing, % siti realmente protetti dal WAF, % sign-in con MFA), azioni prioritarie
e l'esito di ogni modulo dell'ultima esecuzione: può essere inviato a un SIEM o a una dashboard.

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
  orchestrator.py      run / status / init: config, esecuzioni datate, baseline automatica, retention, posture.json
  portal.py            GuardHub: portale unificato, metriche executive, storico KPI
  common.py            helper condivisi (export CSV sicuro, JSON in HTML, rate limiter, exit code, grade)
  scanners/
    dns_email.py       MailGuard DNS
    waf.py             WAFGuard (Imperva)
    zero_trust.py      ZTAGuard (Microsoft)
tests/                 test automatici (pytest) con fixture sintetiche
examples/              configurazione e lista domini di esempio
```

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
