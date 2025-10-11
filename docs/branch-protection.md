# Branch Protection Guide

## Prehľad

Hlavná vetva (`main`) je chránená pomocou GitHub branch protection rules, ktoré zabezpečujú kvalitu a bezpečnosť kódu.

## Pravidlá ochrany vetvy

### Požadované kontroly stavu
Pred zlúčením pull requestu musia prejsť všetky tieto kontroly:
- **PowerShell Script Analysis** - Analýza PowerShell skriptov pomocou PSScriptAnalyzer
- **Markdown Linting** - Kontrola formátovania Markdown súborov
- **Security Scanning** - Bezpečnostné skenovanie pomocou Trivy
- **Repository Structure Validation** - Validácia štruktúry repozitára
- **PowerShell Syntax Validation** - Kontrola syntaxe PowerShell skriptov

### Požiadavky na review
- **Minimálne 1 schválenie** je potrebné pre každý pull request
- **Code owner review** je povinný pre všetky zmeny
- **Dismiss stale reviews** - staré reviews sa automaticky zrušia pri nových commitoch
- **Require approval of most recent push** - najnovší commit musí byť schválený

### Bezpečnostné obmedzenia
- **Enforce for administrators** - pravidlá platia aj pre administrátorov
- **No force pushes** - priame force push do main vetvy je zakázané
- **No deletions** - main vetva nemôže byť zmazaná
- **Require conversation resolution** - všetky diskusie musia byť vyriešené

## Nastavenie ochrany vetvy

### Metóda 1: GitHub Actions (Automatická)

Workflow súbor `.github/workflows/branch-protection.yml` automaticky nastaví ochranu vetvy:

```bash
# Spustenie workflow cez GitHub CLI
gh workflow run branch-protection.yml
```

### Metóda 2: Bash skript (Manuálna)

```bash
# Spustenie setup skriptu
./scripts/setup-branch-protection.sh
```

**Požiadavky:**
- GitHub CLI (`gh`) musí byť nainštalované
- Musíte byť autentifikovaný: `gh auth login`
- Potrebujete admin práva na repozitár

### Metóda 3: GitHub Web Interface

1. Prejdite do **Settings** → **Branches**
2. Kliknite na **Add rule**
3. Zadajte `main` ako branch name pattern
4. Povoľte nasledujúce možnosti:
   - ✅ Require a pull request before merging
   - ✅ Require approvals (1)
   - ✅ Dismiss stale pull request approvals when new commits are pushed
   - ✅ Require review from CODEOWNERS
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - ✅ Require conversation resolution before merging
   - ✅ Restrict pushes that create files larger than 100 MB
   - ✅ Do not allow bypassing the above settings

## Workflow pre prispievateľov

### 1. Vytvorenie feature branch
```bash
git checkout -b feature/nova-funkcionalita
```

### 2. Vykonanie zmien a commit
```bash
git add .
git commit -m "feat: pridanie novej funkcionality"
git push origin feature/nova-funkcionalita
```

### 3. Vytvorenie Pull Request
- Otvorte pull request cez GitHub web interface
- Vyplňte popis zmien
- Označte relevantných reviewerov

### 4. CI/CD kontroly
Automaticky sa spustia:
- PowerShell analýza
- Markdown linting
- Bezpečnostné skenovanie
- Validácia štruktúry

### 5. Code Review
- Code owner musí schváliť zmeny
- Všetky diskusie musia byť vyriešené
- Všetky CI/CD kontroly musia prejsť

### 6. Merge
Po splnení všetkých požiadaviek môže byť pull request zlúčený.

## Riešenie problémov

### Chyba: "Required status check is failing"
```bash
# Skontrolujte CI/CD logy
gh run list --branch feature/nova-funkcionalita

# Zobrazenie detailov konkrétneho behu
gh run view <run-id>
```

### Chyba: "Review required"
- Požiadajte code ownera o review
- Skontrolujte CODEOWNERS súbor pre relevantných reviewerov

### Chyba: "Conversation not resolved"
- Vyriešte všetky komentáre v pull requeste
- Označte diskusie ako vyriešené

### Chyba: "Branch not up to date"
```bash
# Aktualizujte branch
git checkout main
git pull origin main
git checkout feature/nova-funkcionalita
git rebase main
git push --force-with-lease origin feature/nova-funkcionalita
```

## Bezpečnostné výhody

### Ochrana pred
- **Neautorizovanými zmenami** - všetky zmeny musia prejsť review
- **Chybnými skriptami** - automatická analýza PowerShell kódu
- **Bezpečnostnými zraniteľnosťami** - Trivy skenovanie
- **Nekonzistentnou dokumentáciou** - Markdown linting
- **Porušenou štruktúrou** - validácia repozitára

### Audit trail
- Všetky zmeny sú zdokumentované v pull requestoch
- História reviewov je zachovaná
- CI/CD logy poskytujú detailné informácie o kontrolách

## Konfigurácia pre rôzne prostredia

### Development repozitár
```yaml
required_approving_review_count: 1
dismiss_stale_reviews: true
require_code_owner_reviews: true
```

### Production repozitár
```yaml
required_approving_review_count: 2
dismiss_stale_reviews: true
require_code_owner_reviews: true
enforce_admins: true
```

### Open source projekt
```yaml
required_approving_review_count: 1
dismiss_stale_reviews: false
require_code_owner_reviews: false
```

## Monitoring a metriky

### GitHub Insights
- **Pull request metrics** - čas na review, merge rate
- **Code review coverage** - percentuálne pokrytie reviews
- **Security alerts** - automatické upozornenia na zraniteľnosti

### Automatické reporty
```bash
# Generovanie reportu o branch protection
gh api repos/:owner/:repo/branches/main/protection --jq '.required_status_checks.contexts[]'
```

## Najlepšie praktiky

### Pre maintainerov
1. **Pravidelne aktualizujte** branch protection rules
2. **Monitorujte CI/CD** výkonnosť a spoľahlivosť
3. **Reviewujte CODEOWNERS** súbor pri zmenách tímu
4. **Dokumentujte výnimky** ak sú potrebné

### Pre prispievateľov
1. **Testujte lokálne** pred vytvorením pull requestu
2. **Píšte jasné commit messages** a PR popisy
3. **Reagujte na feedback** rýchlo a konštruktívne
4. **Udržiavajte branches aktuálne** s main vetvou

## Súvisiace dokumenty

- [Contributing Guidelines](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Installation Guide](installation.md)