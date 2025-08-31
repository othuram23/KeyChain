# fix_keychain.ps1
# Usage: Ouvre PowerShell dans C:\Users\Admin\KeyChain et exécute ce script
# (ou exécute les commandes manuellement, dans l'ordre).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $RepoPath = "C:\Users\Admin\KeyChain"
    if (-not (Test-Path $RepoPath)) { throw "Le dossier $RepoPath n'existe pas. Vérifie le chemin." }
    Set-Location $RepoPath

    Write-Host "`n==> 1) Mark 'scripts/checks.sh' executable in git index (for Linux/CI)..." -ForegroundColor Cyan
    git update-index --add --chmod=+x scripts/checks.sh

    Write-Host "`n==> 2) Stage common files (.github, .pre-commit-config.yaml, scripts)..." -ForegroundColor Cyan
    git add .github .pre-commit-config.yaml scripts 2>$null

    # Check if something is staged
    $staged = (& git diff --cached --name-only)
    if ([string]::IsNullOrWhiteSpace($staged)) {
        Write-Host "=> Aucun changement à committer (rien de staged)." -ForegroundColor Yellow
    } else {
        Write-Host "Fichiers staged :" -ForegroundColor Green
        $staged | ForEach-Object { Write-Host "  $_" }
        Write-Host "`n==> Commit..." -ForegroundColor Cyan
        git commit -m "chore: add CI/config files and mark checks.sh executable"
        Write-Host "==> Push vers origin/main..." -ForegroundColor Cyan
        git push origin main
    }

    Write-Host "`n==> 3) Nettoyage du cache pre-commit (si présent)..." -ForegroundColor Cyan
    $cacheFolder = Join-Path $env:USERPROFILE ".cache\pre-commit"
    if (Test-Path $cacheFolder) {
        Write-Host "Suppression de $cacheFolder"
        Remove-Item -Recurse -Force $cacheFolder
    } else {
        Write-Host "Cache pre-commit non présent, rien à supprimer." -ForegroundColor Yellow
    }

    Write-Host "`n==> 4) Installer / initialiser pre-commit via Python (évite problèmes PATH)..." -ForegroundColor Cyan
    # utilise --user pour être sûr de ne pas nécessiter de droits
    python -m pip install --user --upgrade pre-commit

    Write-Host "`n==> 5) Nettoyer les anciennes installations pre-commit (sécurisé)..." -ForegroundColor Cyan
    # clean peut échouer si pré-commit n'était pas installé, donc try/catch
    try { python -m pre_commit clean } catch { Write-Host "pre_commit clean : non critique : $_" -ForegroundColor Yellow }

    Write-Host "`n==> 6) Installer les hooks dans le repo..." -ForegroundColor Cyan
    # installe les hooks (équivalent 'pre-commit install')
    python -m pre_commit install

    Write-Host "`n==> 7) Lancer les hooks sur tous les fichiers (vérifie tout)... (peut prendre du temps)" -ForegroundColor Cyan
    python -m pre_commit run --all-files

    Write-Host "`n==> Terminé sans erreur détectée (voir messages ci-dessus)." -ForegroundColor Green
} catch {
    Write-Host "`nERREUR : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stacktrace (pour debug) :" -ForegroundColor DarkRed
    Write-Host $_.Exception.StackTrace
    Write-Host "`nSi l'erreur est 'Filename too long' ou liée à semgrep, suis la procédure recommandée (ensuite dans ce message)." -ForegroundColor Yellow
}
