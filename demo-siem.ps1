# Demo SIEM StartupMed - lance les 5 attaques et montre la detection
$ErrorActionPreference = 'SilentlyContinue'
Set-Location $PSScriptRoot

# Synchroniser l'heure des VM (evite les dates decalees apres une veille du PC)
& "$PSScriptRoot\sync-heure.ps1" | Out-Null

Write-Host ""
Write-Host "==================== DEMO SIEM StartupMed ====================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[0] Remise a zero des journaux du SIEM" -ForegroundColor Yellow
vagrant ssh z4-bastion -c "sudo siem-reset"
Write-Host ""

Write-Host "[0] Etat initial du SIEM (doit etre vide)" -ForegroundColor Yellow
vagrant ssh z4-bastion -c "sudo siem-detect"
Start-Sleep -Seconds 2
Write-Host ""

Write-Host "[1] ATTAQUE : brute force mot de passe (depuis le poste du siege)" -ForegroundColor Yellow
vagrant ssh z5-poste -c "siem-attaques bruteforce"
Write-Host ""

Write-Host "[2] ATTAQUE : elevation de privilege (compte standard 'stagiaire')" -ForegroundColor Yellow
vagrant ssh z5-poste -c "siem-attaques privilege"
Write-Host ""

Write-Host "[3] ATTAQUE : exfiltration - 20 lectures de dossiers via l'API (Internet)" -ForegroundColor Yellow
for ($i = 1; $i -le 20; $i++) { curl.exe -k -s -o NUL --max-time 5 "https://192.168.56.10/patients?id=$i" }
Write-Host "    20 requetes envoyees"
Write-Host ""

Write-Host "[4] ATTAQUE : injection SQL (Internet)" -ForegroundColor Yellow
curl.exe -k -s -o NUL -w "    reponse du WAF : %{http_code} (403 = bloquee)`n" "https://192.168.56.10/patients?id=1%27%20OR%20%271%27=%271"
Write-Host ""

Write-Host "[5] ATTAQUE : RDP depuis l'exterieur (port 3389)" -ForegroundColor Yellow
for ($i = 1; $i -le 3; $i++) { $c = New-Object Net.Sockets.TcpClient; try { $c.ConnectAsync('192.168.56.10', 3389).Wait(1500) } catch {}; $c.Close() }
Write-Host "    3 tentatives RDP envoyees"
Start-Sleep -Seconds 3
Write-Host ""

Write-Host "============ RESULTAT : le SIEM remonte les 5 attaques ============" -ForegroundColor Cyan
vagrant ssh z4-bastion -c "sudo siem-detect"
Write-Host ""
Write-Host "Journal des alertes horodatees et conservees :" -ForegroundColor Yellow
vagrant ssh z4-bastion -c "sudo cat /var/log/central/ALERTES.log"
Write-Host ""
Write-Host "==================== FIN DE LA DEMO ====================" -ForegroundColor Cyan
