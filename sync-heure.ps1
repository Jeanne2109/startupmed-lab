# Synchronise l'heure de toutes les VM du labo sur l'heure du PC.
# A lancer si les dates des logs sont decalees (apres une veille du PC).
Set-Location $PSScriptRoot
$utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
Write-Host "Synchronisation de l'heure des VM sur le PC ($utc UTC)..." -ForegroundColor Cyan
foreach ($vm in 'fw','z1-dmz','z2-app','z3-db','z4-bastion','z5-poste','opensearch') {
  vagrant ssh $vm -c "sudo date -u -s '$utc'" 2>$null | Out-Null
  $h = vagrant ssh $vm -c "date '+%F %T %Z'" 2>$null
  Write-Host ("  {0,-12} {1}" -f $vm, $h)
}
Write-Host "Heure synchronisee sur toutes les VM." -ForegroundColor Green
