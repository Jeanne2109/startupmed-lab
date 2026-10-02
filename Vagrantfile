# -*- mode: ruby -*-
# Labo StartupMed — Atelier 2 (segmentation & matrice de flux)
# Une commande : `vagrant up`  (~15 min la premiere fois)

require "openssl"
require "securerandom"
require "base64"
require "fileutils"

# ---------------------------------------------------------------------------
# Secrets du labo : generes une seule fois dans .lab-secrets/ (jamais dans le code)
# ---------------------------------------------------------------------------
SECRETS = File.join(File.dirname(__FILE__), ".lab-secrets")
FileUtils.mkdir_p(SECRETS)

def lab_secret(name)
  path = File.join(SECRETS, name)
  File.binwrite(path, yield) unless File.exist?(path)
  File.binread(path).strip
end

DB_PASSWORD    = lab_secret("db_password")    { SecureRandom.hex(16) }
ADMIN_PASSWORD = lab_secret("admin_password") { SecureRandom.alphanumeric(14) }

# Cle SSH du compte "admin" : privee sur le bastion, publique sur les serveurs
KEY_PRIV = File.join(SECRETS, "admin_id_rsa")
KEY_PUB  = File.join(SECRETS, "admin_id_rsa.pub")
unless File.exist?(KEY_PRIV) && File.exist?(KEY_PUB)
  key       = OpenSSL::PKey::RSA.new(3072)
  ssh_str   = ->(s) { [s.bytesize].pack("N") + s }
  ssh_mpint = ->(bn) { b = bn.to_s(2); b = "\x00".b + b if b.getbyte(0) >= 0x80; ssh_str.call(b) }
  blob      = ssh_str.call("ssh-rsa".b) + ssh_mpint.call(key.e) + ssh_mpint.call(key.n)
  File.binwrite(KEY_PRIV, key.to_pem)
  File.binwrite(KEY_PUB, "ssh-rsa #{Base64.strict_encode64(blob)} admin@z4-bastion\n")
end

# ---------------------------------------------------------------------------
# Plan d'adressage (une zone = un reseau interne VirtualBox isole)
#   Z0 Internet simule : 192.168.56.0/24 (votre PC = 192.168.56.1)
#   Z1 DMZ 10.10.1.0/24 · Z2 Applicative 10.10.2.0/24 · Z3 Donnees 10.10.3.0/24
#   Z4 Administration 10.10.4.0/24 · Z5 Siege 10.10.5.0/24
# ---------------------------------------------------------------------------
Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "virtualbox" do |vb|
    vb.linked_clone = true
    vb.cpus = 1
  end

  # Une VM de zone : une seule carte dans sa zone, routee via le pare-feu
  zone_vm = lambda do |m, name, ip, gw, intnet, memory|
    m.vm.hostname = name
    m.vm.network "private_network", ip: ip, virtualbox__intnet: intnet
    m.vm.provider("virtualbox") { |vb| vb.memory = memory; vb.name = "startupmed-#{name}" }
    m.vm.provision "routes", type: "shell", path: "scripts/routes.sh", args: [gw], run: "always"
  end

  # ---- Pare-feu F1/F2/F3 : routeur Debian + nftables ----------------------
  config.vm.define "fw" do |m|
    m.vm.hostname = "fw"
    m.vm.network "private_network", ip: "192.168.56.10"                       # Z0
    m.vm.network "private_network", ip: "10.10.1.1", virtualbox__intnet: "z1-dmz"
    m.vm.network "private_network", ip: "10.10.2.1", virtualbox__intnet: "z2-app"
    m.vm.network "private_network", ip: "10.10.3.1", virtualbox__intnet: "z3-donnees"
    m.vm.network "private_network", ip: "10.10.4.1", virtualbox__intnet: "z4-admin"
    m.vm.network "private_network", ip: "10.10.5.1", virtualbox__intnet: "z5-siege"
    m.vm.provider("virtualbox") { |vb| vb.memory = 512; vb.name = "startupmed-fw" }
    m.vm.provision "file", source: "fw/nftables.conf", destination: "/tmp/nftables.conf"
    m.vm.provision "shell", path: "scripts/fw.sh"
    # SIEM : transmet les blocages du pare-feu au SIEM (Z4)
    m.vm.provision "siem", type: "shell", path: "scripts/fw-siem.sh"
  end

  # ---- Z1 : DMZ — WAF (Apache + ModSecurity + OWASP CRS) ------------------
  config.vm.define "z1-dmz" do |m|
    zone_vm.call(m, "z1-dmz", "10.10.1.10", "10.10.1.1", "z1-dmz", 512)
    m.vm.provision "file", source: KEY_PUB, destination: "/tmp/admin_id_rsa.pub"
    m.vm.provision "shell", path: "scripts/admin-cible.sh"
    m.vm.provision "shell", path: "scripts/z1-dmz.sh"
  end

  # ---- Z2 : Applicative — API de demo -------------------------------------
  config.vm.define "z2-app" do |m|
    zone_vm.call(m, "z2-app", "10.10.2.10", "10.10.2.1", "z2-app", 1024)
    m.vm.provision "file", source: KEY_PUB, destination: "/tmp/admin_id_rsa.pub"
    m.vm.provision "shell", path: "scripts/admin-cible.sh"
    m.vm.provision "shell", path: "scripts/z2-app.sh", args: [DB_PASSWORD]
    # Jour 3 : conteneur durci + scan Trivy + redemarrage automatique
    m.vm.provision "conteneur", type: "shell", path: "scripts/z2-conteneur.sh"
  end

  # ---- Z3 : Donnees de sante — PostgreSQL (TLS) ---------------------------
  config.vm.define "z3-db" do |m|
    zone_vm.call(m, "z3-db", "10.10.3.10", "10.10.3.1", "z3-donnees", 768)
    m.vm.provision "file", source: KEY_PUB, destination: "/tmp/admin_id_rsa.pub"
    m.vm.provision "shell", path: "scripts/admin-cible.sh"
    m.vm.provision "shell", path: "scripts/z3-db.sh", args: [DB_PASSWORD]
    # Jour 3 : sauvegarde horaire (RPO 1 h)
    m.vm.provision "sauvegarde", type: "shell", path: "scripts/z3-sauvegarde.sh"
  end

  # ---- Z4 : Administration — bastion SSH + MFA (TOTP) + logs centralises --
  config.vm.define "z4-bastion" do |m|
    zone_vm.call(m, "z4-bastion", "10.10.4.10", "10.10.4.1", "z4-admin", 512)
    m.vm.provision "file", source: KEY_PRIV, destination: "/tmp/admin_id_rsa"
    m.vm.provision "shell", path: "scripts/z4-bastion.sh", args: [ADMIN_PASSWORD]
    # Jour 3 : copies immuables des sauvegardes + restauration en une commande
    m.vm.provision "sauvegarde", type: "shell", path: "scripts/z4-sauvegarde.sh"
    # SIEM : moteur de detection des 4 scenarios d'attaque
    m.vm.provision "siem", type: "shell", path: "scripts/z4-siem.sh"
  end

  # ---- Z5 : Siege — poste salarie -----------------------------------------
  config.vm.define "z5-poste" do |m|
    zone_vm.call(m, "z5-poste", "10.10.5.10", "10.10.5.1", "z5-siege", 512)
    m.vm.provision "shell", path: "scripts/z5-poste.sh"
  end
end
