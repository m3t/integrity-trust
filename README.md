## Intro

> In many cases it's much more preferable to build software from the source instead of using signed binaries.
But this build process has to be carefully thought out:
* **Git**
  * [Horror story](http://mikegerwitz.com/papers/git-horror-story)
  * [Signing your work](https://git-scm.com/book/tr/v2/Git-Tools-Signing-Your-Work)
>  
* **Reproducible builds**
  * [The Tor Blog](https://blog.torproject.org/blog/deterministic-builds-part-one-cyberwar-and-global-compromise)
  * [Debian Wiki](https://wiki.debian.org/ReproducibleBuilds)

This collection of snippets follows the approach (like [this](https://www.whonix.org/wiki/OpenPGP#Bootstrapping_OpenPGP_keys_from_the_web) article) that the system is not necessarily your personal environment and therefore there isn't any [trust](http://web.monkeysphere.info/doc/trust-models/)-path to your own OpenPGP key.

In terms of [disc images](#disc-images) there is to a certain extent a chicken-egg problem concerning the question:
*How to deploy a [secure system](https://ssl.kundenserver.de/www.hauke-laging.de/sicherheit/openpgp.html#sicheres_system)?*
That is why the following commands try to avoid unnecessary expensive **network activity** and don't make use of notable vulnerable network-clients like **web browsers** or BitTorrent clients!

* [EFF - SSD: Keeping Your Data Safe](https://ssd.eff.org/en/module/keeping-your-data-safe)

### Prepare environment
*Based on a work by [Daniel Kahn Gillmor](https://help.riseup.net/en/security/message-security/openpgp/best-practices) and Jacob Appelbaum*

**Dependencies**
```sh
sudo aptitude update
sudo aptitude install git curl pgpdump
```

Mainly used by the ["Web-/Keyserver"](#web-keyserver)-method:
```sh
# https://www.ssllabs.com/ssltest/analyze.html?d=sks-keyservers.net
curl --tlsv1.2 --create-dirs -o "$HOME/certs/hkps.pool.sks-keyservers.net.pem" "https://sks-keyservers.net/sks-keyservers.netCA.pem"
git clone "https://github.com/ioerror/duraconf.git" "$HOME/duraconf"
# Disable remote push
git --git-dir="$HOME/duraconf/.git" remote set-url --push origin no-pushing
# Change .gnupg folder temporarily
export GNUPGHOME="$HOME/duraconf/configs/gnupg" 
chmod 700 "$GNUPGHOME"
# Modify gpg.conf
sed -i "/keyserver-options ca-cert/s|=.*$|=$HOME/certs/hkps.pool.sks-keyservers.net.pem|" "$GNUPGHOME/gpg.conf"
```

### GPG messages

```
gpg: no ultimately trusted keys found
```
You didn't create an OpenPGP key for [yourself](#generate-key) yet,
which is of no importance to the approach here.


```
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
```
This warning is related to the trust that you put in the signing key.
To remove this warning you would have to personally [sign](https://ssl.kundenserver.de/www.hauke-laging.de/sicherheit/openpgp.html#beglaubigung) the signing key with your own key ([--lsign-key](https://ssl.webpack.de/www.openpgp-schulungen.de/glossar/lckey/)).

[![xkcd: Responsible Behavior](http://imgs.xkcd.com/comics/responsible_behavior.png)](https://xkcd.com/364/)
*by [xkcd](https://xkcd.com/364/)*

Further reading:
* [Apache Software Foundation](https://www.apache.org/dev/release-signing.html)
* [GnuPG - FAQ](https://www.gnupg.org/faq/gnupg-faq.html#glossary)

## Generic proceeding

### Check public key

#### Offline fingerprint<sup>[1](#footnote1)</sup>

Compare key's fingerprint [2] with it's **printed** version [1].

##### [Certification Authorities](http://wiki.kairaven.de/open/krypto/gpg/p/gpg3#zertifizierungsstellen)
* [c't CA](http://ct.de/pgpCA)

  ```sh
  # (c't magazine, page "Impressum") [1]
  ```
  
  ```sh
  gpg2 --recv-keys <keyid_from_magazine>
  gpg2 --fingerprint pgpCA@ct.heise.de # [2]
  ```
  
  Check public key against known signatures
  ```sh
  # No output <=> Bad public key
  gpg2 --check-sigs "owner@domain.tld" | grep -E -e 'sig\!(.*)pgpCA@ct.heise.de'
  ```

#### Built-in keyring<sup>[1](#footnote1)</sup>

Check a public key against a "built-in" keyring ..

* [Debian](https://packages.debian.org/sid/debian-keyring)
  
  .. authenticated by APT
  ```sh
  # https://wiki.debian.org/DebianMaintainer#step_4_:_Account_creation
  apt-get download debian-keyring # ~50MB (!)
  dpkg-deb -x debian-keyring*.deb keyring
  gpg2 --keyring=./keyring/usr/share/keyrings/debian-keyring.gpg --check-sigs owner@domain.tld
  ```
  
  > On the output, the status of the verification is indicated by a flag directly following the "sig" tag.
  **A "!" indicates that the signature has been successfully verified,**
  a "-" denotes a bad signature
  and a "%" is used if an error occurred while checking the signature (e.g. a non supported algorithm).

#### DNSSEC/OPENPGPKEY
[TODO](https://sys4.de/de/blog/2015/02/26/pgp-schluessel-einfach-und-sicher-verteilen/)

#### Web-/Keyserver

Compare the fingerprint between two online sources:

##### Webserver [1]

```sh
# TODO: DNSSEC/TLSA
# TODO: https://testssl.sh/
# If there's no SSL/TLS support you may use at least somehting like:
# https://proxy.suma-ev.de/cgi-bin/proxy/nph-proxy.cgi/
# Option A
curl --tlsv1.2 "https://domain.tld/public_key.asc" | gpg2 --with-fingerprint # [1]
# Option B
curl --tlsv1.2 "https://domain.tld/fingerprint.html" | grep -e 'fingerprint =' -C 1 # [1]
```

##### Keyserver [2]

```sh
gpg2 --search-key owner@domain.tld
```

> There should exist **only one single (not expired/revoked) key** on the keyserver.

> If there are more (not expired/revoked) keys with the same name,
you can't ensure which is right,
because someone could have hijacked the webserver [1] and uploaded his [faked key](http://www.heise.de/ct/ausgabe/2015-6-Gefaelschte-PGP-Keys-im-Umlauf-2549724.html) [2].

A supportive strategy could be to explore **who has signed** the public key:
```
gpg2 --list-sigs owner@domain.tld
# Show sigs' name
curl --cacert "$HOME/certs/hkps.pool.sks-keyservers.net.pem" --tlsv1.2 "https://hkps.pool.sks-keyservers.net/pks/lookup?op=vindex&fingerprint=on&exact=on&search=<keyid>"
```

```sh
gpg2 --fingerprint owner@domain.tld # [2]
```
BTW: Look for the owner on whois, legal info etc...

### Show PGP-packet's human-readable content
```sh
# alternative to pgpdump (gpg v1.4):
# gpg --list-packets --verbose --debug 0x02
pgpdump signature.asc
```
Example: Get signer's public key
```sh
gpg2 --recv-keys <keyid_from_pgpdump>
```

### Import key from WWW to GnuPG
```sh
wget -O - https://domain.tld/public.key | gpg2 --import
```

### Move key from GnuPG to APT keyring
```sh
# https://wiki.debian.org/SecureApt#How_to_find_and_add_a_key
gpg2 -a --export '<keyid>' | sudo apt-key add -
# Delete from gpg keyring
gpg2 --delete-key <keyid>
```

### Check signature
```sh
# Check signature, e.g. .gpg, .asc, .sig
# gpg: Good signature from ..
gpg2 --verify sha256sum.gpg sha256sum.txt
gpg2 --verify SHA1SUM.asc
gpg2 --verify IMAGE.iso.sig IMAGE-vXX.iso
```

### Verify checksum
```sh
# Read checksums from the file and check them
# No output <=> Broken file(s)
sha256sum -c sha256sum.txt 2>/dev/null | grep -e 'OK$'
```


## Repositories

### [JonDo](https://prism-break.org/en/projects/jondofox/)

**Method**: [Web-/Keyserver](#web-keyserver)
* https://anonymous-proxy-servers.net/en/help/firststeps2.html
```sh
# Option A
curl --tlsv1.2 "https://anonymous-proxy-servers.net/downloads/JonDos_GmbH.asc" | gpg2 --with-fingerprint # [1]
# Option B
curl --tlsv1.2 "https://anonymous-proxy-servers.net/en/help/firststeps2.html" | grep -e 'fingerprint =' -C 1 # [1]

gpg2 --search-key info@jondos.de
gpg2 --fingerprint info@jondos.de # [2]
```

```sh
gpg2 -a --export 'info@jondos.de' | sudo apt-key add -
gpg2 --delete-key info@jondos.de
```

```sh
# Add source
sudo sh -c "echo 'deb https://debian.anonymous-proxy-servers.net DISTRI main' >> /etc/apt/sources.list.d/jondo.list"
# Replace DISTRI by the name of your distribution.
# User of Linux Mint (Debian edition) may use sid to replace DISTRI.
sudo aptitude update
```

### [ownCloud](https://prism-break.org/en/projects/owncloud/)

Browse through [OpenSUSE Build Service](https://en.wikipedia.org/wiki/Open_Build_Service):
```
* Account
  https://build.opensuse.org/search
  * https://build.opensuse.org/project/show/isv:ownCloud
    * Package
      https://build.opensuse.org/project/subprojects/isv:ownCloud
      * Desktop-Client
        https://build.opensuse.org/project/show/isv:ownCloud:desktop#raw_packages
        * https://build.opensuse.org/package/show/isv:ownCloud:desktop/owncloud-client
          * Instructions
            https://software.opensuse.org/download.html?project=isv%3AownCloud%3Adesktop&package=owncloud-client
```

**Method**: [Web-/Keyserver](#web-keyserver)
```sh
curl --tlsv1.2 "https://proxy.suma-ev.de/cgi-bin/proxy/nph-proxy.cgi/en/-0/http/download.opensuse.org/repositories/isv:/ownCloud:/desktop/Debian_8.0/Release.key" | gpg2 --with-fingerprint # [1]

gpg2 --search-key isv:ownCloud
gpg2 --fingerprint isv:ownCloud # [2]
```

```sh
gpg2 -a --export isv:ownCloud | sudo apt-key add -
gpg2 --delete-key isv:ownCloud
```

```sh
# Add source
sudo sh -c "echo 'deb http://download.opensuse.org/repositories/isv:/ownCloud:/desktop/Debian_8.0/ /' >> /etc/apt/sources.list.d/owncloud-client.list"
sudo aptitude update
```


## Disc images

### [JonDo Live](https://prism-break.org/en/projects/jondo-live-cd/)

**Download**
```sh
# https://anonymous-proxy-servers.net/en/jondo-live-cd.html
wget https://downloads.anonymous-proxy-servers.net/jondo-live-dvd.iso
```

**Method**: [Web-/Keyserver](#web-keyserver) **[I]**
* https://anonymous-proxy-servers.net/en/help/install_pgp_signaturen.html
```sh
# Option A
curl --tlsv1.2 "https://anonymous-proxy-servers.net/downloads/Software_JonDos_GmbH.asc" | gpg2 --with-fingerprint # [1]
# Option B
curl --tlsv1.2 "https://anonymous-proxy-servers.net/en/help/install_pgp_signaturen.html" | grep -e 'fingerprint:' -C 1 # [1]

gpg2 --search-key software@jondos.de
gpg2 --fingerprint software@jondos.de # [2]
```

**Method**: [Web-/Keyserver](#web-keyserver) **[II]**
* https://www.privacy-handbuch.de/handbuch_24o.htm
```sh
# Option A
curl --tlsv1.2 "https://www.privacy-handbuch.de/download/software_at_privacy-handbuch.de_pub.asc" | gpg2 --with-fingerprint # [1]
# Option B
curl --tlsv1.2 "https://www.privacy-handbuch.de/handbuch_24o.htm" | grep -e 'Fingerabdruck:' -C 1 # [1]

gpg2 --search-key software@privacy-handbuch.de
gpg2 --fingerprint software@privacy-handbuch.de # [2]
```

```sh
# Verify ISO
gpg2 --verify jondo-live-dvd.iso.asc
```

### Kali

**Beginners' guide**
* [LinuxUser](https://www.linux-user.de/Community-Edition/) magazine: [#1](http://www.linux-community.de/34357) [#2](http://www.linux-community.de/34358) ..

**Download**
```sh
wget --no-directories --no-parent --reject "index.html*" --recursive http://cdimage.kali.org/kali-2.0/
```

**Method**: [Web-/Keyserver](#web-keyserver)
* https://www.kali.org/downloads/
```sh
# Option A
curl --tlsv1.2 "https://www.kali.org/archive-key.asc" | gpg2 --with-fingerprint # [1]
# Option B
# It's the server's fault that we use the option --compressed here
# If curl did not pass an "Accept-Encoding: gzip" request-header,
# the server should not send a compressed response.
curl --compressed --tlsv1.2 "https://www.kali.org/downloads/" | grep -e 'fingerprint =' -C 1 # [1]

gpg2 --search-key devel@kali.org
gpg2 --fingerprint devel@kali.org # [2]
```

```sh
# Verify ISO
gpg2 --verify SHA1SUMS.gpg
sha1sum -c SHA1SUMS
```

### Knoppix

```sh
pgpdump KNOPPIX_*.iso.sha1.asc
gpg2 --recv-keys <keyid_from_pgpdump>
```

**Method**: [Certification Authorities - c't](#certification-authorities)
* http://www.openpgp-schulungen.de/teilnehmer/knoppix/
```sh
# (c't magazine, page "Impressum") [1]
gpg2 --recv-keys <keyid_from_magazine>
gpg2 --fingerprint pgpCA@ct.heise.de # [2]

gpg2 --check-sigs "info@knopper.net" | grep -E -e 'sig\!(.*)pgpCA@ct.heise.de'
```

```sh
# Verify ISO
gpg2 --verify KNOPPIX_*.iso.sha1.asc
sha1sum -c KNOPPIX_*.iso.sha1 2>/dev/null | grep -e 'OK$'
```

### LMDE / Mint
```sh
# Get public key
# Select "Linux Mint Package Repository"
gpg2 --search-key root@linuxmint.com

# Investigate key
gpg2 --list-sigs root@linuxmint.com
# Show sigs' name
curl --cacert "$HOME/certs/hkps.pool.sks-keyservers.net.pem" --tlsv1.2 "https://hkps.pool.sks-keyservers.net/pks/lookup?op=vindex&fingerprint=on&exact=on&search=<keyid>"
```

```sh
# Verify ISO
gpg2 --verify sha256sum.txt.gpg
sha256sum -c sha256sum.txt 2>/dev/null | grep -e 'OK$'
```

### [Tails](https://prism-break.org/en/projects/tails/)

**Beginners' guide**
* https://capulcu.blackblogs.org/bandi/

**Download**
```sh
wget --no-directories --no-parent --accept sig,torrent --recursive --https-only --secure-protocol=PFS https://tails.boum.org/torrents/files/
wget --no-directories --no-parent --accept iso --recursive http://dl.amnesia.boum.org/tails/stable/
```

```sh
wget -O - https://tails.boum.org/tails-signing.key | gpg2 --import
```

**Method**: [Built-in keyring - Debian](#built-in-keyring1)
* https://tails.boum.org/download/index.en.html
* https://tails.boum.org/news/signing_key_transition/index.en.html
* https://tails.boum.org/doc/get/trusting_tails_signing_key/index.en.html#debian
```sh
apt-get download debian-keyring
dpkg-deb -x debian-keyring*.deb keyring
gpg2 --keyring=./keyring/usr/share/keyrings/debian-keyring.gpg --check-sigs tails@boum.org
```

```sh
# Verify ISO
gpg --verify tails-i386-*.iso.sig
```


## Misc

* [Cryptographic Algorithms - Cheat Sheet](http://if-is.net/crypto-poster/)
* [Offline Passphrase Generator](https://en.wikipedia.org/wiki/Diceware)
  * [Animated HowTo](https://ssd.eff.org/en/module/animated-overview-how-make-super-secure-password-using-dice)

[![xkcd: Password Strength](http://imgs.xkcd.com/comics/password_strength.png)](https://xkcd.com/936/)
*by [xkcd](https://xkcd.com/936/)*

### [Generate key](https://ssl.webpack.de/www.openpgp-courses.org/)
*Based on a work by Hauke Laging*

* [Description](https://ssl.webpack.de/www.openpgp-schulungen.de/scripte/)
  * [Keygeneration](https://ssl.webpack.de/www.openpgp-schulungen.de/scripte/keygeneration/)
* [Prep](https://ssl.webpack.de/www.openpgp-schulungen.de/inhalte/einrichtung/teilnahme/)
* [Overview](https://ssl.webpack.de/www.openpgp-schulungen.de/kurzinfo/)
  * [Quality](https://ssl.webpack.de/www.openpgp-schulungen.de/kurzinfo/schluesselqualitaet/)
* [Terms and definitions](https://ssl.webpack.de/www.openpgp-schulungen.de/glossar/)
  * [lckey](https://ssl.webpack.de/www.openpgp-schulungen.de/glossar/lckey/)
* Quick guides, slides [#1](https://ssl.webpack.de/www.openpgp-schulungen.de/inhalte/einrichtung/materialien/)
  [#2](https://ssl.webpack.de/www.openpgp-schulungen.de/teilnehmer/)

#### System: Online
Data to carry (CD, USB-Stick) to the offline-system
```sh
# http://www.heise.de/security/dienste/PGP-Schluessel-der-c-t-CA-473386.html
wget http://www.heise.de/security/dienste/pgp/keys/daffb000.asc

# https://ssl.webpack.de/www.openpgp-schulungen.de/kontakt/
wget https://ssl.webpack.de/www.openpgp-schulungen.de/users/0x5A21B2D0.asc

# https://ssl.webpack.de/www.openpgp-schulungen.de/download/
wget https://ssl.webpack.de/www.openpgp-schulungen.de/download/openpgp-scripte.tgz
wget https://ssl.webpack.de/www.openpgp-schulungen.de/download/openpgp-scripte.tgz.asc
```

#### System: Offline (e.g. [Knoppix](#knoppix))
* [Instructions for Knoppix](https://ssl.webpack.de/www.openpgp-schulungen.de/inhalte/einrichtung/materialien/knoppix-anleitung/)

```sh
gpg2 --import 0x5A21B2D0.asc daffb000.asc
```

**Method**: [Certification Authorities - c't](#certification-authorities)
```sh
# (c't magazine, page "Impressum") [1]
gpg2 --fingerprint pgpCA@ct.heise.de # [2]

gpg2 --check-sigs "0x5A21B2D0" | grep -E -e 'sig\!(.*)pgpCA@ct.heise.de'
```

```sh
# Verify scripts
gpg2 --verify openpgp-scripte.tgz.asc
```

### Smartcard

* https://wiki.fsfe.org/Card_howtos/Card_with_subkeys_using_backups
* https://www.unitas-network.de/wissenswertes/anleitungen/smartcards
* https://privacy-handbuch.de/handbuch_32r.htm
* http://wiki.gnupg.org/SmartCard


***
<a name="footnote1">1</a>: Actually it's not really important to get the public key on a secure way.


***
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/80x15.png" /></a><br />This <span xmlns:dct="http://purl.org/dc/terms/" href="http://purl.org/dc/dcmitype/Text" rel="dct:type">work</span> by <span xmlns:cc="http://creativecommons.org/ns#" property="cc:attributionName">m3t (96bd6c8bb869fe632b3650fb7156c797ef8c2a055d31dde634565f3edda485ba) &lt;mlt [at] posteo [dot] de&gt;</span> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.
