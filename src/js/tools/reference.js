/* Wissen · Referenz — Begriffe, Ports und Meldestellen */
(() => {
  'use strict';
  const { register, util } = window.TB;
  const { esc } = util;

  const searchTable = (root, U, rows, cols, ph) => {
    root.innerHTML = `<div class="panel"><input id="f" placeholder="${esc(ph)}" style="font-size:15px"/></div><div class="panel"><div class="tbl-wrap" style="max-height:none"><table class="tbl" id="t"></table></div></div>`;
    const draw = () => {
      const q = U.q('#f').value.trim().toLowerCase();
      const r = rows.filter((x) => !q || x.join(' ').toLowerCase().includes(q));
      U.q('#t').innerHTML = `<tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr>` + r.map((x) => `<tr>${x.map((v, i) => `<td class="${i === 0 && cols[0] === 'Port' ? 'mono' : ''}" ${i === 0 ? 'style="white-space:nowrap;font-weight:600"' : ''}>${String(v).startsWith('<') ? v : esc(v)}</td>`).join('')}</tr>`).join('');
    };
    U.q('#f').addEventListener('input', draw); draw();
  };

  const GLOSSAR = [
    ['2FA / MFA', 'Zwei- bzw. Mehr-Faktor-Anmeldung: Passwort plus etwas, das man besitzt (App, Schlüssel). Stoppt die meisten Kontoübernahmen.'],
    ['APT', 'Advanced Persistent Threat: gut ausgestattete Angreifergruppe, oft staatlich, die lange unentdeckt bleibt.'],
    ['Attack Surface', 'Angriffsfläche: alles, was von aussen erreichbar ist (Websites, VPN, Mail, Cloud-Konten, Mitarbeitende).'],
    ['BACS', 'Bundesamt für Cybersicherheit (früher NCSC). Zentrale Meldestelle der Schweiz, ncsc.admin.ch.'],
    ['Backdoor', 'Versteckter Zugang, den Angreifer einrichten, um später zurückzukehren.'],
    ['Botnetz', 'Viele infizierte Geräte, die ferngesteuert z. B. Spam versenden oder DDoS-Angriffe ausführen.'],
    ['Brute Force', 'Systematisches Durchprobieren von Passwörtern. Abwehr: lange Passwörter, 2FA, Sperren nach Fehlversuchen.'],
    ['CEO-Fraud', 'Betrug, bei dem sich Täter als Chef ausgeben und dringende Überweisungen verlangen.'],
    ['CERT / CSIRT', 'Team, das auf Sicherheitsvorfälle reagiert. In der Schweiz u. a. GovCERT beim BACS.'],
    ['Credential Stuffing', 'Angreifer probieren geleakte Benutzername/Passwort-Paare bei anderen Diensten aus.'],
    ['CSP', 'Content-Security-Policy: Header, der festlegt, woher eine Website Skripte und Inhalte laden darf.'],
    ['CVE', 'Common Vulnerabilities and Exposures: weltweit eindeutige Nummer einer bekannten Schwachstelle.'],
    ['CVSS', 'Bewertungssystem für den Schweregrad von Schwachstellen (0–10).'],
    ['DDoS', 'Überlastungsangriff: Ein Dienst wird mit Anfragen geflutet, bis er nicht mehr erreichbar ist.'],
    ['DKIM', 'Digitale Signatur für E-Mails. Beweist, dass eine Mail von der Domain stammt und nicht verändert wurde.'],
    ['DMARC', 'Regel, was Empfänger mit Mails tun sollen, die SPF/DKIM nicht bestehen (none, quarantine, reject).'],
    ['DNSSEC', 'Signiert DNS-Antworten und verhindert, dass Besucher auf gefälschte Server umgeleitet werden.'],
    ['EDR / XDR', 'Endpoint Detection and Response: erkennt und stoppt verdächtiges Verhalten auf Geräten, mehr als klassischer Virenschutz.'],
    ['EDÖB', 'Eidgenössischer Datenschutz- und Öffentlichkeitsbeauftragter. Empfänger von Meldungen zu Datenschutzverletzungen.'],
    ['Exploit', 'Code oder Technik, die eine Schwachstelle ausnutzt.'],
    ['Fail2ban', 'Linux-Werkzeug, das IPs nach zu vielen Fehlanmeldungen sperrt.'],
    ['Hardening (Härtung)', 'Systeme so konfigurieren, dass möglichst wenig Angriffsfläche bleibt.'],
    ['HSTS', 'HTTP Strict Transport Security: zwingt Browser, eine Website nur noch über HTTPS aufzurufen.'],
    ['IDN-Homograph', 'Domain mit Zeichen aus anderen Alphabeten, die wie lateinische aussehen (z. B. kyrillisches «а»).'],
    ['IKT-Minimalstandard', 'Empfehlungen des Bundes zur Verbesserung der IKT-Resilienz, gegliedert in Identifizieren, Schützen, Erkennen, Reagieren, Wiederherstellen.'],
    ['Incident Response', 'Geplantes Vorgehen bei einem Sicherheitsvorfall: erkennen, eindämmen, beseitigen, wiederherstellen, lernen.'],
    ['IOC', 'Indicator of Compromise: Spur eines Angriffs, z. B. IP-Adresse, Domain, Datei-Hash.'],
    ['ISG', 'Informationssicherheitsgesetz des Bundes. Regelt u. a. die Meldepflicht für Cyberangriffe auf kritische Infrastrukturen.'],
    ['KEV', 'Known Exploited Vulnerabilities: Liste der US-Behörde CISA mit Schwachstellen, die aktiv ausgenutzt werden.'],
    ['Lateral Movement', 'Angreifer bewegen sich nach dem Einbruch von System zu System im Netzwerk.'],
    ['LAPS', 'Windows Local Administrator Password Solution: einzigartige, rotierende lokale Admin-Passwörter.'],
    ['Least Privilege', 'Jede Person und jedes System erhält nur die Rechte, die es wirklich braucht.'],
    ['Malware', 'Schadsoftware: Viren, Trojaner, Ransomware, Spyware.'],
    ['MTA-STS', 'Erzwingt verschlüsselte Zustellung von E-Mails an die eigenen Mailserver.'],
    ['nDSG / DSG', 'Schweizer Datenschutzgesetz (revidiert seit 1. September 2023).'],
    ['Passkey', 'Passwortlose Anmeldung mit kryptografischem Schlüssel auf dem Gerät. Phishing-resistent.'],
    ['Patch', 'Software-Update, das eine Schwachstelle schliesst.'],
    ['Pentest', 'Beauftragter, kontrollierter Angriff, um Schwachstellen zu finden. Nur mit schriftlicher Erlaubnis.'],
    ['Phishing', 'Gefälschte Nachrichten, die zur Eingabe von Daten oder zum Öffnen von Schadsoftware verleiten. Per SMS: Smishing, per Telefon: Vishing.'],
    ['Ransomware', 'Schadsoftware, die Daten verschlüsselt und/oder stiehlt und Lösegeld erpresst.'],
    ['SIEM', 'System, das Logs zentral sammelt und auf Angriffsmuster auswertet.'],
    ['Social Engineering', 'Manipulation von Menschen, um an Informationen oder Zugänge zu gelangen.'],
    ['SPF', 'DNS-Eintrag, der festlegt, welche Server E-Mails für eine Domain versenden dürfen.'],
    ['Supply-Chain-Angriff', 'Angriff über einen Lieferanten, Dienstleister oder eine Software-Abhängigkeit.'],
    ['Tabletop-Übung', 'Planspiel am Tisch: Das Team spielt einen Vorfall durch, ohne Technik anzufassen.'],
    ['TLS', 'Verschlüsselung für Verbindungen im Internet (das «S» in HTTPS). Aktuell: TLS 1.2 und 1.3.'],
    ['Typosquatting', 'Registrierung von Tippfehler-Domains (z. B. swissnamd.ch), um Besucher oder Mails abzufangen.'],
    ['Zero-Day', 'Schwachstelle, die ausgenutzt wird, bevor der Hersteller einen Patch hat.'],
    ['Zero Trust', 'Sicherheitsmodell: Keinem Gerät oder Benutzer automatisch vertrauen, jeden Zugriff prüfen.'],
  ];
  register({
    id: 'glossar', name: 'Security-Glossar', glyph: 'A–Z', cat: 'reference',
    desc: '50 Security-Begriffe verständlich auf Deutsch erklärt – von 2FA bis Zero Trust.',
    keywords: 'glossar begriffe erklärung wörterbuch security lexikon',
    render(root, U) { searchTable(root, U, GLOSSAR, ['Begriff', 'Erklärung'], 'Begriff suchen …'); },
  });

  const RISKY = [
    ['21', 'FTP', 'hoch', 'Unverschlüsselt. Durch SFTP (22) ersetzen.'],
    ['22', 'SSH', 'mittel', 'Nur mit Schlüssel, Fail2ban, idealerweise nur über VPN oder IP-Freigabe.'],
    ['23', 'Telnet', 'kritisch', 'Unverschlüsselt, nie ins Internet.'],
    ['25', 'SMTP', 'tief', 'Nur auf Mailservern. Offenes Relay vermeiden.'],
    ['53', 'DNS', 'mittel', 'Offene Resolver werden für DDoS missbraucht.'],
    ['80', 'HTTP', 'tief', 'Nur zur Umleitung auf HTTPS.'],
    ['110 / 143', 'POP3 / IMAP', 'hoch', 'Unverschlüsselte Varianten. 995/993 verwenden.'],
    ['135–139', 'Windows RPC/NetBIOS', 'kritisch', 'Nie ins Internet.'],
    ['161', 'SNMP', 'hoch', 'v1/v2c mit «public» verrät Netzwerkdetails.'],
    ['389 / 636', 'LDAP / LDAPS', 'kritisch', 'Verzeichnisdienst, nie öffentlich.'],
    ['443', 'HTTPS', 'tief', 'Normal. Admin-Oberflächen trotzdem nicht öffentlich.'],
    ['445', 'SMB', 'kritisch', 'Dateifreigaben. Einfallstor für WannaCry & Co. Nie ins Internet.'],
    ['500 / 4500', 'IPsec VPN', 'tief', 'VPN-Gateways aktuell halten, häufiges Angriffsziel.'],
    ['1433', 'MS SQL', 'kritisch', 'Datenbank nie direkt öffentlich.'],
    ['1723', 'PPTP', 'hoch', 'Veraltetes, unsicheres VPN.'],
    ['1900', 'UPnP/SSDP', 'hoch', 'UPnP am Router deaktivieren.'],
    ['2375 / 2376', 'Docker API', 'kritisch', 'Offene Docker-API = volle Kontrolle über den Server.'],
    ['3306', 'MySQL/MariaDB', 'kritisch', 'Nur lokal oder über privates Netz.'],
    ['3389', 'RDP', 'kritisch', 'Häufigster Einstieg für Ransomware. Nur über VPN.'],
    ['5432', 'PostgreSQL', 'kritisch', 'Nur lokal oder über privates Netz.'],
    ['5900', 'VNC', 'kritisch', 'Oft schwache Passwörter, unverschlüsselt.'],
    ['5985 / 5986', 'WinRM', 'hoch', 'Windows-Fernverwaltung, nur intern.'],
    ['6379', 'Redis', 'kritisch', 'Standardmässig ohne Passwort.'],
    ['8080 / 8443', 'Web-Admin, Proxy', 'mittel', 'Häufig vergessene Testsysteme und Admin-Panels.'],
    ['9200', 'Elasticsearch', 'kritisch', 'Viele Datenlecks durch offene Instanzen.'],
    ['10000', 'Webmin', 'hoch', 'Server-Admin-Oberfläche.'],
    ['11211', 'Memcached', 'kritisch', 'DDoS-Verstärker, Datenlecks.'],
    ['27017', 'MongoDB', 'kritisch', 'Viele Datenlecks durch offene Instanzen.'],
  ].map(([p, s, r, d]) => [p, s, `<span class="sev ${r === 'kritisch' ? 'krit' : r}">${r}</span>`, d]);
  register({
    id: 'risky-ports', name: 'Riskante Ports', glyph: ':445', cat: 'reference',
    desc: 'Welche Dienste gehören nie ins Internet? Ports mit Risiko-Einstufung und Empfehlung.',
    keywords: 'ports firewall rdp smb exposed internet risiko dienste offen',
    render(root, U) { searchTable(root, U, RISKY, ['Port', 'Dienst', 'Risiko offen im Internet', 'Empfehlung'], 'Port oder Dienst suchen …'); },
  });

  const link = (u, t) => `<a href="${u}" target="_blank" rel="noopener">${esc(t || u.replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, ''))}</a>`;
  const STELLEN = [
    ['BACS – Bundesamt für Cybersicherheit', 'Meldepflicht kritischer Infrastrukturen (24 h) und freiwillige Meldungen zu Cybervorfällen, Warnungen, Ratgeber.', link('https://www.ncsc.admin.ch', 'ncsc.admin.ch')],
    ['BACS – Meldeformular', 'Freiwillige Meldung von Vorfällen, Betrugsversuchen und Schwachstellen.', link('https://www.report.ncsc.admin.ch/de/', 'report.ncsc.admin.ch')],
    ['antiphishing.ch', 'Phishing-Seiten und -Mails melden (BACS).', link('https://www.antiphishing.ch', 'antiphishing.ch')],
    ['Polizei', 'Strafanzeige bei Erpressung, Betrug, Datendiebstahl. Notfall: 117.', '117 · Kantonspolizei'],
    ['EDÖB', 'Meldung von Datenschutzverletzungen mit hohem Risiko (Art. 24 DSG).', link('https://www.edoeb.admin.ch', 'edoeb.admin.ch')],
    ['Eigene Bank', 'Bei Zahlungsbetrug sofort anrufen. Minuten zählen.', 'Nummer auf der Notfallkarte'],
    ['Cyber-Versicherung', 'Viele Policen verlangen sofortige Meldung und vermitteln Incident-Response-Teams.', 'Police und Notfallnummer bereithalten'],
    ['Have I Been Pwned', 'Prüfen, ob E-Mail-Adressen oder Domains in Datenlecks vorkommen.', link('https://haveibeenpwned.com', 'haveibeenpwned.com')],
    ['CISA KEV', 'Liste aktiv ausgenutzter Schwachstellen.', link('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'cisa.gov/kev')],
    ['NVD', 'Nationale Schwachstellen-Datenbank (NIST) mit CVSS-Bewertungen.', link('https://nvd.nist.gov', 'nvd.nist.gov')],
  ];
  register({
    id: 'meldestellen', name: 'Meldestellen & Hilfe', glyph: 'CH', cat: 'reference',
    desc: 'Wo melden, wen anrufen? BACS, Polizei, EDÖB, antiphishing.ch und weitere Anlaufstellen.',
    keywords: 'melden meldestelle hilfe bacs ncsc polizei edöb antiphishing kontakt schweiz',
    render(root, U) { searchTable(root, U, STELLEN, ['Stelle', 'Wofür', 'Kontakt'], 'Suchen …'); },
  });
})();
