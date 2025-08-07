# Das Skipt analysiert die access.log des ngix auf verdächtige Aktivitäten
## Was das Skript erkennt:
- HTTP-Fehlercodes wie 4xx, 5xx (z. B. 404, 500)
- Viele Anfragen von einer IP (mögliche Brute-Force oder Scan-Versuche)
- Verdächtige User-Agents (z. B. sqlmap, nikto, curl, etc.)
- POST/GET-Requests (z. B. unerwartete Loginversuche)
- Zugriffe auf Admin-, Login- oder Setup-Seiten
- Requests mit verdächtigen Parametern (?cmd=, ?id=1'--, etc.)
### Neu hinzugefügt: 
-Abfrage auf den Ländercode der ip-Adressen.
-Datum/Uhrzeit der Anfragen

## Der Aufruf benötigt root (sudo)-Rechte, um an die access.log zu kommen.
#ngix #python #access.log
