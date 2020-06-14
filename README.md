# Décode balise avec un ESP32

Packet sniffer
  
Reçoit et décode les données émises par une balise et les affiche dans la console.

Fonctionne avec une carte à base d'ESP32 et https://github.com/esp8266/Arduino

Limitation du SDK, la trame ne peut être décodée en totalité : ID, LAT, LONG et AlTmsl si le ssid est court
