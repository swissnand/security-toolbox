// Schmale, sichere Brücke: Die Oberfläche bekommt keinen Node-Zugriff,
// nur diese fest definierten, lesenden Funktionen des Hauptprozesses.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('toolbox', {
  platform: process.platform,
  isApp: true,
  get: (url, opts) => ipcRenderer.invoke('net:get', url, opts || {}),
  probe: (url, opts) => ipcRenderer.invoke('net:probe', url, opts || {}),
  tlsVersions: (host, port) => ipcRenderer.invoke('net:tls-versions', host, port || 443),
  macAudit: () => ipcRenderer.invoke('mac:audit'),
});
