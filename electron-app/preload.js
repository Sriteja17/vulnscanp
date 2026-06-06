// ─────────────────────────────────────────────────────────────
// VulnScan5G – Preload Script
// Runs in a sandboxed context before the renderer loads.
// Exposes a minimal, safe API to the renderer via
// contextBridge so that nodeIntegration stays disabled.
// ─────────────────────────────────────────────────────────────

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  /**
   * Open a native folder-picker dialog.
   * @returns {Promise<string|null>} Absolute path or null if cancelled.
   */
  selectFolder: () => ipcRenderer.invoke('select-folder'),

  /**
   * Open a native file-picker dialog filtered to C/C++ sources.
   * @returns {Promise<string|null>} Absolute path or null if cancelled.
   */
  selectFile: () => ipcRenderer.invoke('select-file'),

  /**
   * Open a URL in the user's default web browser.
   * @param {string} url - The URL to open.
   */
  openExternal: (url) => ipcRenderer.invoke('open-external', url),

  /**
   * Open a native folder-picker for choosing where to save fixed files.
   * @returns {Promise<string|null>} Absolute path or null if cancelled.
   */
  selectSaveFolder: () => ipcRenderer.invoke('select-save-folder'),

  /**
   * The host operating-system platform string
   * (e.g. 'win32', 'darwin', 'linux').
   */
  platform: process.platform,
});
