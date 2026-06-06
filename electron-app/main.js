// ─────────────────────────────────────────────────────────────
// VulnScan5G – Electron Main Process
// Spawns the Python API server, waits for readiness, then
// loads the renderer UI in a frameless dark-themed window.
// ─────────────────────────────────────────────────────────────

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path  = require('path');
const { spawn } = require('child_process');
const http  = require('http');

// ── Globals ──────────────────────────────────────────────────
let mainWindow    = null;
let splashWindow  = null;
let pythonProcess = null;

const API_URL        = 'http://localhost:8765';
const POLL_INTERVAL  = 500;   // ms between readiness checks
const MAX_POLL_TIME  = 60000; // give up after 60 s (bundled exe may take longer)

// ── Python Server Management ─────────────────────────────────

/**
 * Resolve the path to the Python server executable.
 * - Packaged (production): uses the PyInstaller-bundled exe in extraResources
 * - Development: falls back to spawning `python api_server.py`
 */
function getServerCommand() {
  if (app.isPackaged) {
    // In production, the PyInstaller bundle is in resources/vulnscan5g-server/
    const serverExe = path.join(
      process.resourcesPath,
      'vulnscan5g-server',
      'vulnscan5g-server.exe'
    );
    return { command: serverExe, args: [], cwd: path.dirname(serverExe) };
  }
  // Development mode: use Python directly
  const projectRoot = path.join(__dirname, '..');
  return { command: 'python', args: ['api_server.py'], cwd: projectRoot };
}

/**
 * Spawn the Python API server as a child process.
 * Automatically picks the right executable based on whether
 * the app is packaged or running in development mode.
 */
function startPythonServer() {
  const { command, args, cwd } = getServerCommand();
  console.log(`[main] Starting server: ${command} ${args.join(' ')} (cwd: ${cwd})`);

  pythonProcess = spawn(command, args, {
    cwd: cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Forward server stdout / stderr to the Electron console for
  // debugging during development.
  pythonProcess.stdout.on('data', (data) => {
    console.log(`[python] ${data.toString().trim()}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[python:err] ${data.toString().trim()}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`[python] process exited with code ${code}`);
    pythonProcess = null;
  });

  pythonProcess.on('error', (err) => {
    console.error(`[main] Failed to start server: ${err.message}`);
    pythonProcess = null;
  });
}

/**
 * Poll the /config endpoint until the server responds with 200,
 * then resolve.  Rejects after MAX_POLL_TIME milliseconds.
 */
function waitForServer() {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const poll = () => {
      const req = http.get(`${API_URL}/config`, (res) => {
        // Consume the response body so the socket is freed
        res.resume();
        if (res.statusCode === 200) {
          resolve();
        } else {
          scheduleNext();
        }
      });

      req.on('error', () => scheduleNext());
      req.setTimeout(POLL_INTERVAL, () => {
        req.destroy();
        scheduleNext();
      });
    };

    const scheduleNext = () => {
      if (Date.now() - startTime > MAX_POLL_TIME) {
        reject(new Error('Python API server did not become ready in time'));
        return;
      }
      setTimeout(poll, POLL_INTERVAL);
    };

    poll();
  });
}

/**
 * Gracefully kill the Python child process (if running).
 */
function killPythonServer() {
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
}

// ── Splash Window ────────────────────────────────────────────

/**
 * Create a small branded splash window shown while the Python
 * server is starting. Gives the user visual feedback instead of
 * a blank screen during the 5-30 second startup.
 */
function createSplashWindow() {
  splashWindow = new BrowserWindow({
    width: 400,
    height: 340,
    frame: false,
    transparent: false,
    backgroundColor: '#0f0f1a',
    resizable: false,
    alwaysOnTop: true,
    center: true,
    skipTaskbar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  splashWindow.loadFile(path.join(__dirname, 'src', 'splash.html'));

  splashWindow.on('closed', () => {
    splashWindow = null;
  });
}

// ── Window Creation ──────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width:  1280,
    height: 850,
    backgroundColor: '#0f0f1a',
    frame: true,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0f0f1a',
      symbolColor: '#ffffff',
      height: 36,
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    show: false, // avoid a white flash – show once content is ready
    icon: path.join(__dirname, 'assets', 'icon.ico'),
  });

  // Show the window and close splash once the renderer is ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (splashWindow && !splashWindow.isDestroyed()) {
      splashWindow.close();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ── IPC Handlers ─────────────────────────────────────────────

function registerIpcHandlers() {
  // Let the renderer ask the user to pick a folder
  ipcMain.handle('select-folder', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory'],
    });
    return canceled ? null : filePaths[0];
  });

  // Let the renderer ask the user to pick a C/C++ source file
  ipcMain.handle('select-file', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      filters: [
        { name: 'C/C++ Files', extensions: ['c', 'cpp', 'h', 'hpp', 'cc', 'cxx'] },
      ],
    });
    return canceled ? null : filePaths[0];
  });

  // Let the renderer ask the user to pick a save location
  ipcMain.handle('select-save-folder', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory', 'createDirectory'],
      title: 'Choose where to save fixed files',
    });
    return canceled ? null : filePaths[0];
  });

  // Open a URL in the user's default browser
  ipcMain.handle('open-external', async (_event, url) => {
    if (typeof url === 'string' && url.startsWith('http')) {
      await shell.openExternal(url);
    }
  });
}

// ── App Lifecycle ────────────────────────────────────────────

app.whenReady().then(async () => {
  registerIpcHandlers();

  // 1. Show splash screen immediately
  createSplashWindow();

  // 2. Create the main window (hidden until content is ready)
  createWindow();

  // 3. Spawn the Python API server
  startPythonServer();

  // 4. Wait until it responds on /config
  try {
    await waitForServer();
    console.log('[main] Python API server is ready');
  } catch (err) {
    console.error('[main]', err.message);
    // Still load the UI so the user sees a meaningful error
  }

  // 5. Load the renderer — mainWindow.show() + splash close
  //    is triggered by 'ready-to-show' event set in createWindow()
  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));
});

// Quit when all windows are closed (Windows & Linux behaviour)
app.on('window-all-closed', () => {
  killPythonServer();
  app.quit();
});

// Clean up the Python process when Electron exits
app.on('before-quit', () => {
  killPythonServer();
});
