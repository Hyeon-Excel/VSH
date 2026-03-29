import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import * as path from 'path';
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';

let mainWindow: BrowserWindow;
let apiProcess: ChildProcessWithoutNullStreams | null = null;

const isDev = process.env.NODE_ENV === 'development';
const shouldAutoStartApi = (process.env.VSH_AUTO_START_API || 'true').toLowerCase() !== 'false';

function resolveProjectRoot(): string {
  // main.ts lives in vsh_desktop. Dist output also stays under vsh_desktop.
  return path.resolve(__dirname, '..');
}

function startApiServer() {
  if (!shouldAutoStartApi || apiProcess) {
    return;
  }

  const projectRoot = resolveProjectRoot();
  const pythonCommand = process.platform === 'win32' ? 'python' : 'python3';
  const args = ['-m', 'uvicorn', 'vsh_api.main:app', '--host', '127.0.0.1', '--port', '3000'];

  apiProcess = spawn(pythonCommand, args, {
    cwd: projectRoot,
    env: { ...process.env, PYTHONPATH: projectRoot },
    stdio: 'pipe',
  });

  apiProcess.stdout.on('data', (data) => {
    console.log(`[VSH API] ${data.toString().trim()}`);
  });

  apiProcess.stderr.on('data', (data) => {
    console.error(`[VSH API] ${data.toString().trim()}`);
  });

  apiProcess.on('exit', (code) => {
    console.log(`[VSH API] process exited with code ${code}`);
    apiProcess = null;
  });
}

function stopApiServer() {
  if (!apiProcess) {
    return;
  }

  if (process.platform === 'win32') {
    spawn('taskkill', ['/pid', String(apiProcess.pid), '/f', '/t']);
  } else {
    apiProcess.kill('SIGTERM');
  }

  apiProcess = null;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist-react/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null!;
  });
}

ipcMain.handle('dialog:openFile', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [{ name: 'Python Files', extensions: ['py'] }],
  });
  return result.filePaths[0];
});

ipcMain.handle('dialog:openDirectory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
  });
  return result.filePaths[0];
});

app.on('ready', () => {
  startApiServer();
  createWindow();
});

app.on('before-quit', () => {
  stopApiServer();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
