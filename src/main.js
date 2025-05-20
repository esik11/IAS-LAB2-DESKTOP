const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { setupIpcHandlers } = require('./utils/ipcHandlers');
const { checkDatabaseTables } = require('./utils/dbCheck');

// Global reference to the main window
let mainWindow;

// Create the main window
async function createWindow() {
  // Check database first
  console.log('Checking database setup...');
  await checkDatabaseTables();
  
  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 1024,
    height: 768,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // Load login screen
  mainWindow.loadFile(path.join(__dirname, 'views', 'login.html'));

  // Set up IPC handlers for communication between renderer and main process
  setupIpcHandlers(mainWindow);

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// When Electron has finished initialization and is ready to create browser windows.
app.whenReady().then(createWindow);

// Quit when all windows are closed, except on macOS.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  // On macOS it's common to re-create a window when the dock icon is clicked
  if (mainWindow === null) {
    createWindow();
  }
}); 