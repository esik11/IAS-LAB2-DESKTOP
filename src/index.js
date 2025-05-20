const { app, BrowserWindow, protocol } = require('electron');
const path = require('node:path');
const { testConnection } = require('./config/database');
const User = require('./models/User');
const Session = require('./models/Session');
const { setupIpcHandlers } = require('./utils/ipcHandlers');

// Global reference to mainWindow to prevent garbage collection
let mainWindow = null;

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

// Register app protocol before app is ready
protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { secure: true, standard: true } }
]);

// Initialize database tables
async function initDatabase() {
  try {
    // Test database connection
    const connected = await testConnection();
    if (!connected) {
      console.error('Failed to connect to the database. Please check your database configuration.');
      return false;
    }

    // Create tables
    await User.createTables();
    await Session.createTable();

    return true;
  } catch (error) {
    console.error('Database initialization error:', error.message);
    return false;
  }
}

async function createWindow() {
  try {
  // Create the browser window.
    mainWindow = new BrowserWindow({
      width: 1024,
      height: 768,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: false
    },
  });

    // Set up custom protocol to serve local files
    protocol.registerFileProtocol('app', (request, callback) => {
      const url = request.url.substr(6); // Remove 'app://'
      const decodedUrl = decodeURI(url);
      try {
        return callback(path.normalize(`${__dirname}/${decodedUrl}`));
      } catch (error) {
        console.error('Protocol error:', error);
        return callback(404);
      }
    });

    // Set up IPC handlers before loading the file
    console.log('Setting up IPC handlers...');
    setupIpcHandlers(mainWindow);
    console.log('IPC handlers setup complete');

    // Load the app
    const startUrl = path.join(__dirname, 'views/login.html');
    console.log('Loading app from:', startUrl);
    await mainWindow.loadFile(startUrl);
    console.log('Main window loaded');

    // Open DevTools in development
    if (process.env.NODE_ENV === 'development') {
  mainWindow.webContents.openDevTools();
    }

    // Handle window closed
    mainWindow.on('closed', () => {
      mainWindow = null;
    });

    // Enable logging from the renderer process
    mainWindow.webContents.on('console-message', (event, level, message, line, sourceId) => {
      const levels = ['debug', 'info', 'warning', 'error'];
      console.log(`[Renderer ${levels[level]}]:`, message);
      if (sourceId) {
        console.log('Source:', sourceId, 'Line:', line);
      }
    });

  } catch (error) {
    console.error('Error during window creation:', error);
    app.quit();
  }
}

// This method will be called when Electron has finished initialization
app.whenReady().then(async () => {
  try {
    // Initialize database
    const dbInitialized = await initDatabase();
    if (!dbInitialized) {
      console.error('Failed to initialize database. Exiting...');
      app.quit();
      return;
    }
    
    await createWindow();
  } catch (error) {
    console.error('Error during app initialization:', error);
    app.quit();
  }
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Handle activation
app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    await createWindow();
  }
});

// Handle any uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (error) => {
  console.error('Unhandled Rejection:', error);
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.
