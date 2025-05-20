// See the Electron documentation for details on how to use preload scripts:
// https://www.electronjs.org/docs/latest/tutorial/process-model#preload-scripts

const { contextBridge, ipcRenderer } = require('electron');

// Helper function to wrap IPC calls with error handling
const invokeWithLogging = async (channel, data) => {
  try {
    console.log(`Invoking IPC channel: ${channel}`, data);
    const result = await ipcRenderer.invoke(channel, data);
    console.log(`IPC ${channel} result:`, result);
    return result;
  } catch (error) {
    console.error(`IPC ${channel} error:`, error);
    throw error;
  }
};

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld(
  'api', {
    // Auth methods
    login: (credentials) => invokeWithLogging('auth:login', credentials),
    register: (userData) => invokeWithLogging('auth:register', userData),
    verifyEmail: (data) => invokeWithLogging('auth:verify-email', data),
    resendVerification: (data) => invokeWithLogging('auth:resend-verification', data),
    verify2FA: (data) => invokeWithLogging('auth:verify-2fa', data),
    resend2FA: (data) => invokeWithLogging('auth:resend-2fa', data),
    logout: () => invokeWithLogging('auth:logout'),
    getCurrentUser: () => invokeWithLogging('auth:get-user-info'),
    
    // Session methods
    verifySession: () => invokeWithLogging('auth:verify-session'),
    refreshSession: (refreshToken) => invokeWithLogging('auth:refresh-session', refreshToken),
    
    // Token management
    setAccessToken: (token) => localStorage.setItem('access_token', token),
    getAccessToken: () => localStorage.getItem('access_token'),
    setRefreshToken: (token) => localStorage.setItem('refresh_token', token),
    getRefreshToken: () => localStorage.getItem('refresh_token'),
    clearTokens: () => {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    },
    
    // Navigation methods
    navigateTo: (page) => invokeWithLogging('navigateTo', page),
    
    // Event listeners
    onAuthStateChanged: (callback) => {
      const handler = (_, user) => callback(user);
      ipcRenderer.on('auth-state-changed', handler);
      return () => ipcRenderer.removeListener('auth-state-changed', handler);
    },
    onSessionExpired: (callback) => {
      const handler = () => callback();
      ipcRenderer.on('session-expired', handler);
      return () => ipcRenderer.removeListener('session-expired', handler);
    }
  }
);
