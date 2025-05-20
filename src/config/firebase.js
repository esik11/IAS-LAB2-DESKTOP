const { initializeApp } = require('firebase/app');
const { getAuth } = require('firebase/auth');
const { getFirestore } = require('firebase/firestore');
require('dotenv').config();

// Your Firebase configuration
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  databaseURL: process.env.FIREBASE_DATABASE_URL,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID
};

// Validate required configuration
const requiredFields = ['apiKey', 'authDomain', 'projectId'];
for (const field of requiredFields) {
  if (!firebaseConfig[field]) {
    throw new Error(`Missing required Firebase configuration: ${field}`);
  }
}

let app, auth, db;

try {
  // Initialize Firebase
  app = initializeApp(firebaseConfig);
  auth = getAuth(app);
  db = getFirestore(app);
} catch (error) {
  console.error('Firebase initialization error:', error);
  throw error;
}

module.exports = { app, auth, db }; 