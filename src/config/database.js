const mysql = require('mysql2/promise');

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ias_auth',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Test the connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('Database connection established successfully');
    
    // Test if we can actually query the database
    const [tables] = await connection.query('SHOW TABLES');
    console.log('Available tables:', tables.map(t => Object.values(t)[0]));
    
    // Test if we can access the otp_history table specifically
    const [otpTable] = await connection.query('SHOW TABLES LIKE "otp_history"');
    if (otpTable.length > 0) {
      console.log('OTP history table exists');
      
      // Test if we can query the table
      const [structure] = await connection.query('DESCRIBE otp_history');
      console.log('OTP table structure:', structure);
    } else {
      console.log('Warning: OTP history table does not exist');
    }
    
    connection.release();
    return true;
  } catch (error) {
    console.error('Detailed database connection error:', error);
    console.error('Error code:', error.code);
    console.error('Error number:', error.errno);
    console.error('SQL state:', error.sqlState);
    return false;
  }
}

module.exports = { pool, testConnection }; 