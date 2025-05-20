const { pool } = require('../config/database');

async function checkDatabaseTables() {
  try {
    console.log('Checking database tables...');
    
    // Check if otp_history table exists and has the right structure
    const [otpTable] = await pool.query(`
      SHOW TABLES LIKE 'otp_history'
    `);
    
    if (otpTable.length === 0) {
      console.log('Creating otp_history table...');
      await pool.query(`
        CREATE TABLE otp_history (
          id INT PRIMARY KEY AUTO_INCREMENT,
          user_id INT,
          otp VARCHAR(6) NOT NULL,
          otp_type ENUM('LOGIN', 'VERIFY_EMAIL') NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL,
          is_used BOOLEAN DEFAULT FALSE,
          used_at TIMESTAMP NULL,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);
      console.log('otp_history table created successfully');
    } else {
      console.log('otp_history table exists');
    }
    
    // Check if security_logs table exists
    const [securityTable] = await pool.query(`
      SHOW TABLES LIKE 'security_logs'
    `);
    
    if (securityTable.length === 0) {
      console.log('Creating security_logs table...');
      await pool.query(`
        CREATE TABLE security_logs (
          id INT PRIMARY KEY AUTO_INCREMENT,
          user_id INT,
          event_type VARCHAR(50) NOT NULL,
          ip_address VARCHAR(45),
          user_agent VARCHAR(255),
          details TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);
      console.log('security_logs table created successfully');
    } else {
      console.log('security_logs table exists');
    }
    
    console.log('Database check completed successfully');
    return true;
  } catch (error) {
    console.error('Database check error:', error);
    return false;
  }
}

// Export the function
module.exports = { checkDatabaseTables }; 