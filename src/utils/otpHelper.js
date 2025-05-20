const { pool } = require('../config/database');

// Standalone function to verify OTP without using the User model
async function verifyOTP(userId, otp, otpType = 'LOGIN') {
  try {
    console.log('*** Verifying OTP using standalone helper ***');
    console.log('Params:', { userId, otp, otpType });
    
    // Use a simple query that doesn't include problematic SQL
    const [rows] = await pool.query(`
      SELECT id 
      FROM otp_history 
      WHERE user_id = ? 
      AND otp = ? 
      AND otp_type = ?
      AND is_used = FALSE 
      AND expires_at > NOW()
    `, [userId, otp, otpType]);
    
    if (rows.length === 0) {
      console.error('OTP not found or expired');
      return false;
    }
    
    console.log('Found valid OTP with ID:', rows[0].id);
    
    // Mark OTP as used
    await pool.query(`
      UPDATE otp_history SET is_used = TRUE, used_at = NOW()
      WHERE id = ?
    `, [rows[0].id]);
    
    console.log('OTP verified successfully');
    return true;
  } catch (error) {
    console.error('Error verifying OTP:', error);
    return false;
  }
}

module.exports = { verifyOTP }; 