const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();

class EmailService {
  constructor() {
    // Force production mode to actually send emails
    this.devMode = false;
    
    console.log('Initializing email service in PRODUCTION MODE - emails will be sent');
    
    // Create transporter with hardcoded SMTP configuration
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: 'jeorgeandreielevencionado@gmail.com', // REPLACE WITH YOUR ACTUAL EMAIL
        pass: 'wzev ujry ljap nppe',    // REPLACE WITH YOUR ACTUAL APP PASSWORD
      },
    });
    
    // Test connection
    this.transporter.verify((error, success) => {
      if (error) {
        console.error('SMTP connection error:', error);
      } else {
        console.log('SMTP server is ready to send messages');
      }
    });
  }

  async sendVerificationEmail(to, userId) {
    // Log in development mode
    if (this.devMode) {
      console.log('==================================================');
      console.log('DEVELOPMENT MODE - Email would have been sent to:', to);
      console.log('Subject: Verify Your Email Address');
      console.log('Content: Verification link would be included here');
      console.log('==================================================');
      return true;
    }
    
    try {
      console.log('Attempting to send verification email to:', to);
      
      // Send actual email
      const result = await this.transporter.sendMail({
        from: `"Security Team" <${this.transporter.options.auth.user}>`,
        to: to,
        subject: 'Verify Your Email Address',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px;">
            <h2>Verify Your Email Address</h2>
            <p>Thank you for registering. Please verify your email address to continue.</p>
            <p>Click the button below to verify your email:</p>
            <div style="margin: 20px 0;">
              <a href="http://localhost:3000/verify-email?userId=${userId}" 
                 style="background-color: #4CAF50; color: white; padding: 10px 20px; 
                        text-decoration: none; border-radius: 5px;">
                Verify Email
              </a>
            </div>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
        `,
        text: `Please verify your email by clicking this link: http://localhost:3000/verify-email?userId=${userId}`
      });
      
      console.log('Verification email sent successfully:', result);
      return true;
    } catch (error) {
      console.error('Error sending verification email:', error);
      // Provide detailed error information
      if (error.code === 'EAUTH') {
        console.error('Authentication error. Check your email and password.');
      } else if (error.code === 'ESOCKET') {
        console.error('Socket error. Check your SMTP host and port.');
      } else if (error.code === 'ECONNECTION') {
        console.error('Connection error. Check your internet connection.');
      }
      return false;
    }
  }

  async sendLoginOTP(to, otp) {
    // Log in development mode
    if (this.devMode) {
      console.log('==================================================');
      console.log('DEVELOPMENT MODE - OTP EMAIL');
      console.log('To:', to);
      console.log('Subject: Your Login OTP Code');
      console.log('OTP CODE:', otp);
      console.log('==================================================');
      return true;
    }
    
    try {
      console.log('Attempting to send actual OTP email to:', to);
      
      // Send actual email
      const result = await this.transporter.sendMail({
        from: `"Security Team" <${this.transporter.options.auth.user}>`,
        to: to,
        subject: 'Your Login OTP Code',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px;">
            <h2>Your One-Time Password</h2>
            <p>Use the following OTP to complete your login:</p>
            <div style="margin: 20px 0; padding: 15px; background-color: #f5f5f5; 
                      border-radius: 5px; font-size: 24px; font-weight: bold; text-align: center;">
              ${otp}
            </div>
            <p>This code will expire in 5 minutes.</p>
            <p>If you didn't attempt to login, please secure your account immediately.</p>
          </div>
        `,
        text: `Your OTP Code is: ${otp}. This code will expire in 5 minutes.`
      });
      
      console.log('Login OTP email sent successfully:', result);
      return true;
    } catch (error) {
      console.error('Error sending login OTP email:', error);
      // Provide detailed error information
      if (error.code === 'EAUTH') {
        console.error('Authentication error. Check your email and password.');
      } else if (error.code === 'ESOCKET') {
        console.error('Socket error. Check your SMTP host and port.');
      } else if (error.code === 'ECONNECTION') {
        console.error('Connection error. Check your internet connection.');
      }
      return false;
    }
  }
}

// Create and export a singleton instance
const emailService = new EmailService();
module.exports = emailService; 