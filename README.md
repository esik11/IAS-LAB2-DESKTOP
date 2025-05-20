# IAS Authentication Desktop Application

## Overview
This is an Electron-based desktop application that implements a secure Multi-Factor Authentication (MFA) system. The application provides user registration and login functionality with added security through OTP (One-Time Password) verification and backup codes.

## Features
- User registration with email verification
- Secure login with password authentication
- Multi-Factor Authentication (MFA) using OTP
- Backup codes generation for account recovery
- In-memory OTP storage for testing and development

## Technologies Used
- Electron for desktop application framework
- Node.js for backend operations
- Firebase for email verification
- MySQL for user data storage
- Nodemailer for email delivery (configured for testing)
- Speakeasy for OTP generation
- bcryptjs for password hashing
- JWT for token-based authentication

## Setup Instructions
1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Configure the database connection in your environment variables or create a `.env` file with the following:
   ```
   DB_HOST=your_host
   DB_USER=your_user
   DB_PASSWORD=your_password
   DB_DATABASE=your_database
   
   FIREBASE_API_KEY=your_firebase_api_key
   FIREBASE_AUTH_DOMAIN=your_firebase_auth_domain
   FIREBASE_PROJECT_ID=your_firebase_project_id
   
   EMAIL_USER=your_email_address
   EMAIL_PASS=your_email_password
   ```

4. Start the application:
   ```
   npm start
   ```

## MFA Implementation Details
The application implements MFA through the following mechanisms:

### Registration Process
1. User provides email and password
2. Email verification is sent via Firebase
3. Once verified, user can complete registration
4. Backup codes are generated and displayed for account recovery

### Login Process
1. User enters email and password for primary authentication
2. Upon successful primary authentication, OTP verification is required
3. OTP is generated and (in production) sent to user's email
4. For testing purposes, OTP is displayed in the console
5. User enters OTP to complete authentication

### OTP Implementation
- The system uses an in-memory approach to store OTPs for testing
- OTPs are time-based and expire after a short period
- Console logging is enabled for testing purposes to display OTPs

### Backup Codes
- Generated during user registration
- Securely stored in the database
- Can be used in place of OTP if user cannot receive emails

## Known Issues and Workarounds
- Database connectivity issues with OTP storage: Implemented in-memory storage as a workaround
- Email delivery challenges: Console logging implemented for testing purpose
- For testing purposes, OTPs are displayed in the console rather than being delivered via email

## Future Improvements
- Implement proper email delivery in production
- Enhance database reliability for OTP storage
- Add user interface for backup code management
- Add password reset functionality

## License
MIT 