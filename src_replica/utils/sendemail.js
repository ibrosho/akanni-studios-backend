const nodemailer = require('nodemailer');

/**
 * @util sendEmail
 * @description Reusable Nodemailer transporter for Akanni Studios.
 * All SMTP credentials are sourced exclusively from environment variables.
 * Eliminates the security anti-pattern of hardcoded credentials in controllers.
 *
 * @param {Object} options
 * @param {string} options.to      - Recipient email address.
 * @param {string} options.subject - Email subject line.
 * @param {string} options.text    - Plaintext fallback body.
 * @param {string} [options.html]  - Optional HTML body (takes priority if provided).
 *
 * @throws Will throw if SMTP transport fails — callers should wrap in try/catch.
 */
const sendEmail = async ({ to, subject, text, html }) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false, // Use STARTTLS (port 587)
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
    connectionTimeout: 2500, // 2.5 seconds connection timeout
    greetingTimeout: 2500,   // 2.5 seconds greeting timeout
    socketTimeout: 4000,     // 4 seconds socket inactivity timeout
  });

  const mailOptions = {
    from: `"${process.env.SMTP_FROM_NAME || 'Akanni Studios'}" <${process.env.SMTP_USER}>`,
    to,
    subject,
    text,
    ...(html && { html }),
  };

  const info = await transporter.sendMail(mailOptions);

  if (process.env.NODE_ENV !== 'production') {
    console.log(`[MAIL] Message sent: ${info.messageId} → ${to}`);
  }

  return info;
};

module.exports = sendEmail;
