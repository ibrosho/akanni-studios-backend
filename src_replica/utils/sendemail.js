const nodemailer = require('nodemailer');
const https = require('https');

/**
 * @util sendEmail
 * @description Reusable email dispatcher. Supports Brevo REST API (free emails to anyone on Render),
 * Resend HTTP API (for testing), and Nodemailer SMTP (local fallback).
 *
 * @param {Object} options
 * @param {string} options.to      - Recipient email address.
 * @param {string} options.subject - Email subject line.
 * @param {string} options.text    - Plaintext fallback body.
 * @param {string} [options.html]  - Optional HTML body (takes priority if provided).
 *
 * @throws Will throw if transport fails — callers should wrap in try/catch.
 */
const sendEmail = async ({ to, subject, text, html }) => {
  // Option 1: Brevo REST API (Allows sending to ANY recipient for free without a custom domain)
  if (process.env.BREVO_API_KEY) {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify({
        sender: { 
          name: process.env.SMTP_FROM_NAME || 'Akanni Studios', 
          email: process.env.SMTP_USER || 'ibrosho@gmail.com' 
        },
        to: [{ email: to }],
        subject,
        htmlContent: html || text,
        textContent: text
      });

      const options = {
        hostname: 'api.brevo.com',
        port: 443,
        path: '/v3/smtp/email',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'api-key': process.env.BREVO_API_KEY,
          'Content-Length': data.length,
        },
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(body));
          } else {
            reject(new Error(`Brevo API returned status ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', (err) => { reject(err); });
      req.write(data);
      req.end();
    });
  }

  // Option 2: Resend HTTP API
  if (process.env.RESEND_API_KEY) {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify({
        from: process.env.RESEND_FROM || 'Akanni Studios <onboarding@resend.dev>',
        to,
        subject,
        text,
        ...(html && { html }),
      });

      const options = {
        hostname: 'api.resend.com',
        port: 443,
        path: '/emails',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Length': data.length,
        },
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(body));
          } else {
            reject(new Error(`Resend API returned status ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', (err) => { reject(err); });
      req.write(data);
      req.end();
    });
  }

  // Fallback to standard SMTP
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
    console.log(`[MAIL] Message sent via SMTP: ${info.messageId} → ${to}`);
  }

  return info;
};

module.exports = sendEmail;
