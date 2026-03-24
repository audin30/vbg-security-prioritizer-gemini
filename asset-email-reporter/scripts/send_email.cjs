const nodemailer = require('nodemailer');

/**
 * Sends an email with asset data.
 * Usage: node send_email.cjs <to> <subject> <summary_text>
 */
async function sendEmail() {
  const [to, subject, body] = process.argv.slice(2);

  if (!to || !subject || !body) {
    console.error('Error: Missing required arguments: <to> <subject> <body>');
    process.exit(1);
  }

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;

  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    console.error('Error: SMTP environment variables (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS) are not set.');
    process.exit(1);
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: parseInt(SMTP_PORT, 10),
    secure: parseInt(SMTP_PORT, 10) === 465, // true for port 465, false for other ports
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });

  try {
    const info = await transporter.sendMail({
      from: `"Gemini CLI Security Analyst" <${SMTP_USER}>`,
      to,
      subject,
      text: body,
    });

    console.log(`Success: Email sent to ${to}. Message ID: ${info.messageId}`);
  } catch (error) {
    console.error('Error sending email:', error.message);
    process.exit(1);
  }
}

sendEmail();
