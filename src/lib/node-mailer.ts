import nodemailer from "nodemailer";
import "dotenv/config";
import { env } from "#configs/env.js";

let transporter: nodemailer.Transporter | null = null;

function getTransporter() {
  if (transporter) return transporter;
  const host = env.SMTP_HOST;
  const port = Number(env.SMTP_PORT || 587);
  const user = env.SMTP_USER;
  const pass = env.SMTP_USER;
  const from = env.EMAIL_FROM;
  if (!host || !user || !pass || !from) {
    throw new Error("SMTP/EMAIL env not configured");
  }
  transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });
  return transporter;
}

export async function sendEmail(email: string, subject: string, html: string) {
  const transporter = getTransporter();
  return transporter.sendMail({
    from: `<${env.EMAIL_FROM}>`,
    to: email,
    subject,
    html,
  });
}
