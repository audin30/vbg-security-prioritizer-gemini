#!/usr/bin/env node
/**
 * Google Chat Notification Script
 * 
 * Usage: node send_chat.cjs <webhook_url> <message_text>
 */

'use strict';

const axios = require('axios');

async function sendChatMessage() {
  const [webhookUrl, message] = process.argv.slice(2);

  if (!webhookUrl || !message) {
    console.error('Usage: node send_chat.cjs <webhook_url> <message_text>');
    process.exit(1);
  }

  try {
    const payload = {
      text: message
    };

    const response = await axios.post(webhookUrl, payload, {
      headers: { 'Content-Type': 'application/json; charset=UTF-8' }
    });

    if (response.status === 200) {
      console.log('Success: Message sent to Google Chat.');
    } else {
      console.error(`Error: Google Chat API returned status ${response.status}`);
      process.exit(1);
    }
  } catch (error) {
    console.error('Error sending message to Google Chat:', error.response ? error.response.data : error.message);
    process.exit(1);
  }
}

sendChatMessage();
