import * as tls from 'tls';

export interface SendMailOptions {
  user?: string;
  password?: string;
  to?: string;
  subject?: string;
  html: string;
  text?: string;
}

export interface SendMailResult {
  sent: boolean;
  simulated?: boolean;
  messageId?: string;
  error?: string;
  recipient?: string;
  deliveredAt?: string;
}

/**
 * Native Zero-Dependency SMTP Client for Yandex Mail (smtp.yandex.ru:465 SSL/TLS)
 */
export async function sendYandexMail(options: SendMailOptions): Promise<SendMailResult> {
  const user = (options.user || process.env.YANDEX_MAIL_USER || '').trim();
  const password = (options.password || process.env.YANDEX_MAIL_PASSWORD || '').trim();
  const to = (options.to || process.env.YANDEX_MAIL_TO || user || '').trim();
  const subject = options.subject || 'Отчёт безопасности uncflow';

  if (!user || !password || !to) {
    const missing = [];
    if (!user) missing.push('YANDEX_MAIL_USER');
    if (!password) missing.push('YANDEX_MAIL_PASSWORD');
    if (!to) missing.push('YANDEX_MAIL_TO');
    return {
      sent: false,
      simulated: true,
      error: `Яндекс Почта: не указаны параметры (${missing.join(', ')} в .env или настройках блока)`,
      recipient: to || 'не указан'
    };
  }

  // Ensure full email for MAIL FROM
  const fromEmail = user.includes('@') ? user : `${user}@yandex.ru`;
  const toEmail = to;

  return new Promise<SendMailResult>((resolve) => {
    let socket: tls.TLSSocket | null = null;
    let step = 0;
    let buffer = '';
    let timeoutId: NodeJS.Timeout | null = null;

    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      if (socket) {
        try { socket.end(); } catch {}
        try { socket.destroy(); } catch {}
      }
    };

    timeoutId = setTimeout(() => {
      cleanup();
      resolve({
        sent: false,
        error: 'Таймаут соединения с smtp.yandex.ru:465 (8 сек)',
        recipient: toEmail
      });
    }, 8000);

    try {
      socket = tls.connect({
        host: 'smtp.yandex.ru',
        port: 465,
        rejectUnauthorized: false
      }, () => {
        // Connected to Yandex SSL port
      });

      socket.setEncoding('utf-8');

      const sendCmd = (cmd: string) => {
        if (socket && socket.writable) {
          socket.write(cmd + '\r\n');
        }
      };

      socket.on('data', (chunk: string) => {
        buffer += chunk;
        const lines = buffer.split('\r\n');
        const lastLine = lines[lines.length - 2] || lines[lines.length - 1];

        // Multi-line SMTP responses (e.g. 250-...) are not finished until line starting with "250 "
        const isComplete = /^\d{3}\s/.test(lastLine);
        if (!isComplete) return;

        const code = parseInt(lastLine.substring(0, 3), 10);
        buffer = '';

        if (step === 0 && code === 220) {
          // Greeting received, send EHLO
          step = 1;
          sendCmd('EHLO uncflow.local');
        } else if (step === 1 && code === 250) {
          // EHLO accepted, initiate AUTH LOGIN
          step = 2;
          sendCmd('AUTH LOGIN');
        } else if (step === 2 && code === 334) {
          // Send base64 username
          step = 3;
          sendCmd(Buffer.from(fromEmail).toString('base64'));
        } else if (step === 3 && code === 334) {
          // Send base64 password
          step = 4;
          sendCmd(Buffer.from(password).toString('base64'));
        } else if (step === 4 && code === 235) {
          // Auth success, send MAIL FROM
          step = 5;
          sendCmd(`MAIL FROM:<${fromEmail}>`);
        } else if (step === 5 && code === 250) {
          // MAIL FROM ok, send RCPT TO
          step = 6;
          sendCmd(`RCPT TO:<${toEmail}>`);
        } else if (step === 6 && code === 250) {
          // RCPT TO ok, send DATA
          step = 7;
          sendCmd('DATA');
        } else if (step === 7 && code === 354) {
          // Send headers and email content
          step = 8;
          const encodedSubject = `=?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`;
          const rawMessage = [
            `From: uncflow Security <${fromEmail}>`,
            `To: <${toEmail}>`,
            `Subject: ${encodedSubject}`,
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=utf-8',
            'Content-Transfer-Encoding: 8bit',
            '',
            options.html,
            '',
            '.'
          ].join('\r\n');
          sendCmd(rawMessage);
        } else if (step === 8 && code === 250) {
          // Message accepted for delivery!
          step = 9;
          sendCmd('QUIT');
          cleanup();
          resolve({
            sent: true,
            recipient: toEmail,
            deliveredAt: new Date().toISOString(),
            messageId: lastLine.replace(/^250\s+/, '')
          });
        } else if (code >= 400) {
          cleanup();
          resolve({
            sent: false,
            error: `Ошибка SMTP Яндекса (${code}): ${lastLine}`,
            recipient: toEmail
          });
        }
      });

      socket.on('error', (err: any) => {
        cleanup();
        resolve({
          sent: false,
          error: `Ошибка сокета Яндекса: ${err.message}`,
          recipient: toEmail
        });
      });
    } catch (err: any) {
      cleanup();
      resolve({
        sent: false,
        error: `Не удалось подключиться к Яндекс Почте: ${err.message}`,
        recipient: toEmail
      });
    }
  });
}

/**
 * Formats a clean, user-friendly HTML email report without robotic AI boilerplate
 */
export function formatSecurityEmailHtml(data: {
  repoUrl?: string;
  branch?: string;
  findings: any[];
  summaryText?: string;
}): string {
  const findings = data.findings || [];
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;
  const hasBlockers = critical > 0 || high > 0;

  const repoUrl = data.repoUrl || 'Локальный проект';
  const branch = data.branch || 'main';

  const rowsHtml = findings.slice(0, 15).map(f => {
    let badgeColor = '#6b7280';
    if (f.severity === 'CRITICAL') badgeColor = '#ef4444';
    else if (f.severity === 'HIGH') badgeColor = '#f97316';
    else if (f.severity === 'MEDIUM') badgeColor = '#eab308';
    else if (f.severity === 'LOW') badgeColor = '#3b82f6';

    const id = f.class || f.advisoryId || f.category;
    const loc = f.path ? `${f.path}${f.line ? ':' + f.line : ''}` : '-';

    return `
      <tr style="border-bottom: 1px solid #334155;">
        <td style="padding: 10px; font-family: monospace; font-size: 12px; color: #38bdf8;">${f.category}</td>
        <td style="padding: 10px; font-weight: bold; color: #f8fafc; font-size: 12px;">${id}</td>
        <td style="padding: 10px; font-family: monospace; font-size: 11px; color: #94a3b8;">${loc}</td>
        <td style="padding: 10px;">
          <span style="display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: bold; color: #ffffff; background-color: ${badgeColor};">
            ${f.severity || 'MEDIUM'}
          </span>
        </td>
        <td style="padding: 10px; color: #cbd5e1; font-size: 12px; line-height: 1.4;">
          ${f.description || f.message || '-'}
        </td>
      </tr>
    `;
  }).join('');

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Отчёт безопасности uncflow</title>
</head>
<body style="margin: 0; padding: 20px; background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
  <div style="max-width: 680px; margin: 0 auto; background-color: #111827; border: 1px solid #1e293b; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
    
    <!-- Header -->
    <div style="padding: 24px; background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%); border-bottom: 1px solid #334155;">
      <div style="font-size: 20px; font-weight: bold; color: #38bdf8; display: flex; align-items: center;">
        🛡️ uncflow — Отчёт безопасности
      </div>
      <div style="margin-top: 8px; font-size: 13px; color: #94a3b8;">
        Репозиторий: <strong style="color: #f8fafc;">${repoUrl}</strong> (ветка: <code style="color: #38bdf8;">${branch}</code>)
      </div>
      <div style="margin-top: 4px; font-size: 12px; color: #64748b;">
        Дата проверки: ${new Date().toLocaleString('ru-RU')}
      </div>
    </div>

    <!-- Status Banner -->
    <div style="padding: 16px 24px; background-color: ${hasBlockers ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'}; border-bottom: 1px solid ${hasBlockers ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'};">
      <div style="font-size: 14px; font-weight: bold; color: ${hasBlockers ? '#f87171' : '#34d399'};">
        ${hasBlockers ? '🚨 ВНИМАНИЕ: Обнаружены критические уязвимости' : '✅ Проверка успешно пройдена: Критических рисков нет'}
      </div>
      <div style="font-size: 12px; color: #cbd5e1; margin-top: 4px;">
        Всего найдено проблем: <strong>${findings.length}</strong> (🔴 CRITICAL: ${critical}, 🟠 HIGH: ${high}, 🟡 MEDIUM: ${medium}, 🔵 LOW: ${low})
      </div>
    </div>

    <!-- Findings Table -->
    <div style="padding: 24px;">
      <h3 style="margin-top: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8;">Список находок:</h3>
      <table style="width: 100%; border-collapse: collapse; text-align: left;">
        <thead>
          <tr style="border-bottom: 2px solid #334155; font-size: 11px; text-transform: uppercase; color: #64748b;">
            <th style="padding: 8px;">Категория</th>
            <th style="padding: 8px;">Уязвимость</th>
            <th style="padding: 8px;">Файл и строка</th>
            <th style="padding: 8px;">Важность</th>
            <th style="padding: 8px;">Описание</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || '<tr><td colspan="5" style="padding: 16px; text-align: center; color: #64748b;">Уязвимостей не обнаружено</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- Footer -->
    <div style="padding: 16px 24px; background-color: #0f172a; border-top: 1px solid #1e293b; text-align: center; font-size: 11px; color: #64748b;">
      Автоматическое уведомление платформы анализа безопасности uncflow
    </div>
  </div>
</body>
</html>
  `.trim();
}
