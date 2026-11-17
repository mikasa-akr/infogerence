<?php

declare(strict_types=1);

function env(string $key, string $default = ''): string {
    $val = getenv($key);
    if ($val === false) {
        return $default;
    }
    return (string)$val;
}

function loadDotEnv(string $path): void {
    if (!is_file($path) || !is_readable($path)) {
        return;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if (!is_array($lines)) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $pos = strpos($line, '=');
        if ($pos === false) {
            continue;
        }
        $key = trim(substr($line, 0, $pos));
        $value = trim(substr($line, $pos + 1));
        if ($key === '') {
            continue;
        }
        if ((str_starts_with($value, '"') && str_ends_with($value, '"')) || (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
            $value = substr($value, 1, -1);
        }
        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }
}

function smtpSend(array $cfg, string $to, array $cc, string $subject, string $body, array $headers, string &$error): bool {
    $host = $cfg['host'] ?? '';
    $port = (int)($cfg['port'] ?? 0);
    $user = $cfg['username'] ?? '';
    $pass = $cfg['password'] ?? '';
    $encryption = strtolower((string)($cfg['encryption'] ?? ''));

    if ($host === '' || $port <= 0 || $user === '' || $pass === '') {
        $error = 'SMTP config incomplete';
        return false;
    }

    $errno = 0;
    $errstr = '';

    $transport = 'tcp://';
    if ($encryption === 'ssl') {
        $transport = 'tls://';
    }

    $fp = @stream_socket_client($transport . $host . ':' . $port, $errno, $errstr, 20);
    if (!$fp) {
        $error = 'SMTP connect failed: ' . $errno . ' ' . $errstr;
        return false;
    }

    stream_set_timeout($fp, 20);

    $read = static function () use ($fp): string {
        $data = '';
        while (!feof($fp)) {
            $line = fgets($fp, 515);
            if ($line === false) {
                break;
            }
            $data .= $line;
            if (strlen($line) >= 4 && $line[3] === ' ') {
                break;
            }
        }
        return $data;
    };

    $write = static function (string $cmd) use ($fp): void {
        fwrite($fp, $cmd . "\r\n");
    };

    $expect = static function (string $resp, array $codes): bool {
        $code = (int)substr($resp, 0, 3);
        return in_array($code, $codes, true);
    };

    $banner = $read();
    if (!$expect($banner, [220])) {
        $error = 'SMTP banner unexpected: ' . trim($banner);
        fclose($fp);
        return false;
    }

    $ehloHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $write('EHLO ' . $ehloHost);
    $ehlo = $read();
    if (!$expect($ehlo, [250])) {
        $write('HELO ' . $ehloHost);
        $helo = $read();
        if (!$expect($helo, [250])) {
            $error = 'SMTP EHLO/HELO failed: ' . trim($ehlo) . ' ' . trim($helo);
            fclose($fp);
            return false;
        }
    }

    if ($encryption === 'tls') {
        $write('STARTTLS');
        $starttls = $read();
        if (!$expect($starttls, [220])) {
            $error = 'SMTP STARTTLS refused: ' . trim($starttls);
            fclose($fp);
            return false;
        }

        $cryptoOk = @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($cryptoOk !== true) {
            $error = 'SMTP TLS negotiation failed';
            fclose($fp);
            return false;
        }

        $write('EHLO ' . $ehloHost);
        $ehlo2 = $read();
        if (!$expect($ehlo2, [250])) {
            $error = 'SMTP EHLO after STARTTLS failed: ' . trim($ehlo2);
            fclose($fp);
            return false;
        }
    }

    $write('AUTH LOGIN');
    $auth1 = $read();
    if (!$expect($auth1, [334])) {
        $error = 'SMTP AUTH LOGIN not accepted: ' . trim($auth1);
        fclose($fp);
        return false;
    }

    $write(base64_encode($user));
    $auth2 = $read();
    if (!$expect($auth2, [334])) {
        $error = 'SMTP username rejected: ' . trim($auth2);
        fclose($fp);
        return false;
    }

    $write(base64_encode($pass));
    $auth3 = $read();
    if (!$expect($auth3, [235])) {
        $error = 'SMTP password rejected: ' . trim($auth3);
        fclose($fp);
        return false;
    }

    $from = '';
    foreach ($headers as $h) {
        if (stripos($h, 'From:') === 0) {
            $from = trim(substr($h, 5));
            break;
        }
    }

    $fromAddr = '';
    if ($from !== '' && preg_match('/<([^>]+)>/', $from, $m)) {
        $fromAddr = $m[1];
    } elseif ($from !== '' && filter_var($from, FILTER_VALIDATE_EMAIL)) {
        $fromAddr = $from;
    }

    if ($fromAddr === '') {
        $fromAddr = $user;
    }

    $write('MAIL FROM:<' . $fromAddr . '>');
    $mf = $read();
    if (!$expect($mf, [250])) {
        $error = 'SMTP MAIL FROM rejected: ' . trim($mf);
        fclose($fp);
        return false;
    }

    $write('RCPT TO:<' . $to . '>');
    $rcpt = $read();
    if (!$expect($rcpt, [250, 251])) {
        $error = 'SMTP RCPT TO rejected: ' . trim($rcpt);
        fclose($fp);
        return false;
    }

    foreach ($cc as $ccAddr) {
        $ccAddr = trim((string)$ccAddr);
        if ($ccAddr === '' || !filter_var($ccAddr, FILTER_VALIDATE_EMAIL)) {
            continue;
        }
        $write('RCPT TO:<' . $ccAddr . '>');
        $rcptCc = $read();
        if (!$expect($rcptCc, [250, 251])) {
            $error = 'SMTP RCPT TO (CC) rejected: ' . trim($rcptCc);
            fclose($fp);
            return false;
        }
    }

    $write('DATA');
    $dataResp = $read();
    if (!$expect($dataResp, [354])) {
        $error = 'SMTP DATA not accepted: ' . trim($dataResp);
        fclose($fp);
        return false;
    }

    $msg = [];
    $msg[] = 'To: <' . $to . '>';
    $msg[] = 'Subject: ' . $subject;
    foreach ($headers as $h) {
        $msg[] = $h;
    }
    $msg[] = '';
    $msg[] = $body;
    $payload = implode("\r\n", $msg);
    $payload = str_replace(["\r\n.", "\n."], ["\r\n..", "\n.."], $payload);

    fwrite($fp, $payload . "\r\n.\r\n");
    $sentResp = $read();
    if (!$expect($sentResp, [250])) {
        $error = 'SMTP send failed: ' . trim($sentResp);
        fclose($fp);
        return false;
    }

    $write('QUIT');
    fclose($fp);
    return true;
}

function verifyRecaptcha(string $secret, string $response): bool {
    $response = trim($response);
    if ($response === '') {
        error_log('[recaptcha-debug] empty g-recaptcha-response from browser');
        return false;
    }

    $verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
    $data = http_build_query([
        'secret' => $secret,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);

    $result = false;
    if (ini_get('allow_url_fopen')) {
        $opts = ['http' => ['method' => 'POST', 'header' => 'Content-type: application/x-www-form-urlencoded', 'content' => $data, 'timeout' => 10]];
        $result = @file_get_contents($verifyUrl, false, stream_context_create($opts));
        if ($result === false) {
            $e = error_get_last();
            error_log('[recaptcha-debug] file_get_contents failed: ' . ($e['message'] ?? 'unknown'));
        }
    } else {
        error_log('[recaptcha-debug] allow_url_fopen is OFF');
    }

    // Fallback: cURL
    if ($result === false && function_exists('curl_init')) {
        $ch = curl_init($verifyUrl);
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $data, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10]);
        $result = curl_exec($ch);
        if ($result === false) {
            error_log('[recaptcha-debug] curl failed: ' . curl_error($ch));
        }
        curl_close($ch);
    } elseif ($result === false) {
        error_log('[recaptcha-debug] curl extension not available');
    }

    if ($result === false) {
        return false;
    }

    $json = json_decode((string)$result, true);
    if (!is_array($json) || ($json['success'] ?? false) !== true) {
        error_log('[recaptcha-debug] Google said: ' . substr((string)$result, 0, 300));
        return false;
    }
    return true;
}

loadDotEnv(__DIR__ . DIRECTORY_SEPARATOR . '.env');

$method = $_SERVER['REQUEST_METHOD'] ?? '';
if (strtoupper($method) !== 'POST') {
    header('Location: contact.html');
    exit;
}

$to = 'commercial@next.tn';

$name = trim((string)($_POST['name'] ?? ''));
$email = trim((string)($_POST['email'] ?? ''));
$phone = trim((string)($_POST['phone'] ?? ''));
$subject = trim((string)($_POST['subject'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));
$website = trim((string)($_POST['website'] ?? ''));

if ($website !== '') {
    error_log('Contact form blocked by honeypot');
    header('Location: contact.html?error=1');
    exit;
}

$recaptchaSecret = env('RECAPTCHA_SECRET_KEY', '');
$recaptchaResponse = trim((string)($_POST['g-recaptcha-response'] ?? ''));
if ($recaptchaSecret === '') {
    error_log('[recaptcha-debug] RECAPTCHA_SECRET_KEY is EMPTY: .env not found/readable at ' . __DIR__ . '/.env (exists=' . (is_file(__DIR__ . '/.env') ? 'yes' : 'NO') . ')');
}

if ($recaptchaSecret === '' || $recaptchaResponse === '' || !verifyRecaptcha($recaptchaSecret, $recaptchaResponse)) {
    error_log('Contact form blocked by reCAPTCHA');
    header('Location: contact.html?error=2');
    exit;
}

if ($name === '' || $email === '' || $phone === '' || $subject === '' || $message === '') {
    header('Location: contact.html?error=1');
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: contact.html?error=1');
    exit;
}

if (!preg_match('/^[0-9+\s().-]+$/', $phone)) {
    header('Location: contact.html?error=1');
    exit;
}

$clean = static function (string $value): string {
    $value = str_replace(["\r", "\n"], ' ', $value);
    return trim($value);
};

$nameSafe = $clean($name);
$emailSafe = $clean($email);
$phoneSafe = $clean($phone);
$subjectSafe = $clean($subject);

$bodyLines = [
    'Nouveau message depuis le formulaire de contact :',
    '',
    'Nom: ' . $nameSafe,
    'Email: ' . $emailSafe,
    'Téléphone: ' . $phoneSafe,
    '',
    'Message:',
    $message,
];

$body = implode("\n", $bodyLines);

$headers = [];
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-type: text/plain; charset=UTF-8';
$fromAddress = env('MAIL_FROM_ADDRESS', '');
$fromName = env('MAIL_FROM_NAME', '');
$fromHeaderName = $fromName !== '' ? $fromName : $nameSafe;
$fromHeaderAddress = $fromAddress !== '' ? $fromAddress : ('no-reply@' . ($_SERVER['HTTP_HOST'] ?? 'localhost'));
$headers[] = 'From: ' . $fromHeaderName . ' <' . $fromHeaderAddress . '>';
$headers[] = 'Reply-To: ' . $emailSafe;
$cc = ['contact@next.tn'];
$headers[] = 'Cc: ' . implode(', ', $cc);

$mailSubject = 'Contact: ' . $subjectSafe;

$mailer = strtolower(env('MAIL_MAILER', ''));
$sent = false;

$smtpError = '';

if ($mailer === 'smtp') {
    $smtpCfg = [
        'host' => env('MAIL_HOST', ''),
        'port' => env('MAIL_PORT', ''),
        'username' => env('MAIL_USERNAME', ''),
        'password' => env('MAIL_PASSWORD', ''),
        'encryption' => env('MAIL_ENCRYPTION', ''),
    ];
    $sent = smtpSend($smtpCfg, $to, $cc, $mailSubject, $body, $headers, $smtpError);
    if (!$sent) {
        error_log('Contact form SMTP failed: ' . $smtpError);
    }
}

if ($mailer !== 'smtp' && !$sent) {
    $sent = @mail($to, $mailSubject, $body, implode("\r\n", $headers));
    if (!$sent) {
        error_log('Contact form mail() failed');
    }
}

if ($sent) {
    header('Location: contact.html?sent=1');
    exit;
}

header('Location: contact.html?error=3');
exit;