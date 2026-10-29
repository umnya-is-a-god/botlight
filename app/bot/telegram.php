<?php

// Telegram Bot API: messages, files, prompts for input: methods of class Bot (app/bot.php)
trait BotTelegram
{
    public function cleanQueue(): void
    {
        $r = $this->request('deleteWebhook', []);
        $r = $this->request('getUpdates', ['offset' => -1]);
    }



    public function upload($name, $code, $chat = false)
    {
        return $this->sendFile($chat ?: $this->input['chat'], new CURLStringFile($code, $name));
    }

    /**
     * Asks the admin for an answer (a forced reply in the chat): the answer
     * goes to $callback($answer, ...$args), see reply().
     */
    public function prompt(string $text, string $placeholder, string $callback, array $args = [])
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $text,
            $this->input['message_id'],
            reply: $placeholder,
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => $callback,
            'args'           => $args,
        ];
    }

    public function reply()
    {
        if (!empty($_SESSION['reply'][$this->input['reply']])) {
            $this->delete($this->input['chat'], $this->input['reply']);
            $this->delete($this->input['chat'], $this->input['message_id']);
            $callback = $_SESSION['reply'][$this->input['reply']]['callback'];
            $this->input['message_id'] = $this->input['callback_id'] = $_SESSION['reply'][$this->input['reply']]['start_message'];
            $this->{$callback}($this->input['message'], ...$_SESSION['reply'][$this->input['reply']]['args']);
            $this->answer($_SESSION['reply'][$this->input['reply']]['start_message']);
            unset($_SESSION['reply'][$this->input['reply']]);
        }
    }

    // messages to delete later; the polling loop does it (deleteDue)
    public function deleteLater($chat, $message, int $seconds)
    {
        $this->later[] = [$chat, $message, time() + $seconds];
    }

    public function deleteDue()
    {
        foreach ($this->later as $k => [$chat, $message, $at]) {
            if ($at <= time()) {
                $this->delete($chat, $message);
                unset($this->later[$k]);
            }
        }
    }

    /**
     * A Bot API call. One curl handle serves them all: the connection stays
     * open and the address is looked up about once a minute (curl's DNS
     * cache), not for every request. A request that did not reach Telegram
     * (no address, no connection) is sent once more; one that may have
     * reached it only if sending it twice changes nothing.
     */
    public function request($method, $data, $json_header = 0)
    {
        $this->tg ??= curl_init();
        $ch = $this->tg;
        $repeatable = in_array($method, ['getUpdates', 'editMessageText', 'answerCallbackQuery', 'deleteMessage', 'sendMessageDraft', 'getFile', 'getMyName', 'setMyCommands', 'deleteWebhook'], true);
        for ($try = 1; $try <= 2; $try++) {
            // the options of the previous request go, the connection and the cached address stay
            curl_reset($ch);
            curl_setopt_array($ch, [
                CURLOPT_URL               => $this->api . $method,
                CURLOPT_CUSTOMREQUEST     => 'POST',
                CURLOPT_RETURNTRANSFER    => true,
                CURLOPT_CONNECTTIMEOUT    => 5,
                CURLOPT_TIMEOUT           => 15,
                // the containers have no IPv6: no waiting for its answer
                CURLOPT_IPRESOLVE         => CURL_IPRESOLVE_V4,
                CURLOPT_DNS_CACHE_TIMEOUT => 60,
                CURLOPT_HTTPHEADER        => $json_header ? [
                    'Content-Type: application/json'
                ] : [],
                CURLOPT_POSTFIELDS        => $data,
            ]);
            $res  = curl_exec($ch);
            $info = curl_getinfo($ch);
            if (is_array($this->timing)) {
                $this->timing[] = [
                    'm'   => $method,
                    'ms'  => (int) round($info['total_time'] * 1000),
                    'dns' => (int) round($info['namelookup_time'] * 1000),
                    'tcp' => (int) round($info['connect_time'] * 1000),
                ] + ($res === false ? ['err' => curl_error($ch)] : []);
            }
            // nothing sent yet (no address, no connection): safe to send again
            $unsent = $res === false && (float) $info['pretransfer_time'] == 0.0;
            if ($res !== false || $try == 2 || !($unsent || $repeatable)) {
                break;
            }
        }
        $r   = json_decode((string) $res, true);
        // log failed calls: no answer at all, or Telegram refused the request
        if (!is_array($r) || empty($r['ok'])) {
            // method and Telegram's answer only: the request itself may carry
            // links, keys or backups
            $why = $res === false ? 'curl: ' . curl_error($ch) : (is_array($r) ? ($r['error_code'] ?? '') . ' ' . ($r['description'] ?? '') : substr((string) $res, 0, 200));
            // where it came from: the script and the functions (names only, no arguments)
            $from = array_reverse(array_column(array_slice(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 12), 1), 'function'));
            $from = basename((string) ($_SERVER['SCRIPT_NAME'] ?? '')) . ': ' . implode(' > ', $from);
            file_put_contents('/logs/requests_error', date('Y-m-d H:i:s ') . "$method: $why [$from]\n", FILE_APPEND);
        }
        return $r;
    }

    public function polling()
    {
        $offset = -1;
        while (true) {
            try {
                $offset = $this->pollingRound($offset);
            } catch (Throwable $e) {
                error_log("polling: $e");
                sleep(3);
            }
        }
    }

    // one getUpdates and its updates; the next offset
    public function pollingRound(int $offset): int
    {
        $r = $this->request('getUpdates', [
            'offset'          => $offset,
            'limit'           => 3,
            'timeout'         => 5,
            // explicit: without it Telegram keeps the list from an
            // earlier webhook or bot on this token, which may leave out
            // button presses (callback_query)
            'allowed_updates' => json_encode(['message', 'callback_query', 'inline_query', 'channel_post', 'my_chat_member']),
        ]);
        // the loop is alive: healthcheck and scripts/supervise.sh read it
        @touch('/tmp/heartbeat');
        $debug = $this->debugOn();
        $this->deleteDue();
        $this->menuAfterHost();
        if (empty($this->time_warp_profile) || time() - $this->time_warp_profile > 600) {
            $this->time_warp_profile = time();
            $this->syncWarpProfile();
        }
        if (!empty($r['description'])) {
            error_log('getUpdates error: ' . $r['description']);
            sleep(3);
            return $offset;
        }
        if (!empty($r['result'])) {
            foreach ($r['result'] as $v) {
                // with /debug on: how long the update took and each Telegram
                // request in it (the command only, not its data)
                $this->timing = $debug ? [] : null;
                $start        = microtime(true);
                try {
                    $this->input($v);
                } catch (Throwable $e) {
                    error_log($e);
                } finally {
                    session_write_close();
                }
                if ($debug) {
                    $what = isset($v['callback_query']) ? 'button ' . strtok((string) ($v['callback_query']['data'] ?? ''), ' ') : 'message';
                    error_log('timing: ' . json_encode(['update' => $what, 'ms' => (int) round((microtime(true) - $start) * 1000), 'requests' => $this->timing], JSON_UNESCAPED_SLASHES));
                }
                $this->timing = null;
                $offset = max($offset, $v['update_id']);
            }
            $offset++;
        } elseif (!is_array($r)) {
            // no answer from Telegram: not again at once; an empty answer
            // (no update within the timeout) is asked again at once
            sleep(1);
        }
        return $offset;
    }

    public function setcommands()
    {
        $data = [
            'commands' => [
                [
                    'command'     => 'menu',
                    'description' => '...',
                ],
                [
                    'command'     => 'id',
                    'description' => 'your id telegram',
                ],
            ]
        ];
        $this->request('setMyCommands', json_encode($data), 1);
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        if (is_null($text)) {
            $text = '';
        }
        $extra = null;
        $r     = [];
        if ($button) {
            $extra = ['inline_keyboard' => $button];
        }
        if (false !== $reply) {
            $extra = [
                'force_reply'             => true,
                'input_field_placeholder' => $reply,
                'selective'               => true,
            ];
        }
        $length = 3096;
        if (mb_strlen($text, 'utf-8') > $length) {
            $tails = $this->splitText($text, $length);
            foreach ($tails as $k => $v) {
                $data = [
                    'chat_id'                  => $chat,
                    'text'                     => "$v\n",
                    'parse_mode'               => $mode,
                    // no link previews: messages carry subscription links
                    'link_preview_options'     => json_encode(['is_disabled' => true]),
                    'disable_notification'     => $disable_notification,
                    'reply_to_message_id'      => 0 == $k && $to > 0 ? $to : false,
                ];
                if ($k == array_key_last($tails)) {
                    if ($extra) {
                        $data['reply_markup'] = json_encode($extra);
                    }
                }
                $r = $this->request('sendMessage', $data);
            }
        } else {
            $data = [
                'chat_id'                  => $chat,
                'text'                     => $text,
                'parse_mode'               => $mode,
                'link_preview_options'     => json_encode(['is_disabled' => true]),
                'disable_notification'     => $disable_notification,
                'reply_to_message_id'      => $to,
            ];
            if (!empty($extra)) {
                $data['reply_markup'] = json_encode($extra);
            }
            $r = $this->request('sendMessage', $data);
        }
        return $r;
    }

    public function splitText($text, $size = 4096)
    {
        $tails = preg_split('~\n~', $text);
        if (!empty($tails)) {
            foreach ($tails as $v) {
                $lines[] = [
                    'length' => mb_strlen($v, 'utf-8'),
                    'text'   => $v,
                ];
            }
            $i      = 0;
            $output = [];
            foreach ($lines as $v) {
                $i += $v['length'];
                $k  = (int) ceil($i / $size);
                $output[$k] = ($output[$k] ?? '') . $v['text'] . "\n";
            }
            return array_values($output);
        } else {
            return [$text];
        }
    }

    public function sendDraft($chat, $draft_id, $text = '', $mode = 'HTML')
    {
        $data = [
            'chat_id'    => $chat,
            'draft_id'   => $draft_id,
            'text'       => $text,
            'parse_mode' => $mode,
        ];
        return $this->request('sendMessageDraft', json_encode($data), 1);
    }

    public function sendPhoto($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendPhoto', [
            'chat_id'             => $chat,
            'photo'               => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
            'parse_mode'          => 'html',
        ]);
    }

    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendDocument', [
            'chat_id'             => $chat,
            'document'            => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
            'parse_mode'          => 'html',
        ]);
    }

    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        if ($button) {
            $extra = ['inline_keyboard' => $button];
        }
        if ($reply !== false) {
            $extra = [
                'force_reply'             => true,
                'input_field_placeholder' => $reply
            ];
        }
        $data = [
            'chat_id'                  => $chat,
            'message_id'               => $message_id,
            'text'                     => $text,
            'parse_mode'               => $mode,
            'link_preview_options'     => json_encode(['is_disabled' => true]),
        ];
        if (!empty($extra)) {
            $data['reply_markup'] = json_encode($extra);
        }
        return $this->request('editMessageText', $data);
    }

    public function answer($callback_id, $textNotify = false, $notify = false)
    {
        return $this->request('answerCallbackQuery', [
            'callback_query_id' => $callback_id,
            'show_alert'        => $notify,
            'text'              => $textNotify,
        ]);
    }

    public function delete($chat, $message_id)
    {
        $data = [
            'chat_id'    => $chat,
            'message_id' => $message_id,
        ];
        return $this->request('deleteMessage', $data);
    }
}
