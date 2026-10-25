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

    public function request($method, $data, $json_header = 0)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->api . $method,
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_HTTPHEADER => $json_header ? [
                'Content-Type: application/json'
            ] : [],
            CURLOPT_POSTFIELDS     => $data,
        ]);
        $res = curl_exec($ch);
        $r   = json_decode($res, true);
        // log failed calls: no answer at all, or Telegram refused the request
        if (!is_array($r) || empty($r['ok'])) {
            // method and Telegram's answer only: the request itself may carry
            // links, keys or backups
            $why = $res === false ? 'curl: ' . curl_error($ch) : (is_array($r) ? ($r['error_code'] ?? '') . ' ' . ($r['description'] ?? '') : substr((string) $res, 0, 200));
            file_put_contents('/logs/requests_error', date('Y-m-d H:i:s ') . "$method: $why\n", FILE_APPEND);
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
        $this->deleteDue();
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
                try {
                    $this->input($v);
                } catch (Throwable $e) {
                    error_log($e);
                } finally {
                    session_write_close();
                }
                $offset = max($offset, $v['update_id']);
            }
            $offset++;
        } else {
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
            $i = 0;
            foreach ($lines as $v) {
                $i += $v['length'];
                $output[ceil($i / $size)] .= $v['text'] . "\n";
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
