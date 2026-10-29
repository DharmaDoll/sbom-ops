# Slack対応候補通知

Slackへ送る前に、候補・選定理由・本文を標準出力で確認する。実Slack試験は現在保留。
既定で送信しない。GitHub自動起票は[#7](https://github.com/DharmaDoll/sbom-ops/issues/7)
の凍結を維持する。この機能の開発課題は[#25](https://github.com/DharmaDoll/sbom-ops/issues/25)。

## 最短の確認（外部通信なし）

既存の開発環境から、架空の通常通知を表示する:

```sh
.venv/bin/python examples/slack_preview.py
```

`--case urgent`、`--case unassigned`、`--case missing`、`--case reminder` で
緊急・担当不明・情報不足・再通知を比較できる。`--output json` は構造化した本文を出す。
normalは同じ修正作業の2ビルドを1候補へ、unassignedは資産対応を推測せず2候補へ分ける。
reminderは過去の確認済み送信を架空の履歴として与える。実際の送信やDB作成はしない。

成功したsync JSONを使う場合:

```sh
sbom-ops slack notify --findings /path/to/sync.json \
  --observed-at 2026-10-29T04:00:00Z \
  --config examples/slack-config.example.json
```

`--observed-at` はその入力を取得した実際の時刻へ置き換える。古い入力の時刻を現在に
付け替えない。入力は既定24時間以内、未来日時は拒否する。JSONの整合性検証は
取得対象全体の完全性や最新のDT状態を証明するものではない。
`--output json` で選定理由・送信予定本文・宛先・スレッド参照をJSON出力する。
`--db /persistent/slack.sqlite3` を付けると確認済み送信や待機状態を読み、実際の再通知
判断をpreviewできる。DBを指定しなければ送信履歴なしとして表示する。
previewはtoken不要、外部通信なし、送信台帳変更なし。出力には担当・部品・構成の要約を
含むため、保存先のアクセス権と保持期間を運用担当が管理する。

送信対象の既定はP0/P1。P2/P3は `excluded_priority` として本文を確認できるが送らない。
`duplicate` は同じ重要情報を送信済み、`interval` は最小間隔内。
空入力・対象外・一部Projectの欠落を「修正済み」「解消」とは表示しない。
失敗したsync文書は `processing_error`（終了値2）となり、対応候補には変換しない。
処理障害の通知先は単一ホストのジョブ監視とする。同じ壊れたSlack経路へ再送し続けない。

## 運用契約とAPIの選択

| 項目 | 初期契約 |
| --- | --- |
| 送信先 | 運用担当が指定した1チャンネル。Botを招待しメンバーの閲覧範囲を確認 |
| 確認担当 | セキュリティ担当が初期確認。表示された担当と資産対応を確認して引き渡す |
| 判断の記録先 | 設定の `record_url` が示す既存の手動作業管理。未決なら送信開始しない |
| 表示する情報 | サービス/配布単位、担当、優先度・根拠、脆弱性/部品、影響候補、不足情報、確認先、時刻・相関ID |
| 表示しない情報 | 生SBOM、description、分析メモ、認証情報。外部由来URLは省略 |
| 判断 | 人がDT・配置を確認し、対応要否と記録先を決定。Slack投稿や反応で担当/抑制/例外/完了を変更しない |
| 初期頻度 | 候補ごと最小3600秒、定期再通知なし、1実行最大20件、送信間隔1秒以上 |

Incoming Webhookは固定チャンネルへの新規投稿に簡単だが、秘密URLの管理が必要で、
投稿応答からスレッド用tsを得られない。Bot APIはアプリ導入・招待・token管理が必要だが、
投稿応答のchannel/tsを記録して重要変更や再通知を同じスレッドに結べるため採用した。
必要権限は `chat:write` のみ。チャンネル探索・履歴収集・ユーザー自動照合・ボタン承認は
実装しない。投稿済み本文は更新せず、新しい情報を返信する。

公式根拠（2026-10-29確認）:
[chat.postMessage](https://docs.slack.dev/reference/methods/chat.postMessage/)、
[Incoming Webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)、
[rate limits](https://docs.slack.dev/apis/web-api/rate-limits/)、
[メッセージ整形](https://docs.slack.dev/messaging/formatting-message-text/)。

## 設定と明示送信（実試験は保留）

`examples/slack-config.example.json` を運用用JSONへ複製して編集する。
未知の項目は拒否する。token本体をJSON・CLI引数へ置かず `token_env` で環境変数名を指定。
送信時だけその変数を読む。架空channelや `.invalid` の参照先では送信できない。
参照先はHTTPS、userinfo・query・fragmentなしとし、署名URLやWebhook URLを使わない。
チャンネル参加者がアクセスできるDT入口、詳細結果、判断記録先の恒久URLを指定する。

| 設定 | 意味 |
| --- | --- |
| `enabled` | 既定false。falseへの変更で送信だけ止まる |
| `priorities` | P0〜P3から通知対象を選択。優先度の計算は変えない |
| `grouping` | `repair`（既定）または`finding`。運用開始後の変更は通知keyが変わるため事前preview必須 |
| `change_fields` | `priority`, `owners`, `context`, `rationale` のうち重要変更とみなす項目 |
| `min_interval_seconds` | 同じ候補の最小間隔。P0も適用するため緊急運用要件に合わせて決める |
| `reminder_seconds` | 0は無効。正数なら同じ情報でも期限後に再通知。最小間隔も満たす必要あり |
| `pacing_seconds` | チャンネル内のPOST間隔（1以上）。60秒超の待機は `pacing_wait` として次回へ回す |
| `max_messages` | 1実行のPOST上限（1〜100）。残件は次回に選定 |
| `max_attempts` | 確定失敗に対する明示retryを含む1イベントの試行上限（1〜100） |
| `max_input_age_seconds` | 入力観測からの最大経過時間 |

新規導入時に一度だけ、保護した永続ディレクトリに台帳を作る:

```sh
sbom-ops slack init --db /persistent/slack.sqlite3
sbom-ops slack notify --findings /path/to/sync.json \
  --observed-at ACTUAL_OBSERVATION_TIME --config /path/to/slack.json \
  --db /persistent/slack.sqlite3 --dry-run
```

将来の限定試験で送信先と掲載内容を確認後、`enabled: true` と `--execute` を併用する。
`--dry-run` が付いていれば送らない。`--no-github`、環境変数、enabledだけでは送信しない。
通常のsyncとは独立したコマンドなので、無効化してもDT読取・評価・既存出力は続けられる。

## 永続化・定期実行・復旧

単一ホストのスケジューラから「既存sync（GitHub無効）→成功JSONを確定保存→preview/
明示notify」を順番に実行する。同じSlack宛先には必ず同じ永続DBを使う。
SQLiteのinodeに非待機flockを取り、POST前にpendingをFULL同期で保存する。
別DB・複数ホスト・共有ネットワークFSはサポートしない。Actionsの一時runnerへは
配置しない。DB親ディレクトリを運用アカウントだけに許可し、DBは0600を維持する。
DBを削除・再init・過去バックアップへ巻戻すと重複送信防止を失う。再送のために行わない。

```sh
sbom-ops slack show --db /persistent/slack.sqlite3
```

送信意図・候補key・宛先・本文hash・run ID・試行数・結果・Slack channel/ts・監査履歴を
表示する。本文/token/レスポンス本体は台帳に保存しない。送信後に台帳保存が失敗した場合も
pendingが残るので、実際には投稿済みの可能性がある。

| 状態 | 次の行動 |
| --- | --- |
| `confirmed` | channel/tsを確認。同じ情報は再送せず、変更/再通知は親スレッドへ返信 |
| `rate_limited` | 保存されたretry_at以降に原因・送信量を確認し `--retry-failed --execute` で再実行。自動ループしない |
| `rejected` | token・scope・招待・宛先等を修正し、同じ候補・重要情報を明示retry。上限超過は運用確認へ |
| `pending` / `unknown` | 同じ宛先への後続送信を停止。本文の候補key・相関IDでSlackを人が確認。無条件再送しない |
| `processing_error` / 監査保存失敗 | 入力・ディスク・権限・台帳を確認。部分送信の有無をshowとSlackで照合 |

429はRetry-Afterを守る。5xx、timeout、応答喪失、不正応答は受理済みか判別できないため
unknownとする。POSTはクライアント内で再試行しない。API以上のexactly-onceは保証しない。
途中失敗時は既に送った投稿を取り消さず、その実行の後続を停止する。
確定失敗でも復旧前に別候補を送り続けない。次回は失敗した候補を含む新鮮な入力を用意し、
重要情報が同じことを確認して明示retryする。失敗候補がない/変わった/試行上限の場合は
その宛先全体を止める。上限や不明結果を回避するDB再作成・宛先切替は行わない。

不明結果の投稿を人が一意に確認できた場合だけ、保存済み宛先を指定してconfirmする:

```sh
sbom-ops slack confirm --db /persistent/slack.sqlite3 \
  --intent SAVED_INTENT_ID --channel VERIFIED_CHANNEL_ID --ts VERIFIED_TIMESTAMP \
  --actor operator-name
# previewの後、同じ引数に --execute を追加してローカル監査を確定
```

confirmはローカル送信結果の記録のみ。Slack履歴APIを呼ばず、確認の正しさは操作者が担保する。
投稿を確認できなければ停止を維持する。未送信と断定できないまま再送する解除機能はない。

限定試験を再開したら通常・緊急・担当不明・不足・再通知と再実行を限定チャンネルで確認し、
一定期間の件数、重複、未割当率、対象/確認先/次の行動/記録先が理解できたかを#25へ記録する。
通知条件や手動起票への導線はその結果で見直す。実送信の成功を修正完了へ読み替えない。
