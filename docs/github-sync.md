# 任意のGitHub同期と復旧

[作業別の入口へ戻る](operations.md)。通常運用では`--no-github`を指定する。

**状態:** 連携は既定無効。本番有効化と追加の実書込み検証は
[開発Issue #7](https://github.com/DharmaDoll/sbom-ops/issues/7)で保留中。
以下は再開が合意された場合の参照手順であり、初回導入の必須工程ではない。
開発Issueの更新は製品同期の有効化を意味しない。

**担当:** 運用・セキュリティ担当が対象・権限・書込み範囲を確認する。
**前提・入力:** 確認済みProject・repo・経路、専用token、書込み時は永続的な操作記録DB。
**期待結果:** dry-runで対象と操作予定を確認する。実書込みは合意後、各実行の明示許可が必要。
**失敗時:** [本文の扱いと復旧](#本文の扱いと復旧)と[操作記録](#作成の操作記録sqlite)で
GitHub側とDBを照合する。結果不明の作成を無条件に再送しない。

## GitHub同期の確認

### 権限と送信先を先に固定する

開発Issueの更新・コードのpush用認証と、製品の脆弱性Issue同期用認証は別の用途である。
現在の製品クライアントは `https://api.github.com` を使う。GitHub Enterprise Serverの
独自API URLや、GitHub Appのトークン発行・更新は提供していない。

| 製品が行う操作 | API（`/repos/{owner}/{repo}` 以下） | 必要なrepository permission |
| --- | --- | --- |
| 全Issue一覧・更新前の本文確認、dry-run | `GET /issues`、`GET /issues/{number}` | Issues: read |
| 新規作成・管理範囲の本文更新 | `POST /issues`、`PATCH /issues/{number}` | Issues: write |
| 管理ラベルの追加・個別解除 | `POST /issues/{number}/labels`、`DELETE /issues/{number}/labels/{name}` | Issues: write |

表は[Issues API](https://docs.github.com/en/rest/issues/issues)と
[Labels API](https://docs.github.com/en/rest/issues/labels)の権限に対応する。
実書込みでは読取りも必要。Contents・Pull requests・Administrationの書込み権限は要求しない。
自動クローズ、Issue削除、コメント投稿、repoの作成・設定変更は同期処理の対象外。
tokenの権限だけで実行アカウントの権限が増えるわけではない。
特に新規Issue作成時のラベル指定は、実行者にrepoへのpush accessがないと無視され得るため、
後述の限定検証では「作成成功」だけでなく管理ラベルの反映まで確認する。

最初の限定検証は、有効期限を設けたfine-grained PATで、Repository accessを検証先のみに
限定し、IssuesをRead and writeにする。読取りだけのdry-runならRead-onlyでよいが、
それでは実書込み可能なことの証明にはならない。Metadataなど自動付与される読取りと、
明示的に付与する権限を区別する。組織の承認が必要なら承認完了を確認する。
長期運用ではGitHub Appも候補だが、発行・更新は運用側で用意し、権限を広げる代替策にはしない。
詳細は[GitHubのトークン管理](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)を参照。
秘密値は承認済みの保管先から実行環境の `SBOM_OPS_GITHUB_TOKEN` へ渡す。
本文・YAML・Issue・ログへ貼らず、開発用の広いtokenを暗黙に流用しない。
この変数が未指定なら `GH_TOKEN` を使うため、実行環境に残っている認証の用途も確認する。

対象は次のように固定する。資産の担当者情報からrepoやIssue担当者を自動で決める機能ではない。

- `--project` または `runtime.project_uuids` で検証Projectを明示する。省略時は閲覧可能な全Projectになる。
- `routing.projects` が空なら全対象を `github.owner/repo` へ送る。
  一件でも経路を設定したら、全対象ProjectのUUIDに経路を用意する。未登録Projectは停止し、既定repoへ逃がさない。
- 複数repoの経路があってもtokenは共通。全経路の必要権限を確認し、許可するrepoを最小限にする。
  初回検証は一つのrepoだけにする。経路の変更は既存Issueの移動ではなく、別repoでの新規作成につながり得るため事前レビューする。
- prefixと `prefix-P0`〜`prefix-P3` の5ラベルを確認し、既存用途と衝突しないものを選ぶ。
  検証前にrepo側で用意し、後からprefixを変えて既存Issueを見失わせない。
- `plan` は接続せず設定の概要と経路の件数を示すだけで、権限や全送信先の検証にはならない。
  設定・環境変数による上書きを確認し、続いて実際の `sync --dry-run` のrepo・key・操作予定を確認する。

Issue本文には部品・脆弱性・サービス/配布単位などの情報が出る。
非公開資産を公開repoへ送らない。既存Issueも読むため、dry-run出力・操作記録の保管先と閲覧者を決める。
専用prefixは認証上の隔離ではなく、設定誤りで他Issueを変更できない保証でもない。
tokenのrepo制限と、確認済みProject・経路・管理keyの組合せで対象を絞る。

### 複数ビルドを一つの修正作業として扱う

`--asset-db`の照合済みサービス・配布単位、PURL全文、脆弱性の情報源/IDが一致すれば、
同じrepo内ではビルドが増えても一つのIssueへまとめる。repoが違えば別のIssueになる。
部品の版違い・未確認の紐付けは推測でまとめない。DT分析と各Findingの優先度は変えず、
Issueの作成条件・管理ラベルには分析除外を除いた最優先値を使う。

最初の作成・移行は、同じサービス/配布単位・同じrepoに対応する照合済みProjectを全て
`--project`で選び、dry-runする。一部だけでは、選ばなかったビルドの旧Issueを見逃すため停止する。
同範囲に今回確認できない旧FindingのIssueがある場合も、対応を調べるまで新しい組を作らない。
既存Issueが一つなら番号・タイトル・管理範囲外のメモを保持して移行する。複数あれば停止し、
自動で一つを選んだり、余りを閉じたりしない。閉じたIssueを無視して新規作成することもない。

移行後に一部Projectだけを同期した場合、以前の内訳は「今回未確認」として残る。
そのFindingの最後の優先度も維持するため、選択範囲を狭めただけではラベルが下がらない。
現在の対象が全て抑制・NOT_AFFECTED・FALSE_POSITIVEなら更新せず、Issueは閉じない。
資産の再紐付け・同じ組でのラベル経路の不一致は停止して確認する。台帳を省略して
旧Finding単位へ戻す操作も、既存の組を壊さないよう停止する。

本文の`repair-record`は内訳を次回へ引き継ぐ機械用記録で、管理範囲と一緒に保持する。
Base64は暗号化ではないので秘密情報を入れない。SQLiteの旧送信記録は残し、保存された
旧Finding keyから同じIssueへ照合する。移行のためにDBを削除・初期化する必要はない。
本文全体が6万文字を超えたら、メンバーを捨てたり別Issueを増やしたりせず停止する。
記録を手で削って再送を通さず、対象範囲と表現の見直しが必要な状態として扱う。
実環境の有効化検証が済むまでは、以下の手順もdry-runまでに留める。
外部通信なしでこの同期処理を試すには、開発用依存を導入後に
`python -m pytest -q tests/unit/test_grouped_workflow.py`を実行する。
模擬GitHubと一時SQLiteで、作成・旧Issue移行・一部ビルドの同期・応答喪失などを検証し、
実Issueや既存DBは変更しない。

### 本文の扱いと復旧

Issue本文の `<!-- sbom-ops:managed:start -->` と `<!-- sbom-ops:managed:end -->` の
間は自動更新する。担当者の判断、作業メモ、チェックリストはこの範囲の外かコメントに書く。
範囲外の改行・空白を含む本文と、人が変更したタイトルは保持する。
既存タイトルは更新しないため、最新の優先度は本文の管理範囲で確認する。

優先度ラベルも更新する。標準設定では `sbom` と `sbom-P0`〜`sbom-P3` が
sbom-ops専用の名前になる。この5個は人の独自用途に使わないこと。
`bug` や `team:backend`、`sbom-P0-note` など、それ以外のラベルは保持する。
P0/P1からP2/P3に下がっても既存Issueの本文・ラベルは更新するが、Issueは閉じない。
新規作成は設定した優先度（既定はP0/P1）だけが対象となる。

ラベル全体を置き換えず、必要なものを追加して確認した後、古い優先度だけを外す。
これは[GitHubのラベル追加・個別削除API](https://docs.github.com/en/rest/issues/labels)を使い、
対象repoのIssues書込み権限を必要とする。本文のPATCHにラベル一覧を含めないため、
同期中に人が別のラベルを追加しても消さない。ただし予約名の同時編集は避ける。
応答喪失・403・404などで失敗したら、本文だけ更新済み、または新旧の優先度が両方ある
可能性がある。GitHubで状況と権限を確認し、dry-runの `labels ... add=... remove=...` を
確認してから再実行する。次回は最新のラベルから変更を組み直し、古い操作は自動再送しない。
prefixを変更しても旧prefixは自動削除しない。予約名の移行は対象Issueを確認して行う。

旧形式のIssueは、元の本文全体を「移行前の本文」として残し、新しい管理範囲を追加する。
古いスコア・状態は履歴であり、現在の判定ではない。繰り返し同期しても履歴を重ねて追加しない。
移行前の本文も、人が必要箇所を整理するまで自動削除しない。

区切りやkeyが壊れているときは、推測して本文を上書きせずエラーにする。
Issueの編集履歴とFindingを確認し、区切りと対応関係を直した後にdry-runで再確認する。
本文更新がタイムアウトした場合、反映済みの可能性がある。まずGitHub上の本文を確認する。
古い本文の自動再送はしない。新規作成の結果が不明な場合は、以下の操作記録でも再送を防ぐ。

Issueの対応は、閉じたものも含めた一覧と管理keyで照合する。複数の一致や、
旧keyが複数のFindingに対応する場合は止まる。対象を確認し、勝手な統合・削除はしない。
一覧は最大10ページ（各100件、PRを含む）までで、続きがあれば不完全として失敗する。
ページ取得失敗を「既存Issueなし」とみなして新規作成することはない。
`review-closed`は、同じFindingのIssueが既に閉じられているので人の確認が必要という意味。
Findingと完了理由を照合し、必要なら人がIssueを再オープンしてから再実行する。

作成リクエストの応答が失われた場合はPOSTを再送せず、一覧を再取得する。
`create-reconciled`なら対応するIssueを一意に確認できたことを示す。
`create outcome is unknown`や再取得エラーでは、**同期をすぐに再実行しない**。
GitHub上で作成されたかと対象Findingを確認する。次回はSQLiteの未確定記録を先に照合し、
Issueを一意に確認できた場合だけ記録を確定する（`reconcile-create`）。
見つからなければ、送信前に停止した可能性があっても再送せず停止する。
確定済みIssueの削除・移動・key変更・別番号への置換でも勝手に作り直さない。
記録を消す、別DBを使う、古いバックアップへ戻す方法で回避してはいけない。

### 作成の操作記録（SQLite）

GitHub書込みを行う場合は、単一ホストのローカル永続ディスクに操作記録DBを用意する。
これは資産・PoC台帳とは別の**送信事故防止用DB**で、GitHubの対応状態をコピーするものではない。
資産台帳を復元しても、送信済みの記録が巻き戻らないよう分離している。
認証情報や本文は保存しないが、repo・Finding key・Issue番号を含むため権限は0600とする。
次の初期化は最初の1回だけ。既存ファイルは上書きせず、同期時にも自動作成しない。

```bash
mkdir -p var
sbom-ops workflow --db var/workflow.sqlite3 init
export SBOM_OPS_ISSUE_JOURNAL_FILE=var/workflow.sqlite3
sbom-ops workflow --db var/workflow.sqlite3 show
```

旧版の操作記録DB（schema v1）がある場合は、同期を停止してから次の移行を1回行う。
既存の作成記録を保持したまま、監査用テーブルを追加する。バックアップ先の上書きはしない。
資産台帳の `assets migrate` とは別の操作である。

```bash
sbom-ops workflow --db var/workflow.sqlite3 migrate --backup var/workflow-before-audit.sqlite3
sbom-ops workflow --db var/workflow.sqlite3 audit --run-id '同期結果に出たrun_id'
```

`audit` は読取り専用。`--run-id` を省略すると全記録を表示する。
run IDはCLIの開始からエラー出力まで共通で、本文更新やラベル操作の経過を追える。
`operation_started` は送信前の記録、`operation_confirmed` は確認済み、
`operation_unknown` は結果未確認、`operation_reconciled` は再照合で確認できた操作である。
本文更新だけconfirmedで、ラベル操作がunknownなら、そのIssueの本文とラベルを確認する。
startedしかない操作は「未送信」とは限らない。終了記録のないrunも、プロセス状態と
GitHubを確認するまで成功・失敗・実行中と断定しない。作成意図は `show` でも照合する。
監査保存が失敗すると後続書込みは止まり、失敗JSONに `audit_persistence_failed=true` が出る。
その場合、出力にある記録がDBに残っていない可能性があるため、両方を保全する。
Ctrl+Cはinterrupted（終了コード130）、強制終了では終了記録自体が残らない場合がある。
dry-runや `--no-github`、DBを開く前の失敗はSQLiteには記録されない。
旧DBを移行しても過去の操作監査は追加されない。これはローカルの復旧用記録であり、
DB管理者が書き換えられない監査基盤ではない。

`show` は読取りだけで、`pending`（結果未確定）／`confirmed`（番号確認済み）、
元のrun IDと確認時のrun IDを表示する。`pending` は「未送信」を意味しない。
送信前停止と応答喪失を区別できない記録の再送解除コマンドはまだ提供していない。
その場合はDBとGitHubの状況を保全し、書込みを停止して調査する。

同じDBを使う同期を同時起動すると、後続は終了コード3で停止する。
DBを変えた並列実行や複数ホスト・ネットワークディスクでは保護できない。
DBの移動・バックアップは全同期を停止してから行い、書込み後に古いコピーへ戻さない。
破損・紛失時は新規DBで続けず、GitHubとの照合・復旧を先に行う。
dry-runはDB未設定でも可能だが、実行環境のDBを設定すると未確定記録も確認できる。
dry-run中は記録を変更せず、`--no-github` ではDB自体を使わない。
なお、これだけで有効化準備が完了するわけではない。限定実環境での確認などが残るため、
タイマー実行・本番書込みはまだ有効化しない。

更新直前に本文を読み直すが、読取りと書込みの間の同時編集までは防げない。
有効化検証中は同期を1実行に限定し、その短い更新時間にはIssue本文の編集を避ける。
本文への追記は同期後、または別リソースであるコメントで行う。

### 有効化前の確認

GitHub連携は既定で無効。`github.enabled=true` または `SBOM_OPS_GITHUB_ENABLED=true` に
しただけでは書き込めない。書込みには、その実行の `--github-write` と操作記録DBが必要になる。
書込み許可をYAMLや環境変数に保存する設定はない。旧運用で `enabled=true` のまま
`sync` していた場合、許可の省略はエラーになる。まず `--dry-run` で対象と差分を確認する。
`--github-write` 単独では連携自体を有効化しない。また `--dry-run` や `--no-github` と
併用した場合は、書込み禁止の方を優先する。`plan` は常に表示だけで書き込まない。

当面は `--no-github` を使う。本文・ラベル・重複防止の実環境確認や途中失敗の監査など、
[有効化前の必須事項](../ROADMAP.md#github同期を有効にする前の必須事項)の
最新状況は[開発Issue #7](https://github.com/DharmaDoll/sbom-ops/issues/7)を確認する。
以下は書き込みをしない確認用である。

```bash
export SBOM_OPS_GITHUB_ENABLED=true
export SBOM_OPS_GITHUB_OWNER=your-org
export SBOM_OPS_GITHUB_REPO=your-repo
# SBOM_OPS_GITHUB_TOKENは承認済みの保管先から実行環境へ渡しておく。
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --wait-for-analysis --dry-run
```

`SBOM_OPS_GITHUB_TOKEN`がある場合はそちらが優先される。
検証後は `SBOM_OPS_GITHUB_ENABLED=false` に戻すか、必ず `--no-github` を指定する。
既知の問題の解消と対象・権限・経路の確認後に、限定した対象で書き込みを検証する。
その段階でのみ、確認した同じ `sync` の `--dry-run` を外して `--github-write` を付ける。
通常のQuick startや評価だけの実行には付けない。タイマー実行でも実行コマンド側に明示し、
先に `plan` とdry-runでProject・repo・経路・DBの対象を確認すること。

### 限定した実環境での確認手順

検証用repoとProject、許可するIssue操作・件数を先に合意する。開発Issue更新の許可を
製品によるIssue作成の許可とみなさない。架空の資産と検証用Findingを用い、
初回は1サービス・2ビルド・同一部品/脆弱性の一組、作成は最大1 Issueに限定する。
旧形式からの移行は、別の一組・既存の検証用1 Issueを対象にする。
検証用DB・設定・run ID・対象Issue番号を記録し、本番のDBを使い回さない。
これは検証の開始時に対象を分けるためであり、結果不明時に別DBへ逃げる手順ではない。

| 順序 | 操作 | 確認する結果 |
| --- | --- | --- |
| 1 | 同じ設定・台帳・Project選択でGitHub有効のdry-run | 想定repoの一組だけが作成予定。意図しない更新がない。DBとIssueは非変更 |
| 2 | 各回に `--github-write` を指定し、同じ入力で順に2回同期（並列実行しない） | 2ビルドで1 Issue、2回目は同じ番号。管理ラベル・本文・作成記録・監査が対応する |
| 3 | 検証Issueの管理範囲外にメモ、人のタイトルとラベルを設定して再同期 | 人の変更は保持。優先度変更を伴う検証入力では管理ラベルだけ更新 |
| 4 | 片方のビルドだけ選んで同期、続いて元の全選択で同期 | 未選択の内訳を失わず「今回未確認」。再出現しても同じIssueで、選択縮小だけでは優先度を下げない |
| 5 | 検証用旧形式Issueを、全ビルド選択でdry-run後に同期 | 番号・人の本文・タイトルと旧作成記録を保持し、再実行でも重複しない |
| 6 | 読取り専用tokenで書込みを試す限定失敗検証（別途許可した対象のみ） | エラー・run ID・監査を記録し、成功扱いしない。GitHubと記録を読戻し、後続書込みや重複がない |
| 7 | 同期を止め、結果と残存物を確認 | 本文・ラベル・DB監査・run IDを照合し、連携を無効へ戻す。勝手にIssueや記録を削除しない |

各段階で想定外のrepo/key/番号/件数、403/404、応答不明、監査失敗があれば先へ進まない。
「失敗したからもう一度作る」ことはせず、[本文の扱いと復旧](#本文の扱いと復旧)と
[操作記録](#作成の操作記録sqlite)に従う。read-only検証の失敗を理由に権限を広げない。
通信応答喪失・プロセス停止・監査保存失敗は模擬GitHubと一時DBの回帰テストで確認する。
実GitHubへ意図的なネットワーク障害を起こして、同じ証明を得たことにはしない。
実検証の記録には日時、commit、対象の範囲、tokenの種類と権限（値は不可）、
各操作の期待値・結果・Issue番号・run ID、ローカル証跡の場所、未確認事項を残し、
開発Issue #7へ秘密値や非公開の本文を転載せず検証要約を反映する。
限定検証の成功は本番全体や定期実行の承認ではない。展開範囲・保管・同時実行の条件を別途確認する。
