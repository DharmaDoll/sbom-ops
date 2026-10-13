# Roadmap

目的は、DTの脆弱性情報を自社サービス・担当・稼働状況に結び付け、
運用担当者が対応順と次の行動を判断できるようにすること。

この文書は未完了の作業・優先順位・完了条件を管理する。
実装仕様は[SPEC](SPEC.md)、操作は[運用ガイド](docs/operations.md)、
観測事実は各labのEXPERIMENTSに残す。過去の実験日誌はここへ重複掲載しない。

## 現在地

- DT読取、KEV/EPSS/CVSSの評価、GitHubなしの同期とJSON出力は実装済み。
- SQLiteへサービス・配布単位・承認したProject対応・期限付き稼働申告を保存できる。
  申告訂正、担当・重要度更新、廃止、リンク撤回と再承認、履歴とschema v5への移行も実装済み。
- PoC報告は`poc-fetch`で取得し、資産と同じSQLite（schema v6）の専用テーブルに保存する。
  成功情報の再利用・一件ずつの保存・失敗時の過去成功保持を実装済み。JSONは任意出力。
  定期実行と通信制限後の再試行制御は未実装。
- `--output review`とJSONの`review_queue`でFinding・担当・環境を一緒に表示できる。
  資産情報は参考情報であり、P0〜P3やIssue操作を変えない。
- CIのデモ成果物 → SBOM → DT → 資産照合 → 停止申告の通し検証は完了。
  本番のSBOM網羅性・実稼働・公開範囲を証明したわけではない。
- GitHub同期は実装されているが、有効化前の修正と検証が残る。当面は無効で進める。

## 直近の実装順序

2026-10-12のレビューを受け、次の順を採用する。
ここでの「高・中・低」は開発の優先度であり、脆弱性のP0〜P3とは別である。

| 順序 | 作業 | 優先度・必須度 | 完了条件 |
| --- | --- | --- | --- |
| 1 | [#15 PoCの未来日時判定を修正](https://github.com/DharmaDoll/sbom-ops/issues/15) | 高・必須 | 観測前のデータを有効にしない。現在・未来・期限切れを固定時刻で検証 |
| 2 | [#16 サービス・担当・環境とFindingをまとめた対応一覧](https://github.com/DharmaDoll/sbom-ops/issues/16) | 高・製品の中心機能 | P0→P3で表示し、PoCの有無と理由、資産の確認状態を同じ出力で読める |
| 3 | [#17 資産台帳の更新・廃止・リンク訂正](https://github.com/DharmaDoll/sbom-ops/issues/17) | 高・継続運用に必須 | 担当/重要度変更、誤紐付け撤回、廃止を理由・変更者・履歴付きで処理 |
| 4 | [#18 PoC取得・更新を通常運用へ接続](https://github.com/DharmaDoll/sbom-ops/issues/18) | 高・PoC運用に必須 | 対象CVE抽出、設定可能な更新間隔、キャッシュ、期限切れ、失敗表示が一連で動く |
| 5 | [#11 1サービスで運用を通して確認](https://github.com/DharmaDoll/sbom-ops/issues/11) | 高・運用開始に必須 | 登録→CI投入→紐付け→評価→更新→担当変更→停止を再現し、担当者が次の行動を説明できる |
| 6 | [#7 GitHub同期の修正と有効化検証](https://github.com/DharmaDoll/sbom-ops/issues/7) | 中・有効化時に必須 | 下記の条件を満たし、限定対象のdry-run後に作成・更新を確認 |

文書整理はこの順序を支える作業として先に行う。
入口をREADME、操作を運用ガイド、仕様をSPEC、未完了計画を本書へ集約する。
この文書更新だけで上記の実装を完了扱いにしない。

#15の未来日時修正と#16の確認用一覧はローカル実装・自動テスト済み。
コミット・公開後の確認まではIssueを閉じない。
#17は担当・重要度更新、廃止・リンク撤回と再承認、履歴、v5移行と演習までローカル実装済み。
公開・確認後に完了扱いにする。
#18は対象抽出、独立した取得コマンド、期限付き保存、失敗表示をローカル実装済み。
公開CVE 1件で応答を確認し、通信なしの演習も用意した。
SQLite保存・最終成功の継続保持・設定間隔内の再利用・中断後の再実行もローカル実装済み。
次は通信制限後の再試行制御と定期実行の運用を整える。

対応一覧は、サービス／担当／環境／稼働申告／外部公開申告／CVE／PoC有無／評価理由を結ぶ。
未紐付け・期限切れ・矛盾は確認事項として残し、根拠なく担当や稼働状態を補わない。
P0〜P3の変更や自動的なリスク受容は、この表示改善には含めない。
PoC件数は情報源別の参考値とし、PoCの有効性を独自評価しない。

PoC取得は製品用の独立したadapterと契約テストを用意する。
Vulnerability-Lookupをオンライン候補、Vuls vuls.dbを比較・オフライン候補とする。
labを製品からimportせず、対象サービスのCVEを必要な頻度で更新する。
非CVE ID・未解決alias・通信失敗は「PoCなし」にしない。
利用先のAPI認証・利用条件・制限を実行前に確認し、一般の公開参照をPoC件数に混ぜない。

## GitHub同期を有効にする前の必須事項

実装と進捗は[#7](https://github.com/DharmaDoll/sbom-ops/issues/7)、
読取失敗・解析途中・クローズ条件は[#6](https://github.com/DharmaDoll/sbom-ops/issues/6)で追跡する。

- 人がIssue本文に加えた内容を保存し、自動管理部分だけを更新する。
- 優先度変更時に管理対象ラベルも更新し、人のラベルは残す。
- 作成結果が不明な通信失敗を無条件に再POSTせず、照合して重複を防ぐ。
  検索結果の先頭を無検証で採用せず、管理対象keyを確認する。
- 成果物ごとのFinding識別と、サービスの修正作業をまとめる単位を決める。
  同じCVEが複数ビルドに存在するだけで作業を無制限に増やさない。
- 読取から書込まで同じrun IDを使い、途中までの操作と失敗を追跡可能にする。
- 対象リポジトリ・ラベル・権限・Project経路を限定して検証する。
  大量Issueの取得上限・欠落も確認する。

自動クローズは無効を維持する。応答が2回安定しただけでは修正確認にならない。
当面は欠落を「確認待ち」として扱い、自動クローズは成果物・解析状況・連続不在を
含む追加条件が決まった場合だけ別途有効化する。
GitHubを使わない段階では、これらを理由に資産・対応一覧の開発を止めない。

## 運用開始までに並行して整えること

| 作業 | 優先度・必須度 | 完了条件 |
| --- | --- | --- |
| [#19 PoC供給経路のCIテスト](https://github.com/DharmaDoll/sbom-ops/issues/19) | 中・当該機能の継続開発に必要 | Exploit Intelligenceの関連テストをCIで実行し、不具合の再発を検知 |
| SQLite運用 | 中・永続台帳に必須 | 保存先、バックアップ保管、保持期間、復元手順と訓練を決める |
| 情報源の鮮度・失敗表示 | 中・定期運用に必須 | 最終成功と観測不能を区別する。設定された更新間隔だけで「最新」としない |
| 成果物対応の拡張 | 中・対象構成に応じて必要 | 複数コンテナ、新旧並存、再投入、SBOM訂正、欠落・重複を扱う |
| [#13 優先度と期限の方針](https://github.com/DharmaDoll/sbom-ops/issues/13) | 中・期限管理導入時に必要 | SLAを優先度と別管理し、資産・公開範囲を使うルールは人がレビュー |
| [#12 SBOM最低要素](https://github.com/DharmaDoll/sbom-ops/issues/12)・[#13 BOD 26-04](https://github.com/DharmaDoll/sbom-ops/issues/13)の対応整理 | 中・採用要件に応じて必要 | 既存Issueで原文・適用範囲・差分・受入条件を確認し、未確認の適合を主張しない |

単一ホスト・手入力中心は維持する。SQLiteを共有ファイル化せず、複数ホストからの
書込が必要になった場合だけサーバーDBを検討する。CIはDTに直接SBOMを送り続ける。

## 後回しにする作業

- AWS/EKS/ECS等の自動発見：人の登録では解消できない不足が明確になったとき。
- Google Cloud基盤：配備先として必要になったとき。ローカルの運用完成を妨げない。
  [SPECの基盤要件](SPEC.md#google-cloud-deployment-contract)と
  [ADR 0001](docs/adr/0001-gcp-secure-delivery-runtime.md)は維持する。
- VEX書込：DTを正本とし、対象範囲の解決・差分・人の承認・投入後照合が必要になったとき。
- 到達可能性、LLM支援、Jira、Slack/Teams、SARIF、ダッシュボード、マルチテナント。
- 追加のPoC品質審査・複数人の判定一致率・大規模lab網羅検証。
  PoCの動作評価は製品の目的に含めない。
- NFS・停電・ホスト障害の追加実験：実際の配備条件で必要となった場合。

## 過去のPhaseとの対応

従来のPhase番号は過去のIssueや議論を読むために残す。番号順の実装は要求しない。

| 従来のPhase | 現在の扱い |
| --- | --- |
| Phase 0: Production Validation | 直近1〜5と運用開始条件 |
| Phase 1: Operations Foundation | 資産運用・PoC更新・監査を先行。GitHubは直近6 |
| Phase 0.5: Secure GCP Delivery | 配備先として必要になるまで延期 |
| Phase 2: Human-reviewed VEX | 必要時に再開 |
| Phase 3: Reachability Evidence | 後続 |
| Phase 4: LLM Triage Assistance | 後続 |
| Phase 5: Integrations and Visibility | 後続 |

## Work tracking and decision records

ROADMAPは成果・順序・見送り理由、GitHub Issuesは個別作業の範囲・受入条件・進捗を管理する。
`type:decision / type:implementation / type:lab` を使い、
製品が作る脆弱性対応Issue用の `type:remediation` と区別する。
着手時に既存Issueを確認して重複を避け、完了時に実装・テスト・仕様へリンクする。
2026-10-13に直近作業をIssueへ登録・更新した。最新の進捗はIssueのラベルと
チェックリストで確認し、本書には進捗率を重複記載しない。

- `priority:high / priority:medium`：開発優先度。製品の脆弱性用`sbom-P0/P1`とは別。
- `status:todo`：未着手。`status:partial`：一部完了で残作業あり。
- 実装・検証中は`status:in-progress`に変更し、完了条件を満たしたら根拠を付けてcloseする。
  進捗ラベルは同時に一つだけ付ける。先行作業待ちは本文の関連Issueで示す。
- [優先度が高い未完了Issue](https://github.com/DharmaDoll/sbom-ops/issues?q=is%3Aissue%20is%3Aopen%20label%3Apriority%3Ahigh)
  から次の作業を選ぶ。

観測結果は[DT検証記録](lab/dependency_track/EXPERIMENTS.md)と
[脅威情報の検証記録](lab/exploit_intelligence/EXPERIMENTS.md)を参照する。
2026-10-12のCIデモ通し検証も前者に記録済み。
追加labは、実装に必要なDT挙動が既存の証拠から判断できない場合だけ実施する。
失敗・部分結果を含め記録し、実験一覧を消化すること自体を目標にしない。
