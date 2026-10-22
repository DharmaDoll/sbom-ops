# Roadmap

目的は、DTの脆弱性情報を自社サービス・担当・稼働状況に結び付け、
運用担当者が対応順と次の行動を判断できるようにすること。

この文書は成果の方向性・実装順序・見送り理由を管理する。
個別作業の進捗と完了条件の正本はGitHub Issuesとし、本文の状態をここへ重複掲載しない。
実装仕様は[SPEC](SPEC.md)、操作は[運用ガイド](docs/operations.md)、
観測事実は各labのEXPERIMENTSに残す。過去の実験日誌はここへ重複掲載しない。

## 基本方針

- DTをSBOM台帳の正本とし、CIから直接投入する。中間サーバは作らない。
- 自社のサービス・担当・配布単位・承認したProject対応・期限付き稼働申告はSQLiteで扱う。
- PoCは有無・情報源別件数・観測時点を扱い、資産と同じSQLiteへ保存する。動作の有効性は評価しない。
- 資産情報とFindingを結び、対応順と確認事項を示す。申告を実稼働・公開範囲の独立した証明と扱わない。
- GitHub同期は最後に検証する。それまではGitHubなしで運用確認を進める。

## 直近の実装順序

対応一覧・資産更新の基盤を踏まえ、次はPoC運用、1サービスの通し確認、GitHub同期の順とする。
個別の完了／未完了はリンク先のIssueで確認する。
ここでの「高・中・低」は開発の優先度であり、脆弱性のP0〜P3とは別である。

| 順序 | 作業 | 優先度・必須度 | 目指す成果 |
| --- | --- | --- | --- |
| 1 | [#18 PoC取得・更新を通常運用へ接続](https://github.com/DharmaDoll/sbom-ops/issues/18) | 高・PoC運用に必須 | CVE対応の根拠を保ち、取得・更新・期限切れ・失敗表示を一連で扱う |
| 2 | [#11 1サービスで運用を通して確認](https://github.com/DharmaDoll/sbom-ops/issues/11) | 高・運用開始に必須 | 登録→CI投入→紐付け→評価→更新→担当変更→停止を再現し、担当者が次の行動を説明できる |
| 3 | [#7 GitHub同期の修正と有効化検証](https://github.com/DharmaDoll/sbom-ops/issues/7) | 中・有効化時に必須 | 下記の方針に従い、限定対象で作成・更新を確認 |

基盤となる作業は[#15 日時判定](https://github.com/DharmaDoll/sbom-ops/issues/15)、
[#16 対応一覧](https://github.com/DharmaDoll/sbom-ops/issues/16)、
[#17 台帳更新](https://github.com/DharmaDoll/sbom-ops/issues/17)を参照する。

#18では有効な採用済みCVE対応だけをPoC取得・表示へ限定接続する。
元IDとDT情報源・採用根拠を残し、期限切れ・取消・新観測では不明として扱う。
KEV照合・P0〜P3・DT分析・Issue操作へは対応を流用しない。
定期ジョブへの組込みより、限定した対象での接続確認を先行する。
既存の確認方針を無断で緩めず、labのレビュー基盤を丸ごと移植しない。
説明文・related・upstreamからの推測やDT設定変更はしない。
その後#11の資産・担当を含む運用確認へつなげる。追加の網羅的lab検証や頻度調整を先行させない。

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

| 作業 | 優先度・必須度 | 目指す成果 |
| --- | --- | --- |
| [#19 PoC供給経路のCIテスト](https://github.com/DharmaDoll/sbom-ops/issues/19) | 中・当該機能の継続開発に必要 | Exploit Intelligenceの関連テストをCIで実行し、不具合の再発を検知 |
| SQLite運用 | 中・永続台帳に必須 | 保存先、バックアップ保管、保持期間、復元手順と訓練を決める |
| 情報源の鮮度・失敗表示 | 中・定期運用に必須 | 最終成功と観測不能を区別する。設定された更新間隔だけで「最新」としない |
| 成果物対応の拡張 | 中・対象構成に応じて必要 | 複数コンテナ、新旧並存、再投入、SBOM訂正、欠落・重複を扱う |
| [#13 優先度と期限の方針](https://github.com/DharmaDoll/sbom-ops/issues/13) | 中・期限管理導入時に必要 | SLAを優先度と別管理し、資産・公開範囲を使うルールは人がレビュー |
| [#12 SBOM最低要素](https://github.com/DharmaDoll/sbom-ops/issues/12)・[#13 BOD 26-04](https://github.com/DharmaDoll/sbom-ops/issues/13)の対応整理 | 中・採用要件に応じて必要 | 既存Issueで原文・適用範囲・差分・受入条件を確認し、未確認の適合を主張しない |

#13は[4要素と期限の設計案](docs/priority-policy.md#bod-26-04から参考にすること)に沿い、
資産との対応を保った証拠モデル・合成fixture・公式情報の取得契約・読取り専用の参照表示を先行する。
自社ポリシーの承認後に期限管理へ接続し、P0〜P3を指令の日数へ機械的に置き換えない。
公開状態などのunknownをCISAの補完規則で自動的に埋めない。GitHub実書込みの検証先待ちとは独立して進める。

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
| Phase 0: Production Validation | PoC運用・1サービスの通し確認と運用開始条件 |
| Phase 1: Operations Foundation | 資産運用・PoC更新・監査を先行。GitHub同期は最後 |
| Phase 0.5: Secure GCP Delivery | 配備先として必要になるまで延期 |
| Phase 2: Human-reviewed VEX | 必要時に再開 |
| Phase 3: Reachability Evidence | 後続 |
| Phase 4: LLM Triage Assistance | 後続 |
| Phase 5: Integrations and Visibility | 後続 |

## Work tracking and decision records

ROADMAPは成果・順序・見送り理由、GitHub Issuesは個別作業の範囲・受入条件・進捗を管理する。
`type:decision / type:implementation / type:lab` を使い、
製品が作る脆弱性対応Issue用の `type:remediation` と区別する。
着手・中断・公開・完了時の更新手順は[AGENTS.md](AGENTS.md#開発issueの更新完了手順)に従う。
最新の進捗・完了条件はIssueの本文、ラベルとチェックリストで確認し、本書には重複記載しない。
コミット・CI・検証記録を根拠に完了を判断し、コメントだけ更新して古い本文を残さない。

- `priority:high / priority:medium`：開発優先度。製品の脆弱性用`sbom-P0/P1`とは別。
- `status:todo`：未着手。`status:partial`：一部完了で残作業あり。
- 実装・検証中は`status:in-progress`に変更し、完了条件を満たしたら根拠を付けてcloseする。
  進捗ラベルは同時に一つだけ付ける。先行作業待ちは本文の関連Issueで示す。
- [優先度が高い未完了Issue](https://github.com/DharmaDoll/sbom-ops/issues?q=is%3Aissue%20is%3Aopen%20label%3Apriority%3Ahigh)
  から次の作業を選ぶ。

観測結果は[DT検証記録](lab/dependency_track/EXPERIMENTS.md)と
[脅威情報の検証記録](lab/exploit_intelligence/EXPERIMENTS.md)を参照する。
追加labは、実装に必要なDT挙動が既存の証拠から判断できない場合だけ実施する。
失敗・部分結果を含め記録し、実験一覧を消化すること自体を目標にしない。
