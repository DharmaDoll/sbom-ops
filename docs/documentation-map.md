# 文書配置表

[運用ガイド](operations.md)の保守用索引。利用者は[利用シーン](use-cases.md)から作業を選ぶ。
設計元はplan.mdの計画1、進捗と検証記録は[開発Issue #26](https://github.com/DharmaDoll/sbom-ops/issues/26)。
分類基準は「概要／初回導入／日常操作／詳細参照／設計・将来」。
既存の手順を初回導入から移し、入力・期待結果・失敗時の案内を各ページ冒頭に置く。
仕様の正本はSPEC、操作は各手順、実験の事実はlabのEXPERIMENTSに維持する。

## 文書の役割

| 文書 | 役割 |
| --- | --- |
| README | できること・最初に開くページ |
| use-cases | 起点・担当・行動・結果・次の手順 |
| operations | 作業別入口・旧リンクの転送先 |
| 個別手順 | 前提・入力・操作・期待結果・失敗時の確認先 |
| SPEC | 状態・識別・判定・失敗時動作の契約 |

## operationsの全節と移動先

旧見出しはすべてoperations側に残す。見出し内の「一部実装」も旧URLの互換性のために保持し、
移動先では現在の機能と未提供部分を区別する。コードブロック内のコメントは見出しに数えない。

| 旧節 | 分類 | 配置先 |
| --- | --- | --- |
| [運用ガイド](operations.md#運用ガイド) | 概要 | [operations.md](operations.md#運用ガイド) |
| [利用者の作業一覧：いつ・どこで・何をするか](operations.md#利用者の作業一覧いつどこで何をするか) | 概要 | [operations.md](operations.md#利用者の作業一覧いつどこで何をするか) |
| [運用担当者向けの初回演習](operations.md#運用担当者向けの初回演習) | 初回導入 | [getting-started.md](getting-started.md#運用担当者向けの初回演習) |
| [1. 架空例で役割分担を理解する（約10分）](operations.md#1-架空例で役割分担を理解する約10分) | 初回導入 | [getting-started.md](getting-started.md#1-架空例で役割分担を理解する約10分) |
| [2. 人が資産を登録し、DTへ直接SBOMを送る（約20分）](operations.md#2-人が資産を登録しdtへ直接sbomを送る約20分) | 初回導入 | [getting-started.md](getting-started.md#2-人が資産を登録しdtへ直接sbomを送る約20分) |
| [3. DT画面でProjectとFindingを追う（約20分）](operations.md#3-dt画面でprojectとfindingを追う約20分) | 初回導入 | [getting-started.md](getting-started.md#3-dt画面でprojectとfindingを追う約20分) |
| [4. DT Projectを資産台帳へ紐づける（約10分）](operations.md#4-dt-projectを資産台帳へ紐づける約10分) | 初回導入 | [getting-started.md](getting-started.md#4-dt-projectを資産台帳へ紐づける約10分) |
| [5. sbom-opsの結果と照合する（約20分）](operations.md#5-sbom-opsの結果と照合する約20分) | 初回導入 | [getting-started.md](getting-started.md#5-sbom-opsの結果と照合する約20分) |
| [任意: 稼働環境の情報が必要になったら](operations.md#任意-稼働環境の情報が必要になったら) | 初回導入 | [getting-started.md](getting-started.md#任意-稼働環境の情報が必要になったら) |
| [記録と完了条件](operations.md#記録と完了条件) | 初回導入 | [getting-started.md](getting-started.md#記録と完了条件) |
| [SBOMと稼働資産を結ぶ運用フロー（一部実装）](operations.md#sbomと稼働資産を結ぶ運用フロー一部実装) | 日常操作 | [assets.md](assets.md#sbomと稼働資産を結ぶ運用フロー一部実装) |
| [登録単位と新規サービスの開始順序](operations.md#登録単位と新規サービスの開始順序) | 初回導入 | [assets.md](assets.md#登録単位と新規サービスの開始順序) |
| [ライフサイクルで情報を混同しないための確認](operations.md#ライフサイクルで情報を混同しないための確認) | 日常操作 | [assets.md](assets.md#ライフサイクルで情報を混同しないための確認) |
| [Source/Build根拠の登録と訂正](operations.md#sourcebuild根拠の登録と訂正) | 日常操作 | [assets.md](assets.md#sourcebuild根拠の登録と訂正) |
| [保存済みの結果からCVE・部品を逆引きする](operations.md#保存済みの結果からcve部品を逆引きする) | 詳細参照 | [investigation.md](investigation.md#保存済みの結果からcve部品を逆引きする) |
| [架空の速報から資産・担当を確認する（外部通信なし）](operations.md#架空の速報から資産担当を確認する外部通信なし) | 詳細参照 | [investigation.md](investigation.md#架空の速報から資産担当を確認する外部通信なし) |
| [架空のSource・再ビルド・SBOM訂正を登録する](operations.md#架空のsource再ビルドsbom訂正を登録する) | 日常操作 | [assets.md](assets.md#架空のsource再ビルドsbom訂正を登録する) |
| [DTから読み戻して紐づける方法](operations.md#dtから読み戻して紐づける方法) | 日常操作 | [assets.md](assets.md#dtから読み戻して紐づける方法) |
| [担当・重要度を変更する](operations.md#担当重要度を変更する) | 日常操作 | [assets.md](assets.md#担当重要度を変更する) |
| [資産の廃止と紐付けの訂正](operations.md#資産の廃止と紐付けの訂正) | 日常操作 | [assets.md](assets.md#資産の廃止と紐付けの訂正) |
| [将来の資産収集と台帳の保管](operations.md#将来の資産収集と台帳の保管) | 設計・将来 | [assets.md](assets.md#将来の資産収集と台帳の保管) |
| [固定成果物を使ったローカル通し検証](operations.md#固定成果物を使ったローカル通し検証) | 日常操作 | [assets.md](assets.md#固定成果物を使ったローカル通し検証) |
| [CIが作った成果物での確認](operations.md#ciが作った成果物での確認) | 日常操作 | [assets.md](assets.md#ciが作った成果物での確認) |
| [日常の運用とログ](operations.md#日常の運用とログ) | 日常操作 | [daily-operations.md](daily-operations.md#日常の運用とログ) |
| [同じサービスで更新・担当変更・停止を通す](operations.md#同じサービスで更新担当変更停止を通す) | 日常操作 | [daily-operations.md](daily-operations.md#同じサービスで更新担当変更停止を通す) |
| [日常の流れ](operations.md#日常の流れ) | 日常操作 | [daily-operations.md](daily-operations.md#日常の流れ) |
| [任意の評価入力](operations.md#任意の評価入力) | 詳細参照 | [investigation.md](investigation.md#任意の評価入力) |
| [PoC報告を明示的に取得する](operations.md#poc報告を明示的に取得する) | 詳細参照 | [investigation.md](investigation.md#poc報告を明示的に取得する) |
| [PoC更新を定期実行する](operations.md#poc更新を定期実行する) | 詳細参照 | [investigation.md](investigation.md#poc更新を定期実行する) |
| [CVE対応候補を確認する](operations.md#cve対応候補を確認する) | 詳細参照 | [investigation.md](investigation.md#cve対応候補を確認する) |
| [CVE対応候補の採用・取消を記録する](operations.md#cve対応候補の採用取消を記録する) | 詳細参照 | [investigation.md](investigation.md#cve対応候補の採用取消を記録する) |
| [採用したCVE対応をPoC取得・表示へ使う](operations.md#採用したcve対応をpoc取得表示へ使う) | 詳細参照 | [investigation.md](investigation.md#採用したcve対応をpoc取得表示へ使う) |
| [GitHub同期の確認](operations.md#github同期の確認) | 詳細参照 | [github-sync.md](github-sync.md#github同期の確認) |
| [権限と送信先を先に固定する](operations.md#権限と送信先を先に固定する) | 詳細参照 | [github-sync.md](github-sync.md#権限と送信先を先に固定する) |
| [複数ビルドを一つの修正作業として扱う](operations.md#複数ビルドを一つの修正作業として扱う) | 詳細参照 | [github-sync.md](github-sync.md#複数ビルドを一つの修正作業として扱う) |
| [本文の扱いと復旧](operations.md#本文の扱いと復旧) | 詳細参照 | [github-sync.md](github-sync.md#本文の扱いと復旧) |
| [作成の操作記録（SQLite）](operations.md#作成の操作記録sqlite) | 詳細参照 | [github-sync.md](github-sync.md#作成の操作記録sqlite) |
| [有効化前の確認](operations.md#有効化前の確認) | 詳細参照 | [github-sync.md](github-sync.md#有効化前の確認) |
| [限定した実環境での確認手順](operations.md#限定した実環境での確認手順) | 詳細参照 | [github-sync.md](github-sync.md#限定した実環境での確認手順) |
| [CISA評価の取得・保存・表示](operations.md#cisa評価の取得保存表示) | 詳細参照 | [investigation.md](investigation.md#cisa評価の取得保存表示) |
| [同期結果に参照情報を添える](operations.md#同期結果に参照情報を添える) | 詳細参照 | [investigation.md](investigation.md#同期結果に参照情報を添える) |
| [BOD参照の判断支援を架空データで試す](operations.md#bod参照の判断支援を架空データで試す) | 詳細参照 | [investigation.md](investigation.md#bod参照の判断支援を架空データで試す) |
| [運用担当者が確認する順序](operations.md#運用担当者が確認する順序) | 詳細参照 | [investigation.md](investigation.md#運用担当者が確認する順序) |
| [SBOM最低要素の確認について](operations.md#sbom最低要素の確認について) | 詳細参照 | [sbom-input.md](sbom-input.md#sbom最低要素の確認について) |
| [コンテナのSBOMを生成してDTへ送るタイミング](operations.md#コンテナのsbomを生成してdtへ送るタイミング) | 詳細参照 | [sbom-input.md](sbom-input.md#コンテナのsbomを生成してdtへ送るタイミング) |
| [実際に生成したSBOMで試す](operations.md#実際に生成したsbomで試す) | 詳細参照 | [sbom-input.md](sbom-input.md#実際に生成したsbomで試す) |
| [欠落を改善する担当と、訂正・例外の扱い](operations.md#欠落を改善する担当と訂正例外の扱い) | 詳細参照 | [sbom-input.md](sbom-input.md#欠落を改善する担当と訂正例外の扱い) |
| [CIで結果を保存してから終了コードを返す](operations.md#ciで結果を保存してから終了コードを返す) | 詳細参照 | [sbom-input.md](sbom-input.md#ciで結果を保存してから終了コードを返す) |
| [YAML configuration](operations.md#yaml-configuration) | 概要 | [operations.md](operations.md#yaml-configuration) |

## use-casesの全節と整理先

短いシナリオへ統合する。識別key・Issue同期条件・受入仕様は既存のSPECを参照し、
利用シーンに重複した契約を維持しない。旧アンカーは対応するシナリオの直前に残す。

| 旧節 | 分類 | 配置先・仕様の正本 |
| --- | --- | --- |
| [業務フローと利用シーン](use-cases.md#業務フローと利用シーン) | 概要 | [use-cases.md](use-cases.md) |
| [システム間の責務](use-cases.md#システム間の責務) | 概要 | [参照先](use-cases.md#役割と判断の記録先) |
| [Security担当による一元管理](use-cases.md#security担当による一元管理) | 概要 | [参照先](use-cases.md#役割と判断の記録先) |
| [フロー0: Findingを自社の仕事に結び付ける](use-cases.md#フロー0-findingを自社の仕事に結び付ける) | 初回導入 | [参照先](use-cases.md#1-初回導入サービス登録) |
| [起点](use-cases.md#起点) | 初回導入 | [参照先](use-cases.md#1-初回導入サービス登録) |
| [現在の手順（一部実装）](use-cases.md#現在の手順一部実装) | 初回導入 | [参照先](use-cases.md#1-初回導入サービス登録) |
| [フロー1: 通常の定期同期](use-cases.md#フロー1-通常の定期同期) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [起点](use-cases.md#起点-1) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [手順](use-cases.md#手順) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [結果](use-cases.md#結果) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [フロー2: KEV登録による緊急対応](use-cases.md#フロー2-kev登録による緊急対応) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [起点](use-cases.md#起点-2) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [手順](use-cases.md#手順-1) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [制約](use-cases.md#制約) | 概要 | [参照先](use-cases.md#4-日常確認脆弱性通知への対応) |
| [フロー3: Security担当によるトリアージ](use-cases.md#フロー3-security担当によるトリアージ) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [起点](use-cases.md#起点-3) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [手順](use-cases.md#手順-2) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [トリアージの判断](use-cases.md#トリアージの判断) | 詳細参照 | [参照先](priority-policy.md) |
| [フロー4: サプライヤーVEXの取り込み](use-cases.md#フロー4-サプライヤーvexの取り込み) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [起点](use-cases.md#起点-4) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [手順](use-cases.md#手順-3) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [制約](use-cases.md#制約-1) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [フロー5: 開発者による脆弱性修正](use-cases.md#フロー5-開発者による脆弱性修正) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [起点](use-cases.md#起点-5) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [手順](use-cases.md#手順-4) | 概要 | [参照先](use-cases.md#5-調査修正完了確認) |
| [フロー6: Dry-runによる導入・ポリシー検証](use-cases.md#フロー6-dry-runによる導入ポリシー検証) | 初回導入 | [参照先](use-cases.md#1-初回導入サービス登録) |
| [起点](use-cases.md#起点-6) | 初回導入 | [参照先](use-cases.md#1-初回導入サービス登録) |
| [手順](use-cases.md#手順-5) | 初回導入 | [参照先](use-cases.md#1-初回導入サービス登録) |
| [共通ルール](use-cases.md#共通ルール) | 詳細参照 | [参照先](../SPEC.md#workflow-rules) |
| [MVPで確認する受入条件](use-cases.md#mvpで確認する受入条件) | 詳細参照 | [参照先](../SPEC.md#testing-strategy) |

## 現行仕様との照合で直す記載

| 旧記載 | 現行の説明・根拠 |
| --- | --- |
| 成果物・稼働情報は未実装 | 根拠登録・期限付き申告・訂正・照合を提供。SPECのAsset Registry・根拠登録v1、CLIのevidence-register/report-deploymentに対応 |
| サービス更新・廃止・リンク撤回は後続課題 | update-service/retire-service/retire-deployable/revoke-linkを提供。独立した配備先の自動観測は将来 |
| 定期同期のたびにSBOMを送信 | 新成果物・SBOM訂正で投入。同一成果物の再配備・新CVEだけでは再送しない（SPECの生成・投入契約） |
| 定期同期で必ずGitHub起票 | 通常は確認用一覧。GitHubは既定無効・#7で有効化保留 |
| 新規DB・移行先はv10 | 資産DBのCURRENT_SCHEMA_VERSIONは12。各操作の最低必要版と最新の作成・移行先を区別 |
| 採用CVEとPoCの接続は今後 | 取得・表示それぞれの明示オプションで接続可能。定期ジョブへの自動接続とは区別 |
| `sync --format` | 現行CLIの`--output`へ修正 |
| 品質評価は開発中 | sbom-qualityを提供。網羅性・署名・適合認定は保証しない |

## 参照の維持方針

READMEと現行の案内からは移動先へ直接リンクする。Issue本文とコメントで確認した参照のうち、
#18のmain追従リンクは旧アンカーで維持する。#6/#7/#11/#12/#13/#23/#24の固定コミット参照は
当時の検証根拠なので変更しない。外部サイトの全バックリンクは列挙できないため、
既知の参照有無にかかわらず旧operations/use-casesの全見出しアンカーを残す。
文書移動だけを理由にIssueの過去の検証記録を書き換えない。

## 後続の文書拡張

計画2の生成器別CI例は生成・投入手順から、計画3の通知手順は日常確認から案内する。
手順・運用条件が確定する前に利用可能とは記載しない。内部の識別・状態契約を変更する場合は
SPECを先に更新し、操作ページはその参照と操作への影響だけを説明する。
