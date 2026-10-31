# SBOM供給の導入例

[担当別の手順・業務フロー・失敗時対応](../../docs/sbom-producers.md)から始める。

- `npm/`・`uv/`: 同じ架空サービスの配布単位、固定lockとDockerfile。
- `source.sh`: PR向けSource生成。DTへは送らない。
- `handoff.py`: Buildの対象・代表依存・hash確認と、明示したDT投入。
- `registration.json`: 運用担当がpreviewしてから保存する台帳入力。
- `workflows/`: PR確認・配布ビルド・明示投入のActions例。配置するまで起動しない。

固定版は検証用基準であり、安全性・完全性・最新版の推薦ではない。
元SBOM・補足証拠・CI参照は導入先の保持期間とアクセス権で管理する。
