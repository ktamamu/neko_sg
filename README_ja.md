# NeKo_AWS_SG (<u>Ne</u>twork <u>K</u>it <u>o</u>f AWS Security Group)
<div align="center">
<img src="icon.png" alt="neko" width="200">
</div>

NeKo_AWS_SGは、AWSセキュリティグループを監視し、グローバルインターネットに開放されたインバウンドルールを持つものを検出するツールです。検出結果はSlackに通知されます。

## 機能

- AWSアカウント内のすべてのセキュリティグループをスキャン（すべてのセキュリティグループを取得するため、大量のAPI呼び出しが発生する可能性があります）
- グローバルインターネットに開放されたインバウンドルールを持つセキュリティグループを検出
- 検出結果をレポートとして出力
- 検出結果をSlackに通知

## 前提条件

- Python 3.11以上
- [uv](https://docs.astral.sh/uv/) (Pythonパッケージインストーラー・リゾルバー)
- AWSアクセスキーとシークレットキー
- Slack Webhook URL

## セットアップ

1. リポジトリをクローン
   ```bash
   git clone https://github.com/ktamamu/neko_sg.git
   cd　neko_sg
   ```

2. uv をインストール（まだインストールしていない場合）
   ```bash
   # macOS と Linux の場合
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Windows の場合
   powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

3. uv を使用して依存関係をインストール
   ```bash
   uv sync
   ```

4. 環境変数とAWS認証情報の設定

   a. Slack Webhook URLの設定

   プロジェクトのルートディレクトリに .env ファイルを作成し、以下の内容を含めてください：

   ```
   SLACK_WEBHOOK_URL=your_slack_webhook_url
   ```

   または、環境変数を直接設定することもできます

   ```
   export SLACK_WEBHOOK_URL=your_slack_webhook_url
   ```

   b. AWS認証情報の設定

   aws configure コマンドを使用してAWS認証情報を設定してください：
   ```
   aws configure
   ```

   プロンプトに従って、AWSアクセスキーID、AWSシークレットアクセスキー、デフォルトリージョン名、出力形式を入力してください。

## 使用方法

ルートディレクトリから以下のコマンドを実行してください：

```bash
# uv を使用してスクリプトを実行
uv run python src/main.py

# またはエントリーポイント経由で実行
uv run neko-sg
```

### 開発

開発時は、オプションの開発依存関係をインストールできます：

```bash
# 開発依存関係込みでインストール
uv sync --extra dev

# リンティング実行
uv run ruff check src/

# 型チェック実行
uv run mypy src/

# テスト実行
uv run pytest
```

結果は指定されたSlackチャンネルに通知されます。

## 除外ルールの設定

exclusions.yamlファイルを編集して、特定のセキュリティグループやルールを除外できます

```yaml
exclusions:
  - group_id: sg-12345678
    rules:
      - ip_protocol: tcp
        port_range:
          from: 443
          to: 443
        ip_ranges:
          - 0.0.0.0/0
```
