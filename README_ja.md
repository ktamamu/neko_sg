# neko_sg

[![CI](https://github.com/ktamamu/neko_sg/actions/workflows/ci.yml/badge.svg)](https://github.com/ktamamu/neko_sg/actions/workflows/ci.yml)
[![Security](https://github.com/ktamamu/neko_sg/actions/workflows/security.yml/badge.svg)](https://github.com/ktamamu/neko_sg/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

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

### 基本的なスキャン

ルートディレクトリから以下のコマンドを実行してください：

```bash
# uv を使用してスクリプトを実行
uv run python src/main.py

# またはエントリーポイント経由で実行
uv run neko-sg

# scanサブコマンドを明示的に使用
uv run python src/main.py scan
```

### 除外ルールの管理

`exclude`サブコマンドを使用してセキュリティグループを除外リストに追加できます：

```bash
# セキュリティグループを除外ルールに追加（自動検出あり）
uv run python src/main.py exclude sg-1234567890abcdef0

# 自動検出なしで追加
uv run python src/main.py exclude sg-1234567890abcdef0 --no-auto-detect

# エントリーポイント経由で実行
uv run neko-sg exclude sg-1234567890abcdef0
```

`exclude`コマンドの機能：
- 指定されたセキュリティグループを全AWSリージョンから検索
- セキュリティグループの現在のルールを自動検出
- `config/exclusion_rules.yaml`にセキュリティグループを追加
- ファイルが存在しない場合は作成
- 既に除外されている場合はスキップ

### コマンドヘルプ

```bash
# 利用可能なコマンドを表示
uv run python src/main.py --help

# excludeコマンドのヘルプを表示
uv run python src/main.py exclude --help
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

### 自動的な方法（推奨）

`exclude`コマンドを使用してセキュリティグループを除外リストに自動的に追加：

```bash
uv run python src/main.py exclude sg-1234567890abcdef0
```

### 手動での方法

`config/exclusion_rules.yaml`ファイルを手動で編集して、特定のセキュリティグループやルールを除外できます：

```yaml
- security_group_id: sg-1234567890abcdef0
  description: "除外: WebServer-SG (HTTP/HTTPSアクセス)"
  rules:
    - ip_address: "0.0.0.0/0"
      protocol: "tcp"
      port_range:
        from: 443
        to: 443
    - ip_address: "0.0.0.0/0"
      protocol: "tcp"
      port_range:
        from: 80
        to: 80
```

**注意**: 自動的な方法が推奨される理由：
- 構文エラーを防止
- 現在のセキュリティグループルールを自動検出
- 適切なYAMLフォーマットを保証
- ファイル構造が存在しない場合は作成
