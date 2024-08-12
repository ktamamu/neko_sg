# NeKo_AWS_SG (<u>Ne</u>twork <u>K</u>it <u>o</u>f AWS Security Group)
<div align="center">
<img src="icon.png" alt="neko" width="200">
</div>

NeKo_AWS_SGは、AWSのセキュリティグループを監視し、グローバルに対して公開されているインバウンドルールを持つセキュリティグループを検出するツールです。検出結果はSlackに通知されます。

## 機能

- AWSアカウント内のすべてのセキュリティグループをスキャン（全てのセキュリティグループを取得するため、大量のAPI処理が発生する可能性があります。）
- グローバルに対して公開されているインバウンドルールを持つセキュリティグループを検出
- 検出結果をレポートとして出力
- 検出結果をSlackに通知

## 前提条件

- Python 3.7以上
- AWSアクセスキーとシークレットキー
- Slack Webhook URL

## セットアップ

1. リポジトリをクローン：
   ```
   git clone https://github.com/ktamamu/NeKo_AWS_SG.git
   cd NeKo_AWS_SG
   ```

2. 依存関係をインストール：
   ```
   pip install -r requirements.txt
   ```

3. 環境変数とAWS認証情報の設定：
   a. Slack Webhook URLの設定：
      `.env`ファイルをプロジェクトのルートディレクトリに作成し、以下の内容を記入してください：

      ```
      SLACK_WEBHOOK_URL=your_slack_webhook_url
      ```

      または、環境変数を直接設定することもできます：

      ```
      export SLACK_WEBHOOK_URL=your_slack_webhook_url
      ```

   b. AWS認証情報の設定：
      AWSのクレデンシャル情報は`aws configure`コマンドを使用して設定してください：

      ```
      aws configure
      ```

      プロンプトに従って、AWS Access Key ID、AWS Secret Access Key、デフォルトリージョン名、出力形式を入力してください。

## 使用方法

ルートディレクトリから以下のコマンドを実行：

```
python src/main.py
```

実行結果は指定されたSlackチャンネルに通知されます。

## 除外ルールの設定

`exclusions.yaml`ファイルを編集して、特定のセキュリティグループやルールを除外できます：

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

## ライセンス

[MITライセンス](LICENSE)