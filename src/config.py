"""
設定管理モジュール
"""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """アプリケーション設定を管理するデータクラス

    Attributes:
        slack_webhook_url: Slack Webhook URL（Noneの場合は通知しない）
        slack_bot_token: Slack Bot Token（Slack SDK使用時）
        slack_channel: Slack チャンネル名（Slack SDK使用時）
        use_slack_sdk: Slack SDK使用フラグ（Trueの場合はSlack SDKを使用）
        exclusion_rules_file: 除外ルールファイルのパス
        log_level: ログレベル（DEBUG, INFO, WARNING, ERROR, CRITICAL）
        aws_timeout: AWS API呼び出しのタイムアウト（秒）
    """

    slack_webhook_url: str | None = None
    slack_bot_token: str | None = None
    slack_channel: str = "#alerts"
    use_slack_sdk: bool = False
    exclusion_rules_file: str = "../config/exclusion_rules.yaml"
    log_level: str = "INFO"
    aws_timeout: int = 10

    @classmethod
    def from_env(cls) -> "Config":
        """環境変数から設定を読み込む

        Returns:
            Config: 環境変数から読み込んだ設定オブジェクト
        """
        return cls(
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
            slack_bot_token=os.getenv("SLACK_BOT_TOKEN"),
            slack_channel=os.getenv("SLACK_CHANNEL", "#alerts"),
            use_slack_sdk=os.getenv("USE_SLACK_SDK", "false").lower() == "true",
            exclusion_rules_file=os.getenv(
                "EXCLUSION_RULES_FILE", "../config/exclusion_rules.yaml"
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            aws_timeout=int(os.getenv("AWS_TIMEOUT", "10")),
        )

    def get_exclusion_rules_path(self, script_dir: str) -> str:
        """除外ルールファイルの絶対パスを取得

        Args:
            script_dir: スクリプトのディレクトリパス

        Returns:
            str: 除外ルールファイルの絶対パス
        """
        if os.path.isabs(self.exclusion_rules_file):
            return self.exclusion_rules_file
        return os.path.join(script_dir, self.exclusion_rules_file)
