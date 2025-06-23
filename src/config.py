"""
設定管理モジュール
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """アプリケーション設定を管理するデータクラス

    Attributes:
        slack_webhook_url: Slack Webhook URL（Noneの場合は通知しない）
        exclusion_rules_file: 除外ルールファイルのパス
        log_level: ログレベル（DEBUG, INFO, WARNING, ERROR, CRITICAL）
        aws_timeout: AWS API呼び出しのタイムアウト（秒）
    """

    slack_webhook_url: Optional[str] = None
    exclusion_rules_file: str = '../config/exclusion_rules.yaml'
    log_level: str = 'INFO'
    aws_timeout: int = 10

    @classmethod
    def from_env(cls) -> 'Config':
        """環境変数から設定を読み込む

        Returns:
            Config: 環境変数から読み込んだ設定オブジェクト
        """
        return cls(
            slack_webhook_url=os.getenv('SLACK_WEBHOOK_URL'),
            exclusion_rules_file=os.getenv(
                'EXCLUSION_RULES_FILE', '../config/exclusion_rules.yaml'
            ),
            log_level=os.getenv('LOG_LEVEL', 'INFO'),
            aws_timeout=int(os.getenv('AWS_TIMEOUT', '10'))
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
