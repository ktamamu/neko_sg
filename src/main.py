"""
AWSセキュリティグループのグローバルアクセス可能なインバウンドルールを検索し、Slackに通知するスクリプト
"""

import os
from dotenv import load_dotenv
from utils import (
    load_exclusion_rules,
    find_globally_accessible_security_groups,
    format_slack_message,
    send_slack_notification
)

def main():
    """
    メイン処理
    """

    # .envファイルを読み込む
    load_dotenv()

    # スクリプトのディレクトリを取得
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # exclusion_rules.yamlへの相対パスを作成
    exclusion_rules_file = os.path.join(script_dir, '../config', 'exclusion_rules.yaml')

    exclusion_rules = load_exclusion_rules(exclusion_rules_file)

    print("グローバルにアクセス可能なセキュリティグループを検索中...")
    found_groups = list(find_globally_accessible_security_groups(exclusion_rules))

    if not found_groups:
        print("グローバルにアクセス可能なセキュリティグループは見つかりませんでした。")
    else:
        print("検索完了。以下のセキュリティグループにグローバルなインバウンドルールが見つかりました：")
        for sg in found_groups:
            print(f"リージョン: {sg['region']}, セキュリティグループID: {sg['group_id']}")
        # Slack通知の処理
        slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        if slack_webhook_url:
            message = format_slack_message(found_groups)
            send_slack_notification(slack_webhook_url, message)
        else:
            print("SLACK_WEBHOOK_URL環境変数が設定されていないため、Slack通知は送信されません。")

if __name__ == "__main__":
    main()
