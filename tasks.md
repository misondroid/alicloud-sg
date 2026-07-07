# alicloud-sg
## 当リポジトリの目的
- AlibabaCloudのSGリージョンのIPアドレスをAWS WAFで取り扱うためのIPセットを作成するツールを作成します。
  - 手動実行用とLambda用のエントリーポイント関数を持ちます。
### データソース
- APNICの国月IPアドレスレンジ情報
  - https://ftp.apnic.net/stats/apnic/delegated-apnic-latest
- BGP情報
  - AS134963(Alibaba Cloud Singapore) 
- Source CIDRのIPレンジ情報フィード
  - https://sourcecidr.com/feeds/alibaba-cloud.json
  - AWS等クラウドでで実行する際に、CloudFlareによる防護を乗り越えられないため、使用できない。

