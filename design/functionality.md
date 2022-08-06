# 実装の基本方針

## ネットワークのイメージ
ネットワークの構造は以下の図のとおり。
役割(ledger/client/miner)をもつノード同士が接続する。
```
ledger1 ____ ledger2 _________
  |          / |____ client1 |
  |_________/  |____ client2 |
  |            |             |
ledger3 ____ client3         |
  |                          |
  |_____ miner1 _____________|
  |_____ miner2
```

ネットワーク上のノード同士は、以下の要領で接続性を確保する
- ledgerは既知のledgerやminerに自分の存在を示すビーコンを送信する
- minerは既知のledgerに自分の存在を示すビーコンを送信する
- ledgerは他のノードからビーコンを受信すると、その送信者を既知ノードとして登録する
- ledgerは登録済の他のledgerに対して、自分が知るledgerやminer情報を送信する。ルートテーブル交換(RIP)と同様
- ledgerはledger/miner情報を受信すると、それを既知ノードとして登録する。ルートテーブル交換(RIP)と同様
- ネットワーク負荷を抑えるために、ledgerがデータを他ledgerに送信するときは、送信先ノード数に上限を設ける。なお、ネットワークが分断されないように送信先をよしなに選択する
- ledgerは接続済のledgerやminerが生存しているか定期的に確認する。長期間返答がない場合はそのノードを既知ノードから削除する
- clientは1つ以上のledgerに接続する

ノード間通信にはhttpを使用する

## モジュール
以下のようにモジュールを分割する。

- jellyfish-chain-core プロトコルのコア部分
- jellyfish-chain-net ネットワーク上のノード探索や通信維持
- jellyfish-chain-api ノード間通信に使うREST API
- jellyfish-accout アカウントの作成や管理を担うコマンド
- jellyfish-ledger 台帳を稼働させるコマンド
- jellyfish-miner ブロック作成のためのハッシュ探索を稼働させるコマンド
- jellyfish-client クライアント機能を実現するコマンド

## 実装言語
Rust

## 動作環境
Linuxを想定

# モジュール(クレート)の内容

## jellyfish-chain-core
jellyfishプロトコルのコア部分を実装するクレート。

### データ構造
- Account ネットワークに公開される、ユーザを識別するアカウント情報
  - public key ed25519 delek形式の公開鍵。署名の検証に使用する
- SecretAccount ユーザ本人だけがもつ秘匿情報
  - secret key ed25519 delek形式の秘密鍵。署名作成に使用する
- Signature 署名。固定長バイト列のラッパ
- Timestamp 時刻。トランザクションやブロックに含めるデータ
- Digest ハッシュ。固定長バイト列のラッパ
- Transaction ブロックに記録される情報の単位
  - account このトランザクションを作成したアカウント
  - timestamp このトランザクションを作成した時刻
  - content
    - method このトランザクションの種類。トランザクションの追加、修正、削除のいずれか
    - record このトランザクションの内容。任意の文字列（追加・修正の場合のみ）
    - target transaction's block height 対象のトランザクションを保持しているブロック（修正・削除の場合のみ）
    - target transaction's signature 対象のトランザクションの署名（修正・削除の場合のみ）
  - sign このトランザクションの作成者による署名 := sign(account, timestamp, content, secret key)
- Block
  - header
    - height ブロックの高さ。最初のブロックを0として、このブロックが何番目に作成されたか
    - timestamp このブロックが作成された時刻
    - previous_digest 1つ前のブロックのハッシュ
    - difficulty ブロック採掘の難易度
    - markle_root このブロックのトランザクションのマークル木の根のハッシュ
    - nonce ナンス
    - digest このブロックのハッシュ
  - transactions トランザクション
- BlockTree ブロックの時系列関係を表す木。根が最古のブロック、葉が最新のブロック
  - root

### 署名の計算手順
トランザクションに付与する署名は以下の手順で計算する。
整数のバイト列表現にはリトルエンディアンを使用する。

1. 空のバイト列を用意する
1. accountの公開鍵情報のバイト表現を列に追加する
1. timestampをナノ秒刻みのunix epochの64bit整数として、そのバイト表現を列に追加する
1. 以下のとおりトランザクションの内容のバイト列表現を列に追加する
   1. methodのバイト表現を列に追加する。  
     methodとバイト表現との対応関係は以下のとおり。
      - トランザクション追加: 0x01
      - トランザクション修正: 0x02
      - トランザクション削除: 0x04
   1. recordが存在すれば、そのバイト列表現を列に追加する
   1. target transaction block heightが存在すれば、それを64bit整数として解釈し、そのバイト表現を列に追加する
   1. target transaction signatureが存在すれば、そのバイト列表現を追加する
1. バイト列に対して、SecretAccountが保持する秘密鍵により署名を作成する

### ハッシュの計算手順
ブロックのハッシュは以下の手順で計算する。
整数のバイト列表現にはリトルエンディアンを使用する。

1. 空のバイト列を用意する
1. heightを64bit整数として解釈し、そのバイト表現を列に追加する
1. timestampをナノ秒刻みのunix epochの64bit整数として、そのバイト表現を列に追加する
1. previous digestのバイト列を列に追加する
1. difficultyを64bit整数として解釈し、そのバイト表現を列に追加する
1. markle rootのハッシュを列に追加する
1. nonceを64bit整数として解釈し、そのバイト表現を列に追加する
1. バイト列に対してハッシュを計算する

### マークル木について
ブロック内のトランザクションのマークル木は以下の手順で作成する。
ハッシュ計算にはSHA256を使用する。

1. トランザクションを並び替える。
1. トランザクションのハッシュを計算する
1. 計算したハッシュを葉として、2分木となるように木を構築する。各ノードには、子のハッシュから計算したハッシュを格納する
1. 根のハッシュがmarkle rootとなる

### データ関係
コア部分のデータ間関係は以下

```
     Transaction ----- Account
         |
         |
         |
       Block ------ BlockTree
```

## jellyfish-chain-net
