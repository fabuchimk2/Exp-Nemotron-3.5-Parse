# eMudhra 中間CA証明書 秘密鍵漏洩への対応

## 何が起きたか（2026-10-17 報告）

- eMudhra（インドの認証局）の**中間CA証明書8枚**で、秘密鍵が公開証明書から復元できる状態だった。
  6枚がTLS用、2枚がコード署名用。
- 原因は鍵生成時の乱数不足。P-384の秘密鍵が **256未満の整数**（例：`4`）だった。
  候補を最大256個試すだけで秘密鍵が求まる。
- 影響：**任意のドメインのHTTPS証明書やコード署名証明書を偽造できる**。
  これを信頼してしまうクライアントは中間者攻撃（MITM）を受けうる。
- 発行元のルートは `emSign ECC Root CA - G3`。同じ鍵の Sectigo によるクロス署名版もあり、
  そちらは `AAA Certificate Services`（Comodo/Sectigo）に連鎖する。
- 各所の対応：
  - Chrome：CRLSet で SPKI をブロック。Chrome Root Store から emSign ECC Root CA - G3 を削除予定（2026-10-27）。
  - Firefox：OneCRL でブロック。NSS からルートを削除。
  - Ubuntu：ca-certificates `20260816ubuntu0.{22,24}.04.1`（LP: #2171507）で emSign ECC Root CA - G3 を無効化。
    このリポジトリでパッケージの changelog を見て確認済み。
  - Debian：DSA-6572-1（trixie）、DLA-4845-1（bookworm）。
  - Python certifi：2026.10.19 で削除。
- **ブラウザ以外が問題**。独自のCAバンドルを持ち、失効確認をしないソフト（Python、pip、botocore、
  Java、Go製バイナリ、コンテナイメージ）は、更新しない限り侵害チェーンを信頼し続ける。

## このリポジトリで取った対策

| # | 対策 | 実装 |
|---|------|------|
| 1 | OSの ca-certificates を修正版へ更新 | `harden-trust-store.sh` 1/4 |
| 2 | `emSign ECC Root CA - G3` と `AAA Certificate Services` を明示的に無効化（`/etc/ca-certificates.conf` に `!` 行を追加）。パッケージが古いままでも、後でダウングレードされても効く | `harden-trust-store.sh` 2/4 |
| 3 | certifi を 2026.10.19 以上に更新。さらに**コンテナ内の全CAバンドル**から該当証明書を除去 | `audit_trust.py scan --fix` |
| 4 | **ビルドゲート**：監査で何か見つかれば `docker build` を失敗させる | Dockerfile（2か所） |
| 5 | **起動ゲート**：起動時にも再監査し、失敗したら vLLM を起動しない | `docker/entrypoint.sh` |
| 6 | すべてのTLSクライアントが修正済みのシステムバンドルを使うよう設定（`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` / `PIP_CERT`） | Dockerfile `ENV` |
| 7 | 偽造証明書によるMITMで重みがすり替わる被害を抑える：重みはビルド時に焼き込み、sha256 を記録して起動時に照合。実行時は `HF_HUB_OFFLINE=1` で外部と通信しない | Dockerfile / entrypoint |
| 8 | Dockerホスト自体（A2000機とRTX PRO 6000機）の点検と修正 | `host-check.sh` |
| 9 | 鍵の弱さそのものを検出：EC公開鍵が `k·G`（k ≤ 4096）と一致するか総当たりで調べる。指紋リストに頼らないため、まだ知られていない同種の弱い鍵も検出できる | `audit_trust.py` |

### 実際のベースイメージでの検出結果

`vllm/vllm-openai:v0.26.0` をそのまま調べると、4つのバンドルが該当した：

```
[NG] /etc/ssl/certs/ca-certificates.crt                       emSign ECC Root CA - G3, AAA Certificate Services
[NG] /usr/local/lib/python3.12/dist-packages/certifi/cacert.pem      emSign ECC Root CA - G3
[NG] /usr/local/lib/python3.12/dist-packages/pip/_vendor/certifi/... emSign ECC Root CA - G3
[NG] /usr/local/lib/python3.12/dist-packages/botocore/cacert.pem     AAA Certificate Services
```

`harden-trust-store.sh` を実行すると、4つとも `[OK]` になる。
pip や botocore が同梱しているバンドルは、OSの更新でも certifi の更新でも直らない。だから3番の全バンドル除去が要る。

## 使い方

```bash
# コンテナ内（ビルドで自動実行される。手動でも実行できる）
docker compose run --rm nemotron-parse python3 /opt/security/emudhra/audit_trust.py scan

# 通信先が実際に提示するチェーンを点検
docker compose run --rm nemotron-parse python3 /opt/security/emudhra/audit_trust.py \
    hosts huggingface.co cdn-lfs.huggingface.co pypi.org

# Dockerホスト（両方のマシンで実行）
sudo security/emudhra/host-check.sh          # 点検だけ
sudo security/emudhra/host-check.sh --fix    # 修正（apt で更新し、無効化してから再監査）

# テスト
python3 -m unittest discover -s security/emudhra/tests -v
```

`--fix` は変更前のファイルを `*.pre-emudhra-fix` として残す。

## 運用チェックリスト

- [ ] 両ホストで `host-check.sh --fix` を実行し、結果が `OK` になった
- [ ] イメージを再ビルドした（`docker compose build --pull`）。古いイメージは消した
- [ ] 社内プロキシやTLSインスペクション機器のCAストアも更新した（ここが古いままだと、コンテナを直しても防げない）
- [ ] Java（`cacerts`）、Node、Go などで別のCAストアを持つツールが社内にあれば、それぞれ更新した
- [ ] eMudhra / emSign 発行の証明書を自社サーバで使っていないか確認した（使っていれば、Chrome がルートを削除した時点で失効扱いになる）
- [ ] コード署名用の中間CA 2枚（EM OV CS CA - G3B / G3C）で署名されたバイナリを信頼していないか確認した
- [ ] `MODEL_REVISION` をコミットハッシュに固定した

## 制約と注意

- 侵害された**中間CA証明書そのもの**はバンドルに入っていない（サーバがTLSハンドシェイクで送ってくる）。
  ルートを無効化すればチェーンを組めなくなるので、ルートの無効化が本筋の対策になる。
  `hosts` サブコマンドは、実際のチェーンに弱い鍵が含まれていないかを調べる補助的な確認。
- 指紋は、ルートについては Ubuntu の ca-certificates パッケージから取り出して確認した値を使っている（`blocked-roots/`）。
  中間CA 8枚の指紋は報道によって値が食い違うため、ハードコードしていない。その代わりに鍵の弱さを直接検出している。
- 一次情報：Mozilla Bugzilla #2083449、Google / Mozilla のセキュリティブログ、Ubuntu の ca-certificates changelog。
