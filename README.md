# Nemotron-3.5-Parse を Docker で動かす（RTX A2000 / RTX PRO 6000）

[nvidia/Nemotron-3.5-Parse](https://huggingface.co/nvidia/Nemotron-3.5-Parse)（パラメータ数0.63B、文書画像をテキスト・レイアウトクラス・bbox に変換するモデル）を、
1つのDockerイメージで2種類のGPUに載せるための構成。
**eMudhra 中間CA証明書の秘密鍵漏洩への対応を、ビルドと起動の両方に組み込んでいる**（[security/emudhra/](security/emudhra/README.md)）。

## llama.cpp ではなく vLLM を使う理由

2026-10-22 時点の llama.cpp master（`970b51c`）は、このモデルのアーキテクチャに対応していない。

- `convert_hf_to_gguf.py` にも `tools/mtmd` にも該当するコードがない
- GGUF 版も公開されていない

モデルカードが公式に対応を示しているのは **vLLM（NVIDIA のプラグイン付き）** と SGLang。
vLLM 本体へのネイティブ対応（vllm-project/vllm#61651）は 2026-10-21 に main へマージされたが、まだリリースに入っていない。
そこで、モデルカードが基準にしている **vLLM 0.26.0 とプラグイン** を使う。
llama.cpp が対応したら、入れ替えを検討する。

## 構成

```
docker/Dockerfile          vllm/vllm-openai:v0.26.0 を digest 固定。
                           CA対策 → モデルとプラグインを焼き込み → 再監査
docker/entrypoint.sh       起動時の CA 再監査 → 重みの sha256 照合 → vllm serve
compose.yaml               GPU_PROFILE で GPU ごとの設定ファイルを切り替える
profiles/a2000.env         RTX A2000 用（Ampere sm_86、Triton attention）
profiles/rtxpro6000.env    RTX PRO 6000 Blackwell 用（sm_120、モデルカードのスループット設定）
scripts/parse_client.py    OpenAI 互換 API のサンプルクライアント（標準ライブラリだけで動く）
security/emudhra/          eMudhra 対応（監査ツール、イメージ硬化、ホスト点検、テスト）
```

## 前提（各ホスト）

- Linux（x86_64）、Docker、Docker Compose v2、NVIDIA Container Toolkit
- **NVIDIA ドライバ 580 以上**（ベースイメージが CUDA 13.0 のため）
  - 580 にできない場合は、ベースを CUDA 12.9 版に替える（ドライバ 575 以上が必要）。
    `docker/Dockerfile` の `VLLM_IMAGE` を `vllm/vllm-openai:v0.26.0-cu129@sha256:976b4ba10e247dbe5c5ce3e2ba952a359ef641ee25c3d091811c1bec420e5a23` にする
  - RTX PRO 6000（Blackwell）は CUDA 12.8 以上が必須
- 最初に **`sudo security/emudhra/host-check.sh --fix`** を実行する（ホストの CA ストア対策）

## 使い方

```bash
cp .env.example .env
# A2000 機なら GPU_PROFILE=a2000、RTX PRO 6000 機なら GPU_PROFILE=rtxpro6000 にする
# 本番では MODEL_REVISION をコミットハッシュに固定する
vi .env

docker compose build --pull     # ビルド中に eMudhra 監査が走る。NG ならビルドが失敗する
docker compose up -d
docker compose logs -f          # "model revision: ..." の後に vLLM が起動する

curl -s http://127.0.0.1:8000/v1/models
python3 scripts/parse_client.py page.png > page.txt
```

モデルの重み（約1.3GB）はビルド時にイメージへ焼き込む。実行時は `HF_HUB_OFFLINE=1` で外部と通信しない。
LAN に公開する場合は `.env` で `BIND_ADDR=0.0.0.0` と `VLLM_API_KEY` を設定する。

## GPU ごとの設定

| | RTX A2000 | RTX PRO 6000 Blackwell |
|---|---|---|
| アーキテクチャ | Ampere sm_86、6GB または 12GB | Blackwell sm_120、96GB |
| attention | `--attention-backend TRITON_ATTN` | vLLM の既定（FA2 が選ばれる） |
| `MAX_NUM_SEQS` | 8（12GB なら 16、6GB なら 4） | 192（モデルカードの値） |
| `GPU_MEMORY_UTILIZATION` | 0.85（画面出力も兼ねるなら 0.80） | 0.90 |

- モデルカードの例にある `--attention-config '{"flash_attn_version":3}'` は付けていない。FA3 は Hopper（sm_90）専用のため。
  - Blackwell では vLLM が FA2 に自動で切り替える
  - Ampere は NVIDIA が以前の Parse モデルカードで Triton を推奨している
- 値を変えたいときは `profiles/*.env` を編集して `docker compose up -d` し直す。

## 出力

生の出力は、テキスト・クラス（`<class_Table>` など）・正規化された bbox が混ざった文字列。
Markdown などへの変換には、モデルリポジトリに同梱されている後処理を使う
（`postprocessing.py` / `nemotron_parse` パッケージ。イメージ内の `/opt/nemotron-parse` にある）。

```bash
docker compose exec nemotron-parse ls /opt/nemotron-parse
```

## 未検証の点（実機で確認してほしいこと）

この構成を作った環境では GPU が使えず、Hugging Face にも接続できなかった。そのため以下は確認できていない。

- **モデルのダウンロード、プラグインのインストール、GPU での推論**。
  ビルドのうち、CA対策の部分は実際の `vllm/vllm-openai:v0.26.0` で動作を確認した。
  エントリポイントの各ゲートも、vllm をスタブに置き換えて確認した
- モデルカードの README は直接読めず、serve のオプションやプロンプトは検索結果から再構成した。
  プラグインが要求する追加オプションがあれば、`EXTRA_VLLM_ARGS` で足す
- A2000 で Triton attention を使ったときの出力品質と速度、RTX PRO 6000 での attention の自動選択
- MTP（投機的デコード）はプラグインが自動で有効にする。問題が出たら、`NP_VLLM_MTP=0` で無効化できると報じられている（未確認）

## ライセンス

モデルは NVIDIA OpenMDW License Agreement v1.1。このリポジトリのコードは [LICENSE](LICENSE) に従う。
