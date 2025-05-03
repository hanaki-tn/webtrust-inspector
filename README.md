# WebTrust Frontend & API

このリポジトリには、WebTrustアプリケーションのフロントエンドとバックエンドの両方が含まれています。

## プロジェクト構成

- **ルートディレクトリ**: Vite + React + TypeScript フロントエンド
- **webtrust-api/**: FastAPI バックエンド

## フロントエンド (Vite + React)

### 技術スタック

- Vite
- React
- TypeScript
- Tailwind CSS
- shadcn/ui コンポーネント
- Lucide アイコン
- Recharts

### 開発方法

```bash
# 依存関係のインストール
npm install

# 開発サーバーの起動
npm run dev

# ビルド
npm run build
```

## バックエンド (FastAPI)

### 技術スタック

- FastAPI
- Poetry (パッケージ管理)

### 開発方法

```bash
# webtrust-api ディレクトリに移動
cd webtrust-api

# 依存関係のインストール
poetry install

# 開発サーバーの起動
poetry run fastapi dev app/main.py

# 新しいパッケージのインストール
poetry add <package-name>
```

## 両方のプロジェクトを同時に実行する方法

1. 別々のターミナルでフロントエンドとバックエンドを起動します。
2. フロントエンドは `http://localhost:5173` でアクセスできます。
3. バックエンドは `http://localhost:8000` でアクセスできます。
4. API ドキュメントは `http://localhost:8000/docs` で確認できます。
