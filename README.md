# KKinto Temp Media

Temporary public media (image/video/HLS) with 1-day expiry. Admin-only upload, public viewing via signed links.

## Requirements

- Cloudflare Workers
- Cloudflare R2 bucket
- Cloudflare KV namespace
- Cloudflare Durable Objects (usage tracking)

## Quick setup

1) Create an R2 bucket (example name: `kkinto-media`).
2) Create a KV namespace and put its IDs into `wrangler.toml`.
3) Set secrets:

```
wrangler secret put ADMIN_PASSWORD
wrangler secret put TOKEN_SIGNING_SECRET
```

4) Optional local dev:

```
cp .env.example .env
```

## Deploy

```
npm install
npm run deploy
```

## Full deployment flow (Cloudflare + GitHub Actions)

1) Cloudflare setup
   - Add your domain to Cloudflare and point DNS to Cloudflare.
   - Create an R2 bucket (example name: `kkinto-media`).
   - Create a KV namespace and put its IDs into `wrangler.toml`.
   - In `wrangler.toml`, ensure the Durable Object migration is present (already included).

2) Local one-time setup
   - Login: `wrangler login`
   - Set secrets:

```
wrangler secret put ADMIN_PASSWORD
wrangler secret put TOKEN_SIGNING_SECRET
```

3) Configure Worker route
   - In Cloudflare dashboard, add a route like `media.kkinto.com/*` to this Worker.

4) GitHub repo + Actions
   - Create a GitHub repository.
   - Initialize and push:

```
git init
git add .
git commit -m "init temp media worker"
git branch -M main
git remote add origin <YOUR_GITHUB_REPO_URL>
git push -u origin main
```

   - In GitHub repo settings -> Secrets and variables -> Actions, add:
     - `CF_API_TOKEN` (Cloudflare API token with Workers/R2/KV permissions)
     - `CF_ACCOUNT_ID`
   - GitHub Actions workflow is at `.github/workflows/deploy.yml`.
   - On every push to `main`, GitHub will deploy the Worker.

Note: `ADMIN_PASSWORD` and `TOKEN_SIGNING_SECRET` are stored as Worker secrets and do not need to be in GitHub.

## Defaults

- Per-file max size: 1 GiB
- Total max size: 5 GiB
- Media TTL: 1 day

You can change limits via `wrangler.toml` vars.

## Usage

- Visit `/admin` to log in and upload.
- The admin page shows direct media links and a viewer page link.
- Anyone with the link can access until it expires.

## HLS notes

- Generate HLS playlists and segments locally, then upload all files with the same Group ID.
- Share the link for the `.m3u8` file.
 - The view page uses hls.js to improve playback on non-Safari browsers.

Example HLS command (local):

```
ffmpeg -i input.mp4 -hls_time 6 -hls_list_size 0 \
  -hls_segment_filename "output/segment_%03d.ts" output/playlist.m3u8
```
