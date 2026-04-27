# UtilityHut

UtilityHut is a static smart utility app that combines:

- Password manager with browser-side encryption
- Project manager
- Notes app with search
- Task manager

## Run locally

Because this is a static site, you can open `index.html` directly in a browser.

## Deploy to GitHub Pages

1. Create a GitHub repository.
2. Push these files to the repository root.
3. In GitHub, open **Settings -> Pages**.
4. Set **Source** to **GitHub Actions**.
5. The included workflow at `.github/workflows/deploy-pages.yml` will publish the site when you push to `main`.
6. Wait for the Pages deployment to finish.

Your site will be available at:

`https://<your-github-username>.github.io/<repository-name>/`

## Notes

- App data is stored in `localStorage`.
- Password entries are encrypted in the browser before they are saved.
- Exported backups include app data and the encrypted vault payload.
