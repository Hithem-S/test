# CRM Live — Supabase demo

This repository contains files to deploy a simple Supabase-connected static site (GitHub Pages)
and SQL policies for RLS. Follow steps in the workflow to publish the site.

Files:
- index.html.template
- policies.sql
- .github/workflows/deploy-pages.yml
- .env.example
- apply_sql.sh

After adding files, set Secrets in Settings → Secrets and variables → Actions:
- SUPABASE_URL
- SUPABASE_ANON_KEY
