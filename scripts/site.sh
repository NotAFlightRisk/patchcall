#!/bin/sh
# Builds the patchcall.peng.ly demo into ./site, pulse script only when PUBLIC_PLAUSIBLE_SCRIPT is set
set -eu

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp .github/site/extras.html "$work/extras.html"
scripts="'none'"
connect="'none'"
if [ -n "${PUBLIC_PLAUSIBLE_SCRIPT:-}" ]; then
  pulse=$(printf '%s' "$PUBLIC_PLAUSIBLE_SCRIPT" | cut -d/ -f1-3)
  printf '{{define "pulse"}}<script id="pulse" defer src="%s"></script><script defer src="pulse.js"></script>{{end}}\n' \
    "$PUBLIC_PLAUSIBLE_SCRIPT" >> "$work/extras.html"
  scripts="'self' $pulse"
  connect="$pulse"
fi

rm -rf site
PATCHCALL_INVENTORY=.github/site/inventory.yaml PATCHCALL_DATA="$work/data" \
  go run . --render site --extra "$work/extras.html"
cp .github/site/site.css .github/site/robots.txt .github/site/BingSiteAuth.xml site/
cp .github/social-preview.png site/social.png
[ -z "${pulse:-}" ] || cp .github/site/pulse.js site/

cat > site/sitemap.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://patchcall.peng.ly/</loc><lastmod>$(date -u +%F)</lastmod></url>
</urlset>
XML

cat > site/_headers <<HEADERS
/*
  Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; script-src $scripts; connect-src $connect; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
HEADERS
echo "Built site/ from $(grep -c 'image:' .github/site/inventory.yaml) demo apps"
