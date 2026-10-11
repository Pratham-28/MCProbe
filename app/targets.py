"""Preset targets shown in the UI dropdown."""
TARGETS = [
    {"id": "fixture-clean", "label": "Fixture: Clean demo server", "url": "http://127.0.0.1:8101/mcp",
     "description": "Local benign server (run scripts/run_fixtures.sh)"},
    {"id": "fixture-evil", "label": "Fixture: Evil demo server", "url": "http://127.0.0.1:8102/mcp",
     "description": "Local server with poisoning, injection, bloat, secrets, rug pull"},
    {"id": "deepwiki", "label": "DeepWiki", "url": "https://mcp.deepwiki.com/mcp",
     "description": "Public docs server, 3 read-only tools"},
    {"id": "context7", "label": "Context7", "url": "https://mcp.context7.com/mcp",
     "description": "Library documentation lookup"},
    {"id": "cloudflare-docs", "label": "Cloudflare Docs", "url": "https://docs.mcp.cloudflare.com/mcp",
     "description": "Cloudflare documentation search"},
    {"id": "ms-learn", "label": "Microsoft Learn", "url": "https://learn.microsoft.com/api/mcp",
     "description": "Microsoft Learn documentation"},
    {"id": "huggingface", "label": "Hugging Face", "url": "https://huggingface.co/mcp",
     "description": "Hugging Face Hub, many tools"},
]
