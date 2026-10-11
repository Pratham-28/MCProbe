"""Preset targets shown in the UI dropdown."""
TARGETS = [
    {"id": "fixture-clean", "label": "Safe server (demo)", "chip": "Safe server", "url": "http://127.0.0.1:8101/mcp",
     "description": "A well-behaved demo server: two read-only tools, honest annotations. Expect an A."},
    {"id": "fixture-evil", "label": "Evil server (demo)", "chip": "Evil server", "url": "http://127.0.0.1:8102/mcp",
     "description": "A deliberately malicious demo server: hidden instructions, leaked key, rug pull. Expect an F."},
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
    {"id": "github", "label": "GitHub", "url": "https://api.githubcopilot.com/mcp/", "needs_token": True,
     "description": "GitHub's official MCP server. Needs a GitHub personal access token (read-only is enough)."},
]
