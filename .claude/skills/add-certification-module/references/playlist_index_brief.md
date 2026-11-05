# YouTube playlist indexer brief (Phase 6)

Fill in {PLAYLIST_ID}, {TITLE}, {AUTHOR}, {CHANNEL_URL}, {OUT} (e.g. `data/glossary/videos.json`) and today's date.

---

Build an index of a public YouTube playlist so a study app can link each glossary acronym to its short video. Do NOT commit; write only {OUT}.

How to fetch: use the Firecrawl MCP tool `firecrawl_scrape` in Alexandria mode (load it with ToolSearch "select:mcp__Firecrawl__firecrawl_scrape" if needed):
  alexandria = {"provider": "youtube-com", "capability": "videos/playlist_videos", "options": {"playlist": "{PLAYLIST_ID}"}}
Each page returns up to 100 videos plus a "continuation" token; fetch the next page with options {"continuation": "<token>"} until there is none. Pages are large: extract only n, video_id, title and length_text into notes as you go.

Write {OUT}:
{"source": {"title": "{TITLE}", "author": "{AUTHOR}", "playlist_id": "{PLAYLIST_ID}", "url": "https://www.youtube.com/playlist?list={PLAYLIST_ID}", "channel": "{CHANNEL_URL}", "note": "Index of titles, video IDs and lengths only (no video content). Videos play on YouTube.", "retrieved": "<date>"},
 "videos": [{"n": 1, "id": "...", "title": "...", "acronym": "3DES" or null, "expansion": "Triple Data Encryption Standard" or null, "seconds": 34}, ...]}
n = position in the playlist (1-based). Split "ACRONYM - Expansion" on the FIRST " - " and strip spaces; keep the acronym exactly as titled. JSON indent 2, ensure_ascii False, trailing newline.
Report: total captured vs the playlist's count, duplicates, acronyms with several videos (e.g. PAM, SoC/SOC), and titles that did not split cleanly.
