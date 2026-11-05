# Generalising the engine for a second course (Phase 1)

Do this once, in its own PR, before adding the second certification. Security+ must behave identically afterwards (bundle and tests).

| Area | Today (Security+-specific) | Change |
|---|---|---|
| Course definition | spread over the files below | `data/courses/<code>/course.json`: name, vendor, exam code/version, domains (id, name, weight), objectives (code, name, domain), pass mark + scale, exam target dates + source URL + access date, not-affiliated text |
| Objectives | `utils/exam_bank.py` `OBJECTIVES`, `VALID_OBJECTIVES` | read from the active course |
| Domains / weights / pass mark | `utils/exam.py` `DOMAIN_WEIGHTS`, `DOMAIN_NAMES`, `PASS_SCALED`, `DOMAIN_TEST_TARGET` | course registry |
| Objective names | `tools/export_anki.py` `OBJECTIVE_NAMES`; `OBJ` map in `web/index.html` | course registry (web reads it from the catalog) |
| Exam countdown | `webapi.EXAM_TARGET` | course registry |
| Glossary domains | `utils/glossary.py` `DOMAIN_NAMES`, `data/glossary/` | per-course folder |
| Question bank / topics | `data/exam_bank/`, `data/exam_bank/topics/` | `data/courses/<code>/exam_bank/` |
| Videos | `data/video_course.json`, `utils/videos.py` | per course |
| Career / briefings | `data/career_tracks.json`, `data/briefings/` | per course (labs can be shared across courses via objective tags) |
| Labs | `labs/` registry, objectives strings mention SY0-701 | keep labs shared; tag each with objectives per course |
| Progress | one `progress.json` / one browser key | namespace by course (`objectives`, `srs`, `quizzes` keyed by course) and migrate old files |
| Web app | single course | course switcher in the rail; catalog carries `courses`; bundle per course or a combined bundle |
| CLI | single course | `--course <code>` (default: last used) |
| Exports | Anki deck name, CTFd categories say Security+ | course name from the registry |
| Tests | assume Security+ | parametrise over courses; keep Security+ golden tests |
