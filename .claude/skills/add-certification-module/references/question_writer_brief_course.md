# Question writer brief for a new course (Phase 3)

Used for the Okta Certified Professional course (2026-11-05). For another course, replace the Okta exam outline, accuracy rules and folder `data/courses/okta/` with the new course's, and give each writer YOUR SCOPE, files and an ID range.

You are writing original exam-style practice questions for Delzar Certification Academy, a free offline study app.
This course is aligned to the **Okta Certified Professional** exam (Performance Exam, Okta Identity Engine).
Repo: /home/user/delzar-sovereign-wealth-machine/secplus_lab_engine (Python, standard library).
The course is registered in `data/courses/okta/course.json` (read it: domains, weights, objective names).

The real exam is six hands-on use cases (Okta study guide, checked 2026-11-05):
1. Account Creation and User Management (26%): create a user, add a custom attribute, edit a user profile, create a group,
   manually assign users to a group, create a group rule, assign a standard administrator role to a group, create a custom
   role and resource set and assign them to a group.
2. Application Setup with OIN (10%): integrate an OIN app using SAML SSO, set up provisioning from Okta to an app, assign a
   group to an app, verify a user was provisioned.
3. Attribute Mapping and Offboarding (8%): map attributes between Okta and an app, deactivate a user and verify they
   cannot access an app.
4. Security Enforcement (38%): set up an authenticator and enrollment policy, add a rule to the global session policy, add
   an authentication policy, set up password policies for self-service recovery, verify a user must use the required
   authenticators (network zones are part of the related training).
5. Troubleshooting (12%): why a user cannot sign in, expire a password and clear sessions, why a user cannot access an app
   from their dashboard, incorrect group assignment.
6. Syslog and Okta Support (6%): find an event in the System Log; identify Okta resources for help and support.
Earlier Okta Professional guides also covered SSO federation choices (SAML vs OIDC vs WS-Fed vs SWA, IdP- vs SP-initiated,
federation vs password vaulting), Active Directory integration options, group types (Okta, AD/LDAP-sourced, app groups),
end-user self-service, MFA reset options, when to use each policy, Okta reports vs System Log, and the support process.
Include those as concepts where they fit your objectives.

Because the real exam is hands-on, most questions should read like admin console work: "An admin needs to ... Which
setting / which policy / what should the admin do FIRST / what is the MOST likely cause?". Accuracy rules:
- Use **Okta Identity Engine (OIE)** behaviour and names (authenticators, authenticator enrollment policy, global session
  policy, authentication policies / app sign-in policies, Okta Verify, Okta FastPass, password policy with recovery
  authenticators, network zones incl. dynamic zones, Profile Editor, profile sourcing, mappings, user statuses such as
  Staged, Pending user action, Active, Password reset, Password expired, Locked out, Suspended, Deactivated; standard admin
  roles such as Super Administrator, Organization Administrator, Group Administrator, Group Membership Administrator,
  Application Administrator, Help Desk Administrator, Read-only Administrator, Report Administrator; custom admin roles
  with permissions + resource sets; group rules; OIN; provisioning features Create Users, Update User Attributes,
  Deactivate Users, Sync Password; System Log with filter expressions like eventType eq "user.session.start";
  status.okta.com, Okta Help Center, Okta Community, support cases).
- Where Classic Engine differs (factor enrollment, sign-on policies), use OIE and do not test Classic-only behaviour.
- When you are not certain of a product detail, check the Okta Help Center (help.okta.com) with the Firecrawl tools
  (firecrawl_search / firecrawl_scrape) sparingly, or write the question around a concept you are sure of. A wrong answer
  harms the learner; never guess.

## What to produce (only the files named in YOUR SCOPE; never edit any other file; no git)
1. Question files `data/courses/okta/exam_bank/<file>` with this shape:
   {"domain": "<D>", "title": "Okta Domain <D> questions (<objectives>)", "note": "Original questions written for Delzar
   Certification Academy. Not from exam dumps or commercial banks; not affiliated with Okta.", "questions": [ ... ]}
   Single-answer question:
   {"id": "D<D>-NNN", "objective": "X.Y", "topic": "<exact topic name>", "stem": "...?", "choices": [4 strings],
    "answer": "<one of the choices, exact>", "explanation": "Why right, and why the most tempting wrong option is wrong."}
   Also 2-3 performance-style items per objective, in the same file, in the existing formats:
   - multi: {"id","type":"multi","objective","topic","stem":"... Which TWO ...?","choices":[5 strings],"answers":[2],"select":2,"explanation"}
   - order: {"id","type":"order","objective","topic","stem":"Put the steps in order ...","items":[4-6 steps in the correct order],"explanation"}
   - match: {"id","type":"match","objective","topic","stem":"Match each ...","pairs":[{"item","match"} x4-5],"targets_extra":[1 decoy],"explanation"}
   (Look at data/courses/sc300/exam_bank/domain2-a.json for real examples of each type.)
2. A topics file `data/courses/okta/exam_bank/topics/<file>`:
   {"topics": {"X.Y": ["Topic A", ...], ...}, "tags": {}}   (only your objectives; tags stays empty: there are no
   older questions to tag; every new question carries its topic inline).

## Topics and counts
- Each objective: 4 to 6 topics (short Title Case names, no objective numbers) that together cover every task and
  concept above for that objective.
- Each objective: at least 32 single-answer questions; every topic at least 5 single-answer questions.
- IDs must stay inside YOUR ID RANGE so parallel writers never collide.

## Style
- Short realistic workplace scenario in plain language, a question ending with "?", qualifiers where natural (BEST, MOST
  likely, FIRST, Which of the following).
- Exactly 4 distinct options of the same kind, each plausible. No "all/none of the above", no bare numbers (write
  "3 days"), never the word "lab", no made-up codes.
- One defensible correct answer. Spread answer positions evenly (about 25 % each of A-D). The correct answer is the
  uniquely longest option in no more than 25 % of questions.
- About 30 % recall, 70 % applied scenario. No near-duplicates. Explanation 1-3 sentences.
- 100 % original wording; do not copy Okta documentation sentences, practice exams or dumps.

## Check your work (required)
    cd /home/user/delzar-sovereign-wealth-machine/secplus_lab_engine
    DELZAR_COURSE=okta python -m utils.exam_bank data/courses/okta/exam_bank/<file>      # must print OK
Then write and run a throwaway script in /tmp/claude-0/-home-user-delzar-sovereign-wealth-machine/92890991-b586-5706-a4ba-e935723c052f/scratchpad (not the repo) that checks: every topic value is in
the objective's topic list, per-objective single-answer totals >= 32, per-topic totals >= 5, answer-position spread,
longest-answer share, no duplicate stems. Re-read every question once as a strict Okta reviewer and fix any debatable one.

## Report back (short)
Per objective: topics with counts, totals, PBQ count, answer spread, longest-answer share, validator line, and any
product detail you were unsure about.
