# ⚡ QuizArena

A gamified daily-quiz web app for classrooms and small groups. Students log in, take a timed one-question-at-a-time quiz, earn points with speed bonuses, and climb weekly/monthly/all-time leaderboards. Admins create quizzes, schedule time windows, watch live analytics, and share results — all from a secured panel.

Built as a **single `index.html` file** on the front end (React, bundled and inlined) with **Supabase** (Postgres + Auth) as the backend. No build step, no server to run, no environment variables. Paste two keys, drop the file on any static host, done.

---

## ✨ Features

**For students**
- Username-only login (no email needed) with persistent sessions and full attempt history
- One question at a time, whole-quiz countdown timer, live speed-bonus meter
- Scoring: **10 points** per correct answer **+ speed bonus** (+3 ≤10s, +2 ≤20s, +1 ≤30s), no negative marking
- Ranked by score, ties broken by lowest total time
- Weekly / monthly / all-time leaderboards with a podium
- Animated result card with confetti, a downloadable score image, and one-tap social sharing
- Change your own password anytime
- Mobile-first, works on any modern browser

**For admins**
- First account to register automatically becomes the admin
- Create/edit/delete quizzes and **edit any detail at any time** — including after a quiz is live
- Edit or delete **individual questions**
- Set the **start and end window** (admin-assigned availability) and the **per-quiz timer**
- Per-quiz toggles:
  - **Allow students to go back** and change answers (or lock each answer, one-way)
  - **Reveal correct answers** after the quiz
  - **Hide scores until the quiz closes** (or show immediately on submit)
  - Published / draft
- Submission inspector: every player's per-question choice vs. correct answer, **time taken per question, and the timestamp** of each answer
- Rich analytics: submissions, average score, top scorer, average speed bonus, average time, fastest 100%, flagged (anti-cheat) runs, hardest question, accuracy-by-question bars, **score distribution**, and a **per-option answer breakdown** to spot common mistakes
- **Share the leaderboard** (rank, username, score, time) as an image or to WhatsApp / X / Telegram / copy, plus **CSV export** and **answer-key sharing**
- Manage users: ban/unban, reset any student's password
- Reset a quiz's submissions

**Anti-cheat**
- Fullscreen enforced during a quiz; tab-switching, leaving fullscreen, right-click, copy and text-selection are blocked/logged
- Configurable violation limit → automatic submission
- All scoring is computed **on the server**, never in the browser — answers and correct indexes are never exposed to students

---

## 🧱 Tech stack

| Layer | Choice |
|---|---|
| Frontend | React (bundled + minified into one `index.html`), lucide-react icons |
| Backend | Supabase — Postgres, Row Level Security, `SECURITY DEFINER` functions |
| Auth | Supabase Auth (username mapped to a synthetic email) |
| Hosting | Any static host — Vercel, Netlify, Cloudflare Pages, GitHub Pages |

---

## 🚀 Setup (about 10 minutes)

1. **Create a Supabase project** at [supabase.com](https://supabase.com) (free tier is fine).
2. **Run the database script** in the Supabase **SQL Editor**:
   - Fresh project → run **`supabase/schema.sql`** (contains everything).
   - Already deployed an earlier version → run **`supabase/update.sql`** (adds password reset + all v2 features; safe to re-run).
3. **Disable email confirmation** so username-only login works: Supabase → **Authentication → Providers → Email → turn off "Confirm email"**.
4. **Add your keys** to `index.html`. Open it and edit the block near the top:
   ```js
   window.QUIZARENA_CONFIG = {
     url:     "https://YOUR-PROJECT-ref.supabase.co",
     anonKey: "YOUR-ANON-PUBLIC-KEY"
   };
   ```
   Both values are in Supabase → **Project Settings → API** (use the **anon public** key — it's safe to expose; RLS protects your data).
5. **Host it.** Drag `index.html` onto [Netlify Drop](https://app.netlify.com/drop) or import this repo into [Vercel](https://vercel.com). Any static host works.
6. **Register the first account** on your live site — it automatically becomes the **admin**. Everyone who registers after is a student. Create your first quiz from the Admin panel.

---

## 🗂️ What's in the repo

```
index.html                     # the entire front-end app (this is what you host)
supabase/
  schema.sql                   # full database setup for a FRESH project
  update.sql                   # one-file update for an ALREADY-DEPLOYED project
  add-password-reset.sql       # (component) admin password-reset function
  add-v2-features.sql          # (component) back-nav, score-reveal, per-question timing
README.md
```

You only ever run **one** SQL file: `schema.sql` for a new project, or `update.sql` for an existing one.

---

## 🔐 Security model

- **Students can't reach the admin panel.** The admin UI is hidden for non-admins, *and* every admin action is independently checked on the server with an `is_admin()` guard. Even a crafted request from a student is rejected by the database.
- **Correct answers never leave the server.** Students receive questions without the answer key; scoring happens inside a Postgres function. Row Level Security blocks direct reads of the answers table.
- **Submissions are one per student per quiz**, inserted only through the scoring function, which also validates the quiz window and ban status.
- **Password resets** run through a server-side function (bcrypt via `pgcrypto`); no privileged key ever touches the browser.

---

## ⏱️ Scoring rules

```
per correct answer: +10
speed bonus (per correct answer, based on time to first answer):
  <= 10s  -> +3
  <= 20s  -> +2
  <= 30s  -> +1
wrong / unanswered: 0 (no negative marking)
ranking: highest total, ties broken by lowest total time
```

The speed bonus uses **time to your first answer** on each question, so allowing back-navigation doesn't let anyone game the clock — revisiting a question never resets its timer, and only your final answer decides correctness.

---

## 📦 Data retention & capacity (Supabase free tier)

- **How long is history kept?** Indefinitely. Data stays until you delete it or hit the storage cap. Each submission is tiny (~1–2 KB), so 150 students taking a daily quiz produce only tens of MB per year — comfortably within the **500 MB** free database for years.
- **How many users at once?** 150 concurrent players is a very light load for this read/write pattern (no realtime, no heavy queries). The free tier handles it easily; bursts of a few hundred are fine too.
- **The one catch:** free projects **pause after ~7 days with no activity** and take ~30–60s to wake on the next request. Daily use keeps it awake during term; over long holidays either ping it (e.g. a free UptimeRobot monitor) or upgrade to **Pro ($25/mo)**, which removes pausing and adds backups.
- Free tier also covers **50,000 monthly active users** and unlimited API requests. Confirm current numbers at [supabase.com/pricing](https://supabase.com/pricing).

---

## 📄 License

MIT — use it, fork it, run it for your class.
