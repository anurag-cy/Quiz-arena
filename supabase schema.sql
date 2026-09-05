-- ============================================================================
-- CIVIL SERVICES FORUM — QUIZ ARENA · canonical database schema.
-- Build the entire backend from scratch on a NEW Supabase project:
--   Dashboard -> SQL Editor -> New query -> paste this whole file -> Run.
-- Fully idempotent: safe to re-run on an existing database (it will not drop
-- or delete your data; it only (re)creates tables, policies and functions).
-- After running: Authentication -> turn OFF "Confirm email", then register the
-- first account (it becomes the admin).
-- ============================================================================

-- ============================================================================
-- QUIZARENA — Supabase schema, security (RLS) and server-side scoring.
-- Run this ONCE in the Supabase SQL Editor (Dashboard → SQL → New query → Run).
-- ============================================================================

-- ---------- TABLES ----------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text unique not null,
  role       text not null default 'student' check (role in ('student','admin')),
  banned     boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.quizzes (
  id             uuid primary key default gen_random_uuid(),
  title          text not null,
  quiz_date      date not null default current_date,
  start_at       timestamptz not null,           -- window opens
  end_at         timestamptz not null,           -- window closes (deadline)
  duration_sec   int  not null default 360,       -- per-attempt time limit
  published      boolean not null default false,
  publish_answers boolean not null default false,
  violation_limit int not null default 3,
  created_at     timestamptz not null default now(),
  created_by     uuid references auth.users(id)
);

create table if not exists public.questions (
  id            uuid primary key default gen_random_uuid(),
  quiz_id       uuid not null references public.quizzes(id) on delete cascade,
  position      int  not null,
  text          text not null,
  options       jsonb not null,                   -- ["A","B","C","D"]
  correct_index int  not null                      -- hidden from students by RLS
);

create table if not exists public.submissions (
  id            uuid primary key default gen_random_uuid(),
  quiz_id       uuid not null references public.quizzes(id) on delete cascade,
  user_id       uuid not null references auth.users(id) on delete cascade,
  base          int  not null,
  bonus         int  not null,
  total         int  not null,
  total_ms      bigint not null,
  per_ms        jsonb not null,
  answers       jsonb not null,
  correct       jsonb not null,
  violations    int  not null default 0,
  auto_submitted boolean not null default false,
  submitted_at  timestamptz not null default now(),
  unique (quiz_id, user_id)                         -- ONE attempt per student per quiz
);

create index if not exists idx_sub_quiz on public.submissions(quiz_id);
create index if not exists idx_sub_user on public.submissions(user_id);
create index if not exists idx_q_quiz on public.questions(quiz_id);

-- ---------- HELPER: is the caller an admin? --------------------------------
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false);
$$;

-- ---------- AUTO-CREATE PROFILE ON SIGNUP ----------------------------------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_role text := 'student';
begin
  -- The very first account to register becomes the admin automatically.
  if not exists (select 1 from public.profiles where role = 'admin') then
    v_role := 'admin';
  end if;
  insert into public.profiles (id, username, role)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)),
          v_role)
  on conflict (id) do nothing;
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users for each row execute function public.handle_new_user();

-- ---------- ROW LEVEL SECURITY ---------------------------------------------
alter table public.profiles    enable row level security;
alter table public.quizzes     enable row level security;
alter table public.questions   enable row level security;
alter table public.submissions enable row level security;

-- profiles: anyone signed-in can read (needed for leaderboards); only admins edit.
drop policy if exists p_profiles_read on public.profiles;
create policy p_profiles_read on public.profiles for select to authenticated using (true);
drop policy if exists p_profiles_admin_write on public.profiles;
create policy p_profiles_admin_write on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- quizzes: students see published only; admins do everything.
drop policy if exists p_quiz_read on public.quizzes;
create policy p_quiz_read on public.quizzes for select to authenticated
  using (published = true or public.is_admin());
drop policy if exists p_quiz_admin on public.quizzes;
create policy p_quiz_admin on public.quizzes for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- questions: ONLY admins can read the raw table (it holds correct answers).
-- Students receive questions (without answers) through the start_quiz() function.
drop policy if exists p_q_admin on public.questions;
create policy p_q_admin on public.questions for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- submissions: a student reads only their own; admins read all.
-- No INSERT policy exists -> direct inserts are blocked. Scoring goes through
-- submit_quiz() (SECURITY DEFINER), which is the only way to record a score.
drop policy if exists p_sub_read on public.submissions;
create policy p_sub_read on public.submissions for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
drop policy if exists p_sub_admin_del on public.submissions;
create policy p_sub_admin_del on public.submissions for delete to authenticated
  using (public.is_admin());

-- ---------- STUDENT: list available quizzes --------------------------------
create or replace function public.get_quizzes_for_student() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  select coalesce(jsonb_agg(obj order by st desc), '[]'::jsonb) into v_res
  from (
    select jsonb_build_object(
      'id', q.id, 'title', q.title, 'quiz_date', q.quiz_date,
      'start_at', q.start_at, 'end_at', q.end_at, 'duration_sec', q.duration_sec,
      'publish_answers', q.publish_answers,
      'num_questions', (select count(*) from public.questions where quiz_id = q.id),
      'already_submitted', exists(select 1 from public.submissions s where s.quiz_id=q.id and s.user_id=v_uid),
      'status', case when now() < q.start_at then 'upcoming'
                     when now() > q.end_at   then 'closed' else 'open' end
    ) obj, q.start_at st
    from public.quizzes q where q.published = true
  ) t;
  return v_res;
end; $$;

-- ---------- STUDENT: begin an attempt (questions WITHOUT answers) -----------
create or replace function public.start_quiz(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype; v_qs jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already attempted this quiz'; end if;

  select jsonb_agg(jsonb_build_object('id',id,'position',position,'text',text,'options',options) order by position)
    into v_qs from public.questions where quiz_id = p_quiz_id;

  return jsonb_build_object(
    'quiz', jsonb_build_object('id',v_quiz.id,'title',v_quiz.title,'duration_sec',v_quiz.duration_sec,
                               'violation_limit',v_quiz.violation_limit,'end_at',v_quiz.end_at),
    'questions', coalesce(v_qs, '[]'::jsonb));
end; $$;

-- ---------- STUDENT: submit & score (AUTHORITATIVE) ------------------------
-- Base: 10 per correct. Bonus (correct only): <=10s +3, <=20s +2, <=30s +1.
create or replace function public.submit_quiz(
  p_quiz_id uuid, p_answers int[], p_per_ms int[],
  p_violations int default 0, p_auto boolean default false
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_quiz public.quizzes%rowtype;
  v_correct int[];
  v_flags boolean[] := array[]::boolean[];
  v_base int := 0; v_bonus int := 0; v_total_ms bigint := 0;
  v_n int; i int; v_ans int; v_ms int; v_ok boolean; v_rank int;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already submitted this quiz'; end if;

  select array_agg(correct_index order by position) into v_correct
    from public.questions where quiz_id = p_quiz_id;
  v_n := coalesce(array_length(v_correct,1),0);

  for i in 1..v_n loop
    v_ans := coalesce(p_answers[i], -1);
    v_ms  := coalesce(p_per_ms[i], 0);
    v_total_ms := v_total_ms + v_ms;
    v_ok := (v_ans = v_correct[i]);
    v_flags := v_flags || v_ok;
    if v_ok then
      v_base := v_base + 10;
      if    v_ms <= 10000 then v_bonus := v_bonus + 3;
      elsif v_ms <= 20000 then v_bonus := v_bonus + 2;
      elsif v_ms <= 30000 then v_bonus := v_bonus + 1;
      end if;
    end if;
  end loop;

  insert into public.submissions(quiz_id,user_id,base,bonus,total,total_ms,per_ms,answers,correct,violations,auto_submitted)
  values(p_quiz_id,v_uid,v_base,v_bonus,v_base+v_bonus,v_total_ms,
         to_jsonb(p_per_ms),to_jsonb(p_answers),to_jsonb(v_flags),coalesce(p_violations,0),coalesce(p_auto,false));

  select count(*)+1 into v_rank from public.submissions
    where quiz_id=p_quiz_id and (total > v_base+v_bonus
      or (total = v_base+v_bonus and total_ms < v_total_ms));

  return jsonb_build_object('base',v_base,'bonus',v_bonus,'total',v_base+v_bonus,
                            'total_ms',v_total_ms,'correct',to_jsonb(v_flags),'rank',v_rank);
end; $$;

-- ---------- STUDENT: my full history (with rank per quiz) -------------------
create or replace function public.get_my_history() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  select coalesce(jsonb_agg(obj order by st desc), '[]'::jsonb) into v_res
  from (
    select jsonb_build_object(
      'quiz_id', s.quiz_id, 'title', q.title, 'quiz_date', q.quiz_date,
      'base', s.base, 'bonus', s.bonus, 'total', s.total, 'total_ms', s.total_ms,
      'submitted_at', s.submitted_at, 'auto_submitted', s.auto_submitted,
      'publish_answers', q.publish_answers, 'correct', s.correct,
      'num_correct', (select count(*) from jsonb_array_elements(s.correct) e where e::text='true'),
      'num_players', (select count(*) from public.submissions s3 where s3.quiz_id=s.quiz_id),
      'rank', (select count(*)+1 from public.submissions s2
               where s2.quiz_id=s.quiz_id and (s2.total>s.total or (s2.total=s.total and s2.total_ms<s.total_ms)))
    ) obj, s.submitted_at st
    from public.submissions s join public.quizzes q on q.id=s.quiz_id
    where s.user_id=v_uid
  ) t;
  return v_res;
end; $$;

-- ---------- LEADERBOARDS ----------------------------------------------------
create or replace function public.get_weekly_leaderboard(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object('username',p.username,'total',s.total,'total_ms',s.total_ms)
                     order by s.total desc, s.total_ms asc)
    from public.submissions s join public.profiles p on p.id=s.user_id
    where s.quiz_id = p_quiz_id), '[]'::jsonb);
end; $$;

create or replace function public.get_leaderboard(p_scope text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object('username',username,'total',total,'total_ms',total_ms)
                     order by total desc, total_ms asc)
    from (
      select p.username, sum(s.total) total, sum(s.total_ms) total_ms
      from public.submissions s join public.profiles p on p.id=s.user_id
      where (p_scope <> 'monthly')
         or (date_trunc('month', s.submitted_at) = date_trunc('month', now()))
      group by p.username
    ) agg), '[]'::jsonb);
end; $$;

-- ---------- ANSWER KEY (only after admin publishes, or for admins) ----------
create or replace function public.get_answer_key(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_pub boolean;
begin
  select publish_answers into v_pub from public.quizzes where id=p_quiz_id;
  if not (coalesce(v_pub,false) or public.is_admin()) then raise exception 'Answers are not published yet'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object('position',position,'text',text,'options',options,'correct_index',correct_index) order by position)
    from public.questions where quiz_id=p_quiz_id), '[]'::jsonb);
end; $$;

-- ---------- GRANTS ----------------------------------------------------------
grant usage on schema public to authenticated;
grant select on public.profiles, public.quizzes, public.submissions to authenticated;
grant insert, update, delete on public.quizzes, public.questions to authenticated;  -- gated by RLS (admins)
grant update on public.profiles to authenticated;                                   -- gated by RLS (admins)
grant delete on public.submissions to authenticated;                                -- gated by RLS (admins)
grant execute on function
  public.is_admin(), public.get_quizzes_for_student(), public.start_quiz(uuid),
  public.submit_quiz(uuid,int[],int[],int,boolean), public.get_my_history(),
  public.get_weekly_leaderboard(uuid), public.get_leaderboard(text), public.get_answer_key(uuid)
  to authenticated;

-- ---------- ADMIN: reset another user's password ---------------------------
create extension if not exists pgcrypto;
create or replace function public.admin_set_password(p_user_id uuid, p_password text)
returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not public.is_admin() then raise exception 'Only admins can reset passwords'; end if;
  if length(coalesce(p_password,'')) < 6 then raise exception 'Password must be at least 6 characters'; end if;
  if not exists (select 1 from public.profiles where id = p_user_id) then raise exception 'User not found'; end if;
  update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), updated_at = now() where id = p_user_id;
end; $$;
grant execute on function public.admin_set_password(uuid, text) to authenticated;


-- ===== v2 features (folded in for fresh installs) =====
-- ============================================================================
-- QUIZARENA v2 — new admin controls + richer submission data.
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
-- Adds: allow going back, hold-score-until-close, per-question timestamps.
-- ============================================================================

alter table public.quizzes     add column if not exists allow_back boolean not null default false;
alter table public.quizzes     add column if not exists hide_score_until_close boolean not null default false;
alter table public.submissions add column if not exists per_answered_at jsonb not null default '[]'::jsonb;

-- ---------- student quiz list (adds the two new flags) ----------------------
create or replace function public.get_quizzes_for_student() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  select coalesce(jsonb_agg(obj order by st desc), '[]'::jsonb) into v_res
  from (
    select jsonb_build_object(
      'id', q.id, 'title', q.title, 'quiz_date', q.quiz_date,
      'start_at', q.start_at, 'end_at', q.end_at, 'duration_sec', q.duration_sec,
      'publish_answers', q.publish_answers, 'allow_back', q.allow_back,
      'hide_score_until_close', q.hide_score_until_close,
      'num_questions', (select count(*) from public.questions where quiz_id = q.id),
      'already_submitted', exists(select 1 from public.submissions s where s.quiz_id=q.id and s.user_id=v_uid),
      'status', case when now() < q.start_at then 'upcoming'
                     when now() > q.end_at   then 'closed' else 'open' end
    ) obj, q.start_at st
    from public.quizzes q where q.published = true
  ) t;
  return v_res;
end; $$;

-- ---------- begin attempt (returns allow_back) ------------------------------
create or replace function public.start_quiz(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype; v_qs jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already attempted this quiz'; end if;
  select jsonb_agg(jsonb_build_object('id',id,'position',position,'text',text,'options',options) order by position)
    into v_qs from public.questions where quiz_id = p_quiz_id;
  return jsonb_build_object(
    'quiz', jsonb_build_object('id',v_quiz.id,'title',v_quiz.title,'duration_sec',v_quiz.duration_sec,
                               'violation_limit',v_quiz.violation_limit,'end_at',v_quiz.end_at,
                               'allow_back',v_quiz.allow_back),
    'questions', coalesce(v_qs, '[]'::jsonb));
end; $$;

-- ---------- submit & score (new: per-question timestamps + reveal gate) -----
drop function if exists public.submit_quiz(uuid, int[], int[], int, boolean);
create or replace function public.submit_quiz(
  p_quiz_id uuid, p_answers int[], p_per_ms int[], p_answered_at bigint[],
  p_violations int default 0, p_auto boolean default false
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_quiz public.quizzes%rowtype;
  v_correct int[];
  v_flags boolean[] := array[]::boolean[];
  v_base int := 0; v_bonus int := 0; v_total_ms bigint := 0;
  v_n int; i int; v_ans int; v_ms int; v_ok boolean; v_rank int; v_reveal boolean;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already submitted this quiz'; end if;

  select array_agg(correct_index order by position) into v_correct from public.questions where quiz_id = p_quiz_id;
  v_n := coalesce(array_length(v_correct,1),0);
  for i in 1..v_n loop
    v_ans := coalesce(p_answers[i], -1);
    v_ms  := coalesce(p_per_ms[i], 0);
    v_total_ms := v_total_ms + v_ms;
    v_ok := (v_ans = v_correct[i]);
    v_flags := v_flags || v_ok;
    if v_ok then
      v_base := v_base + 10;
      if    v_ms <= 10000 then v_bonus := v_bonus + 3;
      elsif v_ms <= 20000 then v_bonus := v_bonus + 2;
      elsif v_ms <= 30000 then v_bonus := v_bonus + 1;
      end if;
    end if;
  end loop;

  insert into public.submissions(quiz_id,user_id,base,bonus,total,total_ms,per_ms,answers,correct,per_answered_at,violations,auto_submitted)
  values(p_quiz_id,v_uid,v_base,v_bonus,v_base+v_bonus,v_total_ms,
         to_jsonb(p_per_ms),to_jsonb(p_answers),to_jsonb(v_flags),
         to_jsonb(coalesce(p_answered_at,'{}'::bigint[])),coalesce(p_violations,0),coalesce(p_auto,false));

  select count(*)+1 into v_rank from public.submissions
    where quiz_id=p_quiz_id and (total > v_base+v_bonus or (total = v_base+v_bonus and total_ms < v_total_ms));

  v_reveal := (not v_quiz.hide_score_until_close) or (now() > v_quiz.end_at) or public.is_admin();
  if v_reveal then
    return jsonb_build_object('reveal',true,'base',v_base,'bonus',v_bonus,'total',v_base+v_bonus,
                              'total_ms',v_total_ms,'correct',to_jsonb(v_flags),'rank',v_rank,'end_at',v_quiz.end_at);
  else
    return jsonb_build_object('reveal',false,'end_at',v_quiz.end_at);
  end if;
end; $$;
grant execute on function public.submit_quiz(uuid,int[],int[],bigint[],int,boolean) to authenticated;

-- ---------- my history (hides score until close when configured) -----------
create or replace function public.get_my_history() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  select coalesce(jsonb_agg(jsonb_build_object(
      'quiz_id', quiz_id, 'title', title, 'quiz_date', quiz_date, 'submitted_at', submitted_at,
      'auto_submitted', auto_submitted, 'publish_answers', publish_answers, 'revealed', rev,
      'total', case when rev then total end, 'base', case when rev then base end,
      'bonus', case when rev then bonus end, 'total_ms', case when rev then total_ms end,
      'num_correct', case when rev then ncorrect end, 'num_players', nplayers,
      'rank', case when rev then rnk end, 'correct', case when rev then correct end
    ) order by submitted_at desc), '[]'::jsonb) into v_res
  from (
    select s.quiz_id, q.title, q.quiz_date, s.submitted_at, s.auto_submitted, q.publish_answers,
      ((not q.hide_score_until_close) or now() > q.end_at) as rev,
      s.total, s.base, s.bonus, s.total_ms, s.correct,
      (select count(*) from jsonb_array_elements(s.correct) e where e::text='true') as ncorrect,
      (select count(*) from public.submissions s3 where s3.quiz_id=s.quiz_id) as nplayers,
      (select count(*)+1 from public.submissions s2 where s2.quiz_id=s.quiz_id
         and (s2.total>s.total or (s2.total=s.total and s2.total_ms<s.total_ms))) as rnk
    from public.submissions s join public.quizzes q on q.id=s.quiz_id
    where s.user_id=v_uid
  ) x;
  return v_res;
end; $$;

-- ---------- weekly board (hidden until close when configured) ---------------
create or replace function public.get_weekly_leaderboard(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_hide boolean; v_end timestamptz;
begin
  select hide_score_until_close, end_at into v_hide, v_end from public.quizzes where id = p_quiz_id;
  if coalesce(v_hide,false) and now() < v_end and not public.is_admin() then
    return '[]'::jsonb;
  end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object('username',p.username,'total',s.total,'total_ms',s.total_ms)
                     order by s.total desc, s.total_ms asc)
    from public.submissions s join public.profiles p on p.id=s.user_id
    where s.quiz_id = p_quiz_id), '[]'::jsonb);
end; $$;


-- ===== v3 features (folded in for fresh installs) =====
-- ============================================================================
-- QUIZARENA v3 — resilience + browsing.
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
-- Adds: server-tracked attempts (resumable clock + autosaved answers),
--       admin reset of a single student's submission, and an all-quizzes view.
-- ============================================================================

-- ---------- attempts: one in-progress row per (quiz, student) ---------------
create table if not exists public.attempts (
  quiz_id     uuid not null references public.quizzes(id)  on delete cascade,
  user_id     uuid not null references public.profiles(id) on delete cascade,
  started_at  timestamptz not null default now(),
  answers     jsonb not null default '[]'::jsonb,
  per_ms      jsonb not null default '[]'::jsonb,
  answered_at jsonb not null default '[]'::jsonb,
  updated_at  timestamptz not null default now(),
  primary key (quiz_id, user_id)
);
alter table public.attempts enable row level security;
drop policy if exists attempts_own_select on public.attempts;
create policy attempts_own_select on public.attempts
  for select using (user_id = auth.uid() or public.is_admin());
-- all writes happen through SECURITY DEFINER functions below (no client write policy).

-- ---------- peek: load the quiz WITHOUT starting the clock ------------------
-- Returns questions + whether an attempt is already in progress (for resume).
create or replace function public.peek_quiz(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype;
  v_qs jsonb; v_att public.attempts%rowtype; v_remaining int;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already attempted this quiz'; end if;

  select * into v_att from public.attempts where quiz_id=p_quiz_id and user_id=v_uid;

  if v_att.user_id is not null then
    v_remaining := greatest(0, floor(least(
      v_quiz.duration_sec - extract(epoch from (now() - v_att.started_at)),
      extract(epoch from (v_quiz.end_at - now())) ))::int);
  else
    v_remaining := greatest(0, floor(least(
      v_quiz.duration_sec, extract(epoch from (v_quiz.end_at - now())) ))::int);
  end if;

  select jsonb_agg(jsonb_build_object('id',id,'position',position,'text',text,'options',options) order by position)
    into v_qs from public.questions where quiz_id = p_quiz_id;

  return jsonb_build_object(
    'quiz', jsonb_build_object('id',v_quiz.id,'title',v_quiz.title,'duration_sec',v_quiz.duration_sec,
                               'violation_limit',v_quiz.violation_limit,'end_at',v_quiz.end_at,
                               'allow_back',v_quiz.allow_back),
    'questions', coalesce(v_qs, '[]'::jsonb),
    'has_attempt', v_att.user_id is not null,
    'remaining_sec', v_remaining,
    'saved', jsonb_build_object('answers', coalesce(v_att.answers,'[]'::jsonb),
                                'per_ms', coalesce(v_att.per_ms,'[]'::jsonb),
                                'answered_at', coalesce(v_att.answered_at,'[]'::jsonb)));
end; $$;
grant execute on function public.peek_quiz(uuid) to authenticated;

-- ---------- begin: create (or resume) the attempt; clock is authoritative ---
create or replace function public.begin_attempt(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype;
  v_att public.attempts%rowtype; v_remaining int;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already attempted this quiz'; end if;

  insert into public.attempts(quiz_id, user_id) values (p_quiz_id, v_uid)
    on conflict (quiz_id, user_id) do nothing;
  select * into v_att from public.attempts where quiz_id=p_quiz_id and user_id=v_uid;

  v_remaining := greatest(0, floor(least(
    v_quiz.duration_sec - extract(epoch from (now() - v_att.started_at)),
    extract(epoch from (v_quiz.end_at - now())) ))::int);

  return jsonb_build_object(
    'remaining_sec', v_remaining,
    'saved', jsonb_build_object('answers', coalesce(v_att.answers,'[]'::jsonb),
                                'per_ms', coalesce(v_att.per_ms,'[]'::jsonb),
                                'answered_at', coalesce(v_att.answered_at,'[]'::jsonb)));
end; $$;
grant execute on function public.begin_attempt(uuid) to authenticated;

-- ---------- autosave partial answers (called as the student plays) ----------
create or replace function public.save_progress(
  p_quiz_id uuid, p_answers int[], p_per_ms int[], p_answered_at bigint[]
) returns void
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_end timestamptz;
begin
  if v_uid is null then return; end if;
  select end_at into v_end from public.quizzes where id = p_quiz_id;
  if v_end is null or now() > v_end then return; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid) then return; end if;
  update public.attempts
     set answers = to_jsonb(coalesce(p_answers,'{}'::int[])),
         per_ms  = to_jsonb(coalesce(p_per_ms,'{}'::int[])),
         answered_at = to_jsonb(coalesce(p_answered_at,'{}'::bigint[])),
         updated_at = now()
   where quiz_id = p_quiz_id and user_id = v_uid;
end; $$;
grant execute on function public.save_progress(uuid,int[],int[],bigint[]) to authenticated;

-- ---------- submit (v3): same scoring as v2 + clears the attempt row --------
create or replace function public.submit_quiz(
  p_quiz_id uuid, p_answers int[], p_per_ms int[], p_answered_at bigint[],
  p_violations int default 0, p_auto boolean default false
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype;
  v_correct int[]; v_flags boolean[] := array[]::boolean[];
  v_base int := 0; v_bonus int := 0; v_total_ms bigint := 0;
  v_n int; i int; v_ans int; v_ms int; v_ok boolean; v_rank int; v_reveal boolean;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already submitted this quiz'; end if;

  select array_agg(correct_index order by position) into v_correct from public.questions where quiz_id = p_quiz_id;
  v_n := coalesce(array_length(v_correct,1),0);
  for i in 1..v_n loop
    v_ans := coalesce(p_answers[i], -1);
    v_ms  := coalesce(p_per_ms[i], 0);
    v_total_ms := v_total_ms + v_ms;
    v_ok := (v_ans = v_correct[i]);
    v_flags := v_flags || v_ok;
    if v_ok then
      v_base := v_base + 10;
      if    v_ms <= 10000 then v_bonus := v_bonus + 3;
      elsif v_ms <= 20000 then v_bonus := v_bonus + 2;
      elsif v_ms <= 30000 then v_bonus := v_bonus + 1;
      end if;
    end if;
  end loop;

  insert into public.submissions(quiz_id,user_id,base,bonus,total,total_ms,per_ms,answers,correct,per_answered_at,violations,auto_submitted)
  values(p_quiz_id,v_uid,v_base,v_bonus,v_base+v_bonus,v_total_ms,
         to_jsonb(p_per_ms),to_jsonb(p_answers),to_jsonb(v_flags),
         to_jsonb(coalesce(p_answered_at,'{}'::bigint[])),coalesce(p_violations,0),coalesce(p_auto,false));

  delete from public.attempts where quiz_id=p_quiz_id and user_id=v_uid;

  select count(*)+1 into v_rank from public.submissions
    where quiz_id=p_quiz_id and (total > v_base+v_bonus or (total = v_base+v_bonus and total_ms < v_total_ms));

  v_reveal := (not v_quiz.hide_score_until_close) or (now() > v_quiz.end_at) or public.is_admin();
  if v_reveal then
    return jsonb_build_object('reveal',true,'base',v_base,'bonus',v_bonus,'total',v_base+v_bonus,
                              'total_ms',v_total_ms,'correct',to_jsonb(v_flags),'rank',v_rank,'end_at',v_quiz.end_at);
  else
    return jsonb_build_object('reveal',false,'end_at',v_quiz.end_at);
  end if;
end; $$;
grant execute on function public.submit_quiz(uuid,int[],int[],bigint[],int,boolean) to authenticated;

-- ---------- admin: reset a SINGLE student's submission (allow re-attempt) ----
create or replace function public.admin_reset_user_submission(p_quiz_id uuid, p_user_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Admins only'; end if;
  delete from public.submissions where quiz_id = p_quiz_id and user_id = p_user_id;
  delete from public.attempts    where quiz_id = p_quiz_id and user_id = p_user_id;
end; $$;
grant execute on function public.admin_reset_user_submission(uuid,uuid) to authenticated;

-- ---------- student: every quiz + this student's score/stats ----------------
create or replace function public.get_all_quizzes_for_student() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  select coalesce(jsonb_agg(obj order by st desc), '[]'::jsonb) into v_res from (
    select jsonb_build_object(
      'id', q.id, 'title', q.title, 'quiz_date', q.quiz_date,
      'start_at', q.start_at, 'end_at', q.end_at, 'duration_sec', q.duration_sec,
      'num_questions', (select count(*) from public.questions where quiz_id=q.id),
      'publish_answers', q.publish_answers, 'allow_back', q.allow_back,
      'hide_score_until_close', q.hide_score_until_close,
      'status', case when now() < q.start_at then 'upcoming' when now() > q.end_at then 'closed' else 'open' end,
      'already_submitted', s.id is not null,
      'num_players', (select count(*) from public.submissions ss where ss.quiz_id=q.id),
      'revealed', rev,
      'total',       case when s.id is not null and rev then s.total end,
      'base',        case when s.id is not null and rev then s.base end,
      'bonus',       case when s.id is not null and rev then s.bonus end,
      'total_ms',    case when s.id is not null and rev then s.total_ms end,
      'num_correct', case when s.id is not null and rev then (select count(*) from jsonb_array_elements(s.correct) e where e::text='true') end,
      'rank',        case when s.id is not null and rev then (select count(*)+1 from public.submissions s2 where s2.quiz_id=q.id and (s2.total>s.total or (s2.total=s.total and s2.total_ms<s.total_ms))) end,
      'answers',     case when s.id is not null and rev then s.answers end,
      'correct',     case when s.id is not null and rev then s.correct end,
      'auto_submitted', case when s.id is not null then s.auto_submitted end
    ) obj, q.start_at st
    from public.quizzes q
    left join public.submissions s on s.quiz_id=q.id and s.user_id=v_uid
    , lateral (select ((not q.hide_score_until_close) or now()>q.end_at) as rev) r
    where q.published = true
  ) t;
  return v_res;
end; $$;
grant execute on function public.get_all_quizzes_for_student() to authenticated;


-- ===== v4 features (folded in for fresh installs) =====
-- ============================================================================
-- QUIZARENA v4 — auto-finalize.
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
-- When a quiz closes, any attempt that was started but never submitted is
-- scored from its autosaved answers (same scoring as a normal submit), so a
-- student who lost connection before submitting still gets credited.
--
-- Mechanism: finalization runs lazily whenever results are read after close
-- (leaderboards / history / the Quizzes tab / the admin submissions view).
-- That needs no scheduler and works even on a free project that was asleep.
-- For exact "the instant it closes" timing with nobody online, see the
-- optional pg_cron job in optional-cron.sql.
-- ============================================================================

-- ---------- score ONE leftover attempt from its saved answers ---------------
create or replace function public._finalize_one(p_quiz_id uuid, p_user_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_att public.attempts%rowtype;
  v_correct int[]; v_flags boolean[] := array[]::boolean[];
  v_answers int[]; v_perms int[]; v_answered bigint[];
  v_base int := 0; v_bonus int := 0; v_total_ms bigint := 0;
  v_n int; i int; v_ans int; v_ms int; v_ok boolean;
begin
  select * into v_att from public.attempts where quiz_id=p_quiz_id and user_id=p_user_id;
  if not found then return; end if;

  -- already submitted? just drop the stale attempt.
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=p_user_id) then
    delete from public.attempts where quiz_id=p_quiz_id and user_id=p_user_id; return;
  end if;

  select coalesce(array_agg((val)::int    order by ord), '{}'::int[])    into v_answers
    from jsonb_array_elements_text(v_att.answers)     with ordinality t(val, ord);
  select coalesce(array_agg((val)::int    order by ord), '{}'::int[])    into v_perms
    from jsonb_array_elements_text(v_att.per_ms)      with ordinality t(val, ord);
  select coalesce(array_agg((val)::bigint order by ord), '{}'::bigint[]) into v_answered
    from jsonb_array_elements_text(v_att.answered_at) with ordinality t(val, ord);

  select array_agg(correct_index order by position) into v_correct from public.questions where quiz_id=p_quiz_id;
  v_n := coalesce(array_length(v_correct,1),0);
  for i in 1..v_n loop
    v_ans := coalesce(v_answers[i], -1);
    v_ms  := coalesce(v_perms[i], 0);
    v_total_ms := v_total_ms + v_ms;
    v_ok := (v_ans = v_correct[i]);
    v_flags := v_flags || v_ok;
    if v_ok then
      v_base := v_base + 10;
      if    v_ms <= 10000 then v_bonus := v_bonus + 3;
      elsif v_ms <= 20000 then v_bonus := v_bonus + 2;
      elsif v_ms <= 30000 then v_bonus := v_bonus + 1;
      end if;
    end if;
  end loop;

  insert into public.submissions(quiz_id,user_id,base,bonus,total,total_ms,per_ms,answers,correct,per_answered_at,violations,auto_submitted)
  values(p_quiz_id,p_user_id,v_base,v_bonus,v_base+v_bonus,v_total_ms,
         to_jsonb(v_perms),to_jsonb(v_answers),to_jsonb(v_flags),to_jsonb(v_answered),0,true)
  on conflict (quiz_id,user_id) do nothing;

  delete from public.attempts where quiz_id=p_quiz_id and user_id=p_user_id;
end; $$;

-- ---------- finalize every leftover attempt for a CLOSED quiz ---------------
create or replace function public._sweep_quiz(p_quiz_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare v_end timestamptz; r record;
begin
  select end_at into v_end from public.quizzes where id = p_quiz_id;
  if v_end is null or now() <= v_end then return; end if;   -- only after the window shuts
  for r in select user_id from public.attempts where quiz_id = p_quiz_id loop
    perform public._finalize_one(p_quiz_id, r.user_id);
  end loop;
end; $$;

-- ---------- global sweep (used by the optional cron job) --------------------
create or replace function public.finalize_closed_attempts() returns void
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  for r in select a.quiz_id, a.user_id from public.attempts a
           join public.quizzes q on q.id = a.quiz_id where now() > q.end_at loop
    perform public._finalize_one(r.quiz_id, r.user_id);
  end loop;
end; $$;

-- ---------- admin-callable sweep for one quiz (idempotent, closed-only) ------
create or replace function public.ensure_finalized(p_quiz_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  perform public._sweep_quiz(p_quiz_id);
end; $$;
grant execute on function public.ensure_finalized(uuid) to authenticated;

-- ===========================================================================
-- Recreate the read paths so they sweep first — results are always complete.
-- ===========================================================================

-- weekly board: finalize this quiz's leftovers, then return the board ---------
create or replace function public.get_weekly_leaderboard(p_quiz_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_hide boolean; v_end timestamptz;
begin
  perform public._sweep_quiz(p_quiz_id);
  select hide_score_until_close, end_at into v_hide, v_end from public.quizzes where id = p_quiz_id;
  if coalesce(v_hide,false) and now() < v_end and not public.is_admin() then
    return '[]'::jsonb;
  end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object('username',p.username,'total',s.total,'total_ms',s.total_ms)
                     order by s.total desc, s.total_ms asc)
    from public.submissions s join public.profiles p on p.id=s.user_id
    where s.quiz_id = p_quiz_id), '[]'::jsonb);
end; $$;

-- my history: finalize my own closed leftovers, then build history ------------
create or replace function public.get_my_history() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb; r record;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  for r in select a.quiz_id from public.attempts a join public.quizzes q on q.id=a.quiz_id
           where a.user_id=v_uid and now() > q.end_at loop
    perform public._finalize_one(r.quiz_id, v_uid);
  end loop;

  select coalesce(jsonb_agg(jsonb_build_object(
      'quiz_id', quiz_id, 'title', title, 'quiz_date', quiz_date, 'submitted_at', submitted_at,
      'auto_submitted', auto_submitted, 'publish_answers', publish_answers, 'revealed', rev,
      'total', case when rev then total end, 'base', case when rev then base end,
      'bonus', case when rev then bonus end, 'total_ms', case when rev then total_ms end,
      'num_correct', case when rev then ncorrect end, 'num_players', nplayers,
      'rank', case when rev then rnk end, 'correct', case when rev then correct end
    ) order by submitted_at desc), '[]'::jsonb) into v_res
  from (
    select s.quiz_id, q.title, q.quiz_date, s.submitted_at, s.auto_submitted, q.publish_answers,
      ((not q.hide_score_until_close) or now() > q.end_at) as rev,
      s.total, s.base, s.bonus, s.total_ms, s.correct,
      (select count(*) from jsonb_array_elements(s.correct) e where e::text='true') as ncorrect,
      (select count(*) from public.submissions s3 where s3.quiz_id=s.quiz_id) as nplayers,
      (select count(*)+1 from public.submissions s2 where s2.quiz_id=s.quiz_id
         and (s2.total>s.total or (s2.total=s.total and s2.total_ms<s.total_ms))) as rnk
    from public.submissions s join public.quizzes q on q.id=s.quiz_id
    where s.user_id=v_uid
  ) x;
  return v_res;
end; $$;

-- overall/monthly board: global finalize first ------------------------------
create or replace function public.get_leaderboard(p_scope text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  perform public.finalize_closed_attempts();
  return coalesce((
    select jsonb_agg(jsonb_build_object('username',username,'total',total,'total_ms',total_ms)
                     order by total desc, total_ms asc)
    from (
      select p.username, sum(s.total) total, sum(s.total_ms) total_ms
      from public.submissions s join public.profiles p on p.id=s.user_id
      where (p_scope <> 'monthly')
         or (date_trunc('month', s.submitted_at) = date_trunc('month', now()))
      group by p.username
    ) agg), '[]'::jsonb);
end; $$;

-- all quizzes for a student: finalize my own closed leftovers first ----------
create or replace function public.get_all_quizzes_for_student() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_res jsonb; r record;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  for r in select a.quiz_id from public.attempts a join public.quizzes q on q.id=a.quiz_id
           where a.user_id=v_uid and now() > q.end_at loop
    perform public._finalize_one(r.quiz_id, v_uid);
  end loop;

  select coalesce(jsonb_agg(obj order by st desc), '[]'::jsonb) into v_res from (
    select jsonb_build_object(
      'id', q.id, 'title', q.title, 'quiz_date', q.quiz_date,
      'start_at', q.start_at, 'end_at', q.end_at, 'duration_sec', q.duration_sec,
      'num_questions', (select count(*) from public.questions where quiz_id=q.id),
      'publish_answers', q.publish_answers, 'allow_back', q.allow_back,
      'hide_score_until_close', q.hide_score_until_close,
      'status', case when now() < q.start_at then 'upcoming' when now() > q.end_at then 'closed' else 'open' end,
      'already_submitted', s.id is not null,
      'num_players', (select count(*) from public.submissions ss where ss.quiz_id=q.id),
      'revealed', rev,
      'total',       case when s.id is not null and rev then s.total end,
      'base',        case when s.id is not null and rev then s.base end,
      'bonus',       case when s.id is not null and rev then s.bonus end,
      'total_ms',    case when s.id is not null and rev then s.total_ms end,
      'num_correct', case when s.id is not null and rev then (select count(*) from jsonb_array_elements(s.correct) e where e::text='true') end,
      'rank',        case when s.id is not null and rev then (select count(*)+1 from public.submissions s2 where s2.quiz_id=q.id and (s2.total>s.total or (s2.total=s.total and s2.total_ms<s.total_ms))) end,
      'answers',     case when s.id is not null and rev then s.answers end,
      'correct',     case when s.id is not null and rev then s.correct end,
      'auto_submitted', case when s.id is not null then s.auto_submitted end
    ) obj, q.start_at st
    from public.quizzes q
    left join public.submissions s on s.quiz_id=q.id and s.user_id=v_uid
    , lateral (select ((not q.hide_score_until_close) or now()>q.end_at) as rev) r2
    where q.published = true
  ) t;
  return v_res;
end; $$;


-- ===== v5 features (folded in for fresh installs) =====
-- ============================================================================
-- QUIZARENA v5 — one attempt per device (opt-in, per quiz).
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
--
-- Records a per-device token + a browser fingerprint with each attempt. When a
-- quiz has "device lock" enabled, a device that already submitted it is blocked
-- from starting again under a different account. This stops the common
-- "log out, make a new account, retake on the same browser" abuse.
--
-- IMPORTANT (honest limits): this is friction, not a guarantee. A determined
-- student can bypass it with a different browser, another device, or private/
-- incognito mode. And a SHARED device (several students taking turns on one
-- computer) will be blocked after the first — so only enable it where each
-- student has their own device. The fingerprint is also stored so the admin
-- can SEE multiple accounts on one device even when they bypass the hard block.
-- ============================================================================

alter table public.quizzes     add column if not exists device_lock boolean not null default false;
alter table public.submissions add column if not exists device_id text;
alter table public.submissions add column if not exists device_fp text;
alter table public.attempts    add column if not exists device_id text;
alter table public.attempts    add column if not exists device_fp text;
create index if not exists submissions_device_idx on public.submissions(quiz_id, device_id);

-- ---------- peek (adds device-lock check) -----------------------------------
drop function if exists public.peek_quiz(uuid);
create or replace function public.peek_quiz(p_quiz_id uuid, p_device_id text default null, p_device_fp text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype;
  v_qs jsonb; v_att public.attempts%rowtype; v_remaining int;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already attempted this quiz'; end if;
  if v_quiz.device_lock and p_device_id is not null
     and exists(select 1 from public.submissions where quiz_id=p_quiz_id and device_id=p_device_id and user_id<>v_uid)
    then raise exception 'This device has already been used to take this quiz.'; end if;

  select * into v_att from public.attempts where quiz_id=p_quiz_id and user_id=v_uid;
  if v_att.user_id is not null then
    v_remaining := greatest(0, floor(least(
      v_quiz.duration_sec - extract(epoch from (now() - v_att.started_at)),
      extract(epoch from (v_quiz.end_at - now())) ))::int);
  else
    v_remaining := greatest(0, floor(least(
      v_quiz.duration_sec, extract(epoch from (v_quiz.end_at - now())) ))::int);
  end if;

  select jsonb_agg(jsonb_build_object('id',id,'position',position,'text',text,'options',options) order by position)
    into v_qs from public.questions where quiz_id = p_quiz_id;

  return jsonb_build_object(
    'quiz', jsonb_build_object('id',v_quiz.id,'title',v_quiz.title,'duration_sec',v_quiz.duration_sec,
                               'violation_limit',v_quiz.violation_limit,'end_at',v_quiz.end_at,
                               'allow_back',v_quiz.allow_back),
    'questions', coalesce(v_qs, '[]'::jsonb),
    'has_attempt', v_att.user_id is not null,
    'remaining_sec', v_remaining,
    'saved', jsonb_build_object('answers', coalesce(v_att.answers,'[]'::jsonb),
                                'per_ms', coalesce(v_att.per_ms,'[]'::jsonb),
                                'answered_at', coalesce(v_att.answered_at,'[]'::jsonb)));
end; $$;
grant execute on function public.peek_quiz(uuid,text,text) to authenticated;

-- ---------- begin (stores device on the attempt + re-checks lock) -----------
drop function if exists public.begin_attempt(uuid);
create or replace function public.begin_attempt(p_quiz_id uuid, p_device_id text default null, p_device_fp text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype;
  v_att public.attempts%rowtype; v_remaining int;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already attempted this quiz'; end if;
  if v_quiz.device_lock and p_device_id is not null
     and exists(select 1 from public.submissions where quiz_id=p_quiz_id and device_id=p_device_id and user_id<>v_uid)
    then raise exception 'This device has already been used to take this quiz.'; end if;

  insert into public.attempts(quiz_id, user_id, device_id, device_fp)
    values (p_quiz_id, v_uid, p_device_id, p_device_fp)
    on conflict (quiz_id, user_id) do update
      set device_id = coalesce(public.attempts.device_id, excluded.device_id),
          device_fp = coalesce(public.attempts.device_fp, excluded.device_fp);
  select * into v_att from public.attempts where quiz_id=p_quiz_id and user_id=v_uid;

  v_remaining := greatest(0, floor(least(
    v_quiz.duration_sec - extract(epoch from (now() - v_att.started_at)),
    extract(epoch from (v_quiz.end_at - now())) ))::int);

  return jsonb_build_object(
    'remaining_sec', v_remaining,
    'saved', jsonb_build_object('answers', coalesce(v_att.answers,'[]'::jsonb),
                                'per_ms', coalesce(v_att.per_ms,'[]'::jsonb),
                                'answered_at', coalesce(v_att.answered_at,'[]'::jsonb)));
end; $$;
grant execute on function public.begin_attempt(uuid,text,text) to authenticated;

-- ---------- submit (stores device + re-checks lock at the last moment) ------
drop function if exists public.submit_quiz(uuid,int[],int[],bigint[],int,boolean);
create or replace function public.submit_quiz(
  p_quiz_id uuid, p_answers int[], p_per_ms int[], p_answered_at bigint[],
  p_violations int default 0, p_auto boolean default false,
  p_device_id text default null, p_device_fp text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid(); v_quiz public.quizzes%rowtype;
  v_correct int[]; v_flags boolean[] := array[]::boolean[];
  v_base int := 0; v_bonus int := 0; v_total_ms bigint := 0;
  v_n int; i int; v_ans int; v_ms int; v_ok boolean; v_rank int; v_reveal boolean;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if (select banned from public.profiles where id = v_uid) then raise exception 'Account is banned'; end if;
  select * into v_quiz from public.quizzes where id = p_quiz_id;
  if not found or not v_quiz.published then raise exception 'Quiz not available'; end if;
  if now() < v_quiz.start_at then raise exception 'This quiz has not opened yet'; end if;
  if now() > v_quiz.end_at   then raise exception 'The submission window has closed'; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=v_uid)
    then raise exception 'You have already submitted this quiz'; end if;
  if v_quiz.device_lock and p_device_id is not null
     and exists(select 1 from public.submissions where quiz_id=p_quiz_id and device_id=p_device_id and user_id<>v_uid)
    then raise exception 'This device has already been used to take this quiz.'; end if;

  select array_agg(correct_index order by position) into v_correct from public.questions where quiz_id = p_quiz_id;
  v_n := coalesce(array_length(v_correct,1),0);
  for i in 1..v_n loop
    v_ans := coalesce(p_answers[i], -1);
    v_ms  := coalesce(p_per_ms[i], 0);
    v_total_ms := v_total_ms + v_ms;
    v_ok := (v_ans = v_correct[i]);
    v_flags := v_flags || v_ok;
    if v_ok then
      v_base := v_base + 10;
      if    v_ms <= 10000 then v_bonus := v_bonus + 3;
      elsif v_ms <= 20000 then v_bonus := v_bonus + 2;
      elsif v_ms <= 30000 then v_bonus := v_bonus + 1;
      end if;
    end if;
  end loop;

  insert into public.submissions(quiz_id,user_id,base,bonus,total,total_ms,per_ms,answers,correct,per_answered_at,violations,auto_submitted,device_id,device_fp)
  values(p_quiz_id,v_uid,v_base,v_bonus,v_base+v_bonus,v_total_ms,
         to_jsonb(p_per_ms),to_jsonb(p_answers),to_jsonb(v_flags),
         to_jsonb(coalesce(p_answered_at,'{}'::bigint[])),coalesce(p_violations,0),coalesce(p_auto,false),
         p_device_id,p_device_fp);

  delete from public.attempts where quiz_id=p_quiz_id and user_id=v_uid;

  select count(*)+1 into v_rank from public.submissions
    where quiz_id=p_quiz_id and (total > v_base+v_bonus or (total = v_base+v_bonus and total_ms < v_total_ms));

  v_reveal := (not v_quiz.hide_score_until_close) or (now() > v_quiz.end_at) or public.is_admin();
  if v_reveal then
    return jsonb_build_object('reveal',true,'base',v_base,'bonus',v_bonus,'total',v_base+v_bonus,
                              'total_ms',v_total_ms,'correct',to_jsonb(v_flags),'rank',v_rank,'end_at',v_quiz.end_at);
  else
    return jsonb_build_object('reveal',false,'end_at',v_quiz.end_at);
  end if;
end; $$;
grant execute on function public.submit_quiz(uuid,int[],int[],bigint[],int,boolean,text,text) to authenticated;

-- ---------- auto-finalize carries the device forward too --------------------
create or replace function public._finalize_one(p_quiz_id uuid, p_user_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_att public.attempts%rowtype;
  v_correct int[]; v_flags boolean[] := array[]::boolean[];
  v_answers int[]; v_perms int[]; v_answered bigint[];
  v_base int := 0; v_bonus int := 0; v_total_ms bigint := 0;
  v_n int; i int; v_ans int; v_ms int; v_ok boolean;
begin
  select * into v_att from public.attempts where quiz_id=p_quiz_id and user_id=p_user_id;
  if not found then return; end if;
  if exists(select 1 from public.submissions where quiz_id=p_quiz_id and user_id=p_user_id) then
    delete from public.attempts where quiz_id=p_quiz_id and user_id=p_user_id; return;
  end if;

  select coalesce(array_agg((val)::int    order by ord), '{}'::int[])    into v_answers
    from jsonb_array_elements_text(v_att.answers)     with ordinality t(val, ord);
  select coalesce(array_agg((val)::int    order by ord), '{}'::int[])    into v_perms
    from jsonb_array_elements_text(v_att.per_ms)      with ordinality t(val, ord);
  select coalesce(array_agg((val)::bigint order by ord), '{}'::bigint[]) into v_answered
    from jsonb_array_elements_text(v_att.answered_at) with ordinality t(val, ord);

  select array_agg(correct_index order by position) into v_correct from public.questions where quiz_id=p_quiz_id;
  v_n := coalesce(array_length(v_correct,1),0);
  for i in 1..v_n loop
    v_ans := coalesce(v_answers[i], -1);
    v_ms  := coalesce(v_perms[i], 0);
    v_total_ms := v_total_ms + v_ms;
    v_ok := (v_ans = v_correct[i]);
    v_flags := v_flags || v_ok;
    if v_ok then
      v_base := v_base + 10;
      if    v_ms <= 10000 then v_bonus := v_bonus + 3;
      elsif v_ms <= 20000 then v_bonus := v_bonus + 2;
      elsif v_ms <= 30000 then v_bonus := v_bonus + 1;
      end if;
    end if;
  end loop;

  insert into public.submissions(quiz_id,user_id,base,bonus,total,total_ms,per_ms,answers,correct,per_answered_at,violations,auto_submitted,device_id,device_fp)
  values(p_quiz_id,p_user_id,v_base,v_bonus,v_base+v_bonus,v_total_ms,
         to_jsonb(v_perms),to_jsonb(v_answers),to_jsonb(v_flags),to_jsonb(v_answered),0,true,v_att.device_id,v_att.device_fp)
  on conflict (quiz_id,user_id) do nothing;

  delete from public.attempts where quiz_id=p_quiz_id and user_id=p_user_id;
end; $$;


-- ===== v6 features (folded in for fresh installs) =====
-- ============================================================================
-- QUIZARENA v6 — the strong fix: teacher-controlled accounts.
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
--
-- The only airtight way to stop "make a new account and retake" is to stop
-- students making accounts at all. This adds:
--   * a switch to turn student self-registration on/off
--   * a way for the admin to create student accounts from inside the app
--
-- FOR FULL LOCKDOWN also flip the matching Supabase switch (one time):
--   Dashboard -> Authentication -> Sign In / Providers -> turn OFF
--   "Allow new users to sign up".
-- That stops sign-ups at the auth server itself; the switch below controls the
-- app's own UI/echo of that policy.
-- ============================================================================

create extension if not exists pgcrypto;

-- ---------- one-row settings table ------------------------------------------
create table if not exists public.app_settings (
  id int primary key default 1,
  allow_self_registration boolean not null default true,
  constraint app_settings_singleton check (id = 1)
);
insert into public.app_settings (id) values (1) on conflict (id) do nothing;

alter table public.app_settings enable row level security;
drop policy if exists p_settings_read on public.app_settings;
create policy p_settings_read on public.app_settings for select using (true);          -- readable pre-login
drop policy if exists p_settings_admin on public.app_settings;
create policy p_settings_admin on public.app_settings for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------- admin creates a student account (no service key in the browser) --
create or replace function public.admin_create_student(p_username text, p_password text) returns jsonb
language plpgsql security definer set search_path = public, extensions, auth as $$
declare v_uid uuid := gen_random_uuid(); v_clean text; v_email text;
begin
  if not public.is_admin() then raise exception 'Only admins can create accounts'; end if;
  v_clean := trim(p_username);
  if length(v_clean) < 3 then raise exception 'Username needs at least 3 characters'; end if;
  if length(coalesce(p_password,'')) < 6 then raise exception 'Password needs at least 6 characters'; end if;
  v_email := regexp_replace(lower(v_clean), '[^a-z0-9._-]', '_', 'g') || '@students.quizarena.app';
  if exists (select 1 from auth.users where email = v_email) then
    raise exception 'That username is already taken';
  end if;

  -- create the auth user (email pre-confirmed so username-only login works)
  insert into auth.users (id, instance_id, aud, role, email, encrypted_password,
                          email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
                          created_at, updated_at)
  values (v_uid, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
          v_email, crypt(p_password, gen_salt('bf')),
          now(), '{"provider":"email","providers":["email"]}'::jsonb,
          jsonb_build_object('username', v_clean),
          now(), now());

  -- email identity row (required for password login)
  insert into auth.identities (provider_id, user_id, identity_data, provider,
                               last_sign_in_at, created_at, updated_at)
  values (v_uid::text, v_uid, jsonb_build_object('sub', v_uid::text, 'email', v_email),
          'email', now(), now(), now());

  -- profiles row is created automatically by the existing handle_new_user trigger.
  return jsonb_build_object('username', v_clean, 'email', v_email);
end; $$;
grant execute on function public.admin_create_student(text,text) to authenticated;


-- ===== v7 features (folded in for fresh installs) =====
-- ============================================================================
-- QUIZARENA v7 — one browser = one account.
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
--
-- Ties a browser (its stored device token) to the first account that logs in
-- on it. A second, different account can't be created or used in that browser.
-- Admins are exempt (they can sign in anywhere). If a student legitimately
-- needs to move devices, the admin can "Unlink" them from the Users tab.
--
-- NOTE: like any browser-based lock this is friction, not a guarantee — a user
-- who clears storage, uses private mode, or switches browsers/devices gets a
-- fresh token. It stops the casual "log out, make another account here" case.
-- ============================================================================

create table if not exists public.browser_accounts (
  device_id  text primary key,
  user_id    uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.browser_accounts enable row level security;   -- access via SECURITY DEFINER fns only

-- is this browser free to register a brand-new account? (called before sign-up)
create or replace function public.browser_is_free(p_device_id text) returns boolean
language sql security definer set search_path = public as $$
  select case when p_device_id is null then true
              else not exists (select 1 from public.browser_accounts where device_id = p_device_id) end;
$$;
grant execute on function public.browser_is_free(text) to anon, authenticated;

-- bind this browser to the current account (called right after login/register)
create or replace function public.bind_browser(p_device_id text) returns void
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid(); v_owner uuid;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if p_device_id is null or public.is_admin() then return; end if;   -- admins log in anywhere
  select user_id into v_owner from public.browser_accounts where device_id = p_device_id;
  if v_owner is null then
    begin
      insert into public.browser_accounts(device_id, user_id) values (p_device_id, v_uid);
    exception when unique_violation then
      select user_id into v_owner from public.browser_accounts where device_id = p_device_id;
      if v_owner <> v_uid then raise exception 'This browser is already linked to another account.'; end if;
    end;
  elsif v_owner <> v_uid then
    raise exception 'This browser is already linked to another account. Log in to that account, or use a different device.';
  end if;
end; $$;
grant execute on function public.bind_browser(text) to authenticated;

-- admin: free a student's browser link(s) so they can sign in on a new device
create or replace function public.admin_free_browser(p_user_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Admins only'; end if;
  delete from public.browser_accounts where user_id = p_user_id;
end; $$;
grant execute on function public.admin_free_browser(uuid) to authenticated;


-- ===== admin delete user (folded in) =====
-- ============================================================================
-- QUIZARENA — admin: permanently delete a user (login + all their data).
-- Run ONCE in the Supabase SQL Editor. Safe to re-run.
-- Removes the account's submissions, attempts, device/browser links, profile,
-- and the auth login itself — so they disappear from every leaderboard & stat.
-- Admins cannot be deleted (this also stops you deleting your own account).
-- ============================================================================

create or replace function public.admin_delete_user(p_user_id uuid) returns jsonb
language plpgsql security definer set search_path = public, auth as $$
declare v_name text; v_role text;
begin
  if not public.is_admin() then raise exception 'Admins only'; end if;
  select username, role into v_name, v_role from public.profiles where id = p_user_id;
  if v_name is null then raise exception 'User not found'; end if;
  if v_role = 'admin' then raise exception 'You cannot delete an admin account.'; end if;

  delete from public.submissions     where user_id = p_user_id;
  delete from public.attempts         where user_id = p_user_id;
  delete from public.browser_accounts where user_id = p_user_id;
  delete from public.profiles         where id      = p_user_id;
  delete from auth.users              where id      = p_user_id;

  return jsonb_build_object('deleted', v_name);
end; $$;
grant execute on function public.admin_delete_user(uuid) to authenticated;
