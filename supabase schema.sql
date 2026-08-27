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
