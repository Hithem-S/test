-- policies.sql
create table if not exists public.user_profiles (
  id uuid not null primary key,
  employee_id bigint null,
  is_admin boolean default false,
  is_manager boolean default false,
  created_at timestamptz default now()
);

alter table if exists public.customers enable row level security;
alter table if exists public.customer_contacts enable row level security;
alter table if exists public.visits enable row level security;
alter table if exists public.sales enable row level security;
alter table if exists public.sales_funnel enable row level security;
alter table if exists public.territories enable row level security;
alter table if exists public.territory_sales_reps enable row level security;
alter table if exists public.employees enable row level security;
alter table if exists public.audit_logs enable row level security;
alter table if exists public.products enable row level security;
alter table if exists public.hospitals enable row level security;
alter table if exists public.hospital_branches enable row level security;
alter table if exists public.hospital_departments enable row level security;
alter table if exists public.visits enable row level security;

create policy if not exists "customers: select by assigned territory or admin" on public.customers
  for select using (
    exists (
      select 1
      from public.user_profiles up
      join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id
      where up.id = auth.uid()
        and tsr.territory_id = public.customers.territory_id
    )
    or exists (
      select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true
    )
  );

create policy if not exists "customers: insert for authenticated" on public.customers
  for insert with check (auth.uid() is not null);

create policy if not exists "customers: update_delete by territory or admin" on public.customers
  for update, delete using (
    exists (
      select 1
      from public.user_profiles up
      join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id
      where up.id = auth.uid()
        and tsr.territory_id = public.customers.territory_id
    )
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  ) with check (
    exists (
      select 1
      from public.user_profiles up
      join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id
      where up.id = auth.uid()
        and tsr.territory_id = public.customers.territory_id
    )
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  );

create policy if not exists "customer_contacts: select by parent customer" on public.customer_contacts
  for select using (
    exists (
      select 1
      from public.customers c
      where c.id = public.customer_contacts.customer_id
        and (
          exists (
            select 1 from public.user_profiles up join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id
            where up.id = auth.uid() and tsr.territory_id = c.territory_id
          )
          or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
        )
    )
  );

create policy if not exists "customer_contacts: insert authenticated" on public.customer_contacts
  for insert with check (auth.uid() is not null);

create policy if not exists "customer_contacts: update_delete owner or admin or territory" on public.customer_contacts
  for update, delete using (
    (public.customer_contacts.created_by_uuid = auth.uid())
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
    or exists (
      select 1
      from public.customers c
      join public.user_profiles up on up.id = auth.uid()
      join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id
      where c.id = public.customer_contacts.customer_id
        and tsr.territory_id = c.territory_id
    )
  ) with check (
    (public.customer_contacts.created_by_uuid = auth.uid())
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  );

create policy if not exists "visits: select by customer territory or owner" on public.visits
  for select using (
    exists (
      select 1
      from public.customers c
      where c.id = public.visits.customer_id
        and (
          exists (select 1 from public.user_profiles up join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id where up.id = auth.uid() and tsr.territory_id = c.territory_id)
          or public.visits.sales_rep = (
            select e.full_name from public.employees e join public.user_profiles up on up.employee_id = e.id where up.id = auth.uid()
          )
          or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
        )
    )
  );

create policy if not exists "visits: insert authenticated" on public.visits
  for insert with check (auth.uid() is not null);

create policy if not exists "visits: update_delete owner or admin" on public.visits
  for update, delete using (
    (public.visits.created_at is not null)
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  ) with check (auth.uid() is not null);

create policy if not exists "sales: select by territory or admin" on public.sales
  for select using (
    exists (
      select 1 from public.customers c where c.hospital_id = public.sales.hospital_id
      and exists (
        select 1 from public.user_profiles up join public.territory_sales_reps tsr on tsr.employee_id = up.employee_id
        where up.id = auth.uid() and tsr.territory_id = c.territory_id
      )
    )
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  );

create policy if not exists "sales_funnel: select by department->hospital->territory or admin" on public.sales_funnel
  for select using (
    exists (
      select 1
      from public.hospital_departments hd
      join public.hospital_branches hb on hb.branch_id = hd.branch_id
      join public.territories t on t.territory_id = hb.territory_id
      join public.user_profiles up on up.id = auth.uid()
      join public.territory_sales_reps tsr on tsr.territory_id = t.territory_id and tsr.employee_id = up.employee_id
      where hd.department_id = public.sales_funnel.hospital_department_id
    )
    or exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  );

create policy if not exists "employees: select for authenticated" on public.employees
  for select using (auth.uid() is not null);

create policy if not exists "employees: admin only write" on public.employees
  for insert, update, delete using (
    exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  ) with check (
    exists (select 1 from public.user_profiles up where up.id = auth.uid() and up.is_admin = true)
  );

create policy if not exists "territory_sales_reps: select for authenticated" on public.territory_sales_reps
  for select using (auth.uid() is not null);

create policy if not exists "territory_sales_reps: admin or manager write" on public.territory_sales_reps
  for insert, update, delete using (
    exists (select 1 from public.user_profiles up where up.id = auth.uid() and (up.is_admin = true or up.is_manager = true))
  ) with check (
    exists (select 1 from public.user_profiles up where up.id = auth.uid() and (up.is_admin = true or up.is_manager = true))
  );

create policy if not exists "audit_logs: service role only" on public.audit_logs
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
