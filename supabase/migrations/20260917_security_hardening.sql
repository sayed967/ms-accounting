-- Move remaining authorization helpers away from public RPC exposure

drop policy if exists company_industrial_select on public.company_industrial_details;
create policy company_industrial_select on public.company_industrial_details for select to authenticated using(private.is_office_staff());
drop policy if exists company_industrial_write on public.company_industrial_details;
create policy company_industrial_write on public.company_industrial_details for all to authenticated using(private.can_write_office_data()) with check(private.can_write_office_data());

drop policy if exists company_investment_select on public.company_investment_details;
create policy company_investment_select on public.company_investment_details for select to authenticated using(private.is_office_staff());
drop policy if exists company_investment_write on public.company_investment_details;
create policy company_investment_write on public.company_investment_details for all to authenticated using(private.can_write_office_data()) with check(private.can_write_office_data());

drop policy if exists staff_all on public.tax_returns;
create policy staff_all on public.tax_returns for all to authenticated using(private.is_office_staff()) with check(private.is_office_staff());

create or replace function private.refresh_invoice_status()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare inv_id uuid; paid numeric; total numeric; old_status text;
begin
  inv_id:=case when tg_op='DELETE' then old.invoice_id else new.invoice_id end;
  select coalesce(sum(amount),0) into paid from public.invoice_payments where invoice_id=inv_id;
  select total_amount,status into total,old_status from public.invoices where id=inv_id;
  if total is not null then
    update public.invoices set status=case when old_status='cancelled' then 'cancelled' when paid<=0 then 'unpaid' when paid<total then 'partial' else 'paid' end,updated_at=now() where id=inv_id;
  end if;
  if tg_op='DELETE' then return old; else return new; end if;
end $$;
revoke all on function private.refresh_invoice_status() from public,anon,authenticated;
grant execute on function private.refresh_invoice_status() to postgres,service_role;
drop trigger if exists invoice_payment_status on public.invoice_payments;
create trigger invoice_payment_status after insert or update or delete on public.invoice_payments for each row execute function private.refresh_invoice_status();

drop function if exists public.refresh_invoice_status();
drop function if exists public.is_office_staff();
drop function if exists public.is_office_admin();
