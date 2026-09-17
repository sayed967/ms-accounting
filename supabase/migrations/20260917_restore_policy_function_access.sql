-- Required by RLS policies for authenticated office users.
grant execute on function public.is_office_staff() to authenticated;
grant execute on function public.is_office_admin() to authenticated;
