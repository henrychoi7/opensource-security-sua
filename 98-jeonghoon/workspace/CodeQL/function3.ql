import java

from Parameter p
where not exists(p.getAnAccess())
select p
