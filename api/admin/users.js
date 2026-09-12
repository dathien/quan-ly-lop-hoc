import { sql, getSession, isAdmin, hashPassword, json } from '../_auth.js';

const ROLES=new Set(['admin','loptruong','bithu','thuquy']);
const DEFAULTS={
  loptruong:['discipline','duty','tasks'],
  bithu:['weekly','tasks'],
  thuquy:['finance','reports']
};

function cleanPerms(x){
  if(!Array.isArray(x)) return [];
  return [...new Set(x.map(String).filter(Boolean))].slice(0,50);
}

export default async function handler(req,res){
  try{
    const admin=await getSession(req);
    if(!isAdmin(admin)) return json(res,403,{ok:false,error:'Chỉ GVCN/Admin được quản lý thành viên'});

    if(req.method==='GET'){
      const rows=await sql`
        SELECT id, username, full_name, role, google_email, permissions, active, created_at, updated_at
        FROM gvcn_users ORDER BY CASE WHEN role='admin' THEN 0 ELSE 1 END, created_at
      `;
      return json(res,200,{ok:true,users:rows});
    }

    if(req.method==='POST'){
      const b=req.body||{};
      const role=String(b.role||'').trim();
      const username=String(b.username||'').trim().toLowerCase();
      const fullName=String(b.fullName||'').trim();
      const password=String(b.password||'');
      const googleEmail=String(b.googleEmail||'').trim().toLowerCase()||null;
      if(!ROLES.has(role) || role==='admin') return json(res,400,{ok:false,error:'Vai trò không hợp lệ'});
      if(username.length<3 || !fullName || password.length<8) return json(res,400,{ok:false,error:'Tên, tài khoản hoặc mật khẩu chưa hợp lệ'});
      const id='u_'+Date.now().toString(36)+Math.random().toString(36).slice(2,8);
      const hash=hashPassword(password);
      const perms=cleanPerms(b.permissions?.length?b.permissions:DEFAULTS[role]||[]);
      await sql`
        INSERT INTO gvcn_users(id,username,password_hash,full_name,role,google_email,permissions,active)
        VALUES(${id},${username},${hash},${fullName},${role},${googleEmail},${JSON.stringify(perms)}::jsonb,true)
      `;
      return json(res,200,{ok:true});
    }

    if(req.method==='PATCH'){
      const b=req.body||{};
      const id=String(b.id||'');
      const rows=await sql`SELECT * FROM gvcn_users WHERE id=${id} LIMIT 1`;
      const old=rows[0];
      if(!old) return json(res,404,{ok:false,error:'Không tìm thấy thành viên'});
      const username=String(b.username??old.username).trim().toLowerCase();
      const fullName=String(b.fullName??old.full_name).trim();
      const role=String(b.role??old.role);
      const googleEmail=String(b.googleEmail??old.google_email??'').trim().toLowerCase()||null;
      const active=typeof b.active==='boolean'?b.active:old.active;
      const perms=role==='admin'?['*']:cleanPerms(b.permissions??old.permissions??[]);
      if(!ROLES.has(role)) return json(res,400,{ok:false,error:'Vai trò không hợp lệ'});
      if(old.role==='admin' && role!=='admin') return json(res,400,{ok:false,error:'Không thể hạ quyền tài khoản Admin chính'});
      let passwordHash=old.password_hash;
      if(String(b.password||'').trim()){
        if(String(b.password).length<8) return json(res,400,{ok:false,error:'Mật khẩu phải từ 8 ký tự'});
        passwordHash=hashPassword(String(b.password));
      }
      await sql`
        UPDATE gvcn_users SET
          username=${username}, password_hash=${passwordHash}, full_name=${fullName}, role=${role},
          google_email=${googleEmail}, permissions=${JSON.stringify(perms)}::jsonb,
          active=${active}, updated_at=NOW()
        WHERE id=${id}
      `;
      return json(res,200,{ok:true});
    }

    if(req.method==='DELETE'){
      const id=String(req.query?.id||req.body?.id||'');
      const rows=await sql`SELECT role FROM gvcn_users WHERE id=${id} LIMIT 1`;
      if(!rows[0]) return json(res,404,{ok:false,error:'Không tìm thấy thành viên'});
      if(rows[0].role==='admin') return json(res,400,{ok:false,error:'Không thể xóa Admin chính'});
      await sql`DELETE FROM gvcn_users WHERE id=${id}`;
      return json(res,200,{ok:true});
    }

    return json(res,405,{ok:false,error:'Method not allowed'});
  }catch(e){
    console.error(e);
    if(String(e?.message||'').includes('unique')) return json(res,409,{ok:false,error:'Tên đăng nhập hoặc email Google đã tồn tại'});
    return json(res,500,{ok:false,error:'Không thể quản lý thành viên'});
  }
}

