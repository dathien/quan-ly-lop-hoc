import { sql, verifyPassword, signSession, setSessionCookie, publicUser, json } from '../_auth.js';

export default async function handler(req,res){
  if(req.method!=='POST') return json(res,405,{ok:false,error:'Method not allowed'});
  try{
    const username=String(req.body?.username||'').trim().toLowerCase();
    const password=String(req.body?.password||'');
    if(!username || !password) return json(res,400,{ok:false,error:'Vui lòng nhập tài khoản và mật khẩu'});
    const rows=await sql`
      SELECT id, username, full_name, role, google_email, permissions, active, password_hash
      FROM gvcn_users WHERE lower(username)=${username} LIMIT 1
    `;
    const user=rows[0];
    if(!user || !user.active || !verifyPassword(password,user.password_hash))
      return json(res,401,{ok:false,error:'Tài khoản hoặc mật khẩu không đúng'});
    const token=await signSession(user);
    setSessionCookie(res,token);
    return json(res,200,{ok:true,user:publicUser(user)});
  }catch(e){ console.error(e); return json(res,500,{ok:false,error:'Không thể đăng nhập'}); }
}

