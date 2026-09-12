import { OAuth2Client } from 'google-auth-library';
import { sql, signSession, setSessionCookie, publicUser, json } from '../_auth.js';

export default async function handler(req,res){
  if(req.method!=='POST') return json(res,405,{ok:false,error:'Method not allowed'});
  try{
    const credential=String(req.body?.credential||'');
    const clientId=process.env.GOOGLE_CLIENT_ID||'';
    if(!clientId) return json(res,503,{ok:false,error:'Google Login chưa được cấu hình'});
    if(!credential) return json(res,400,{ok:false,error:'Thiếu thông tin Google'});
    const client=new OAuth2Client(clientId);
    const ticket=await client.verifyIdToken({idToken:credential,audience:clientId});
    const payload=ticket.getPayload();
    const email=String(payload?.email||'').trim().toLowerCase();
    if(!email || !payload?.email_verified) return json(res,401,{ok:false,error:'Không xác minh được email Google'});
    const rows=await sql`
      SELECT id, username, full_name, role, google_email, permissions, active
      FROM gvcn_users WHERE lower(google_email)=${email} LIMIT 1
    `;
    const user=rows[0];
    if(!user || !user.active) return json(res,403,{ok:false,error:'Tài khoản Google này chưa được GVCN cấp quyền'});
    const token=await signSession(user);
    setSessionCookie(res,token);
    return json(res,200,{ok:true,user:publicUser(user)});
  }catch(e){ console.error(e); return json(res,401,{ok:false,error:'Đăng nhập Google không thành công'}); }
}

