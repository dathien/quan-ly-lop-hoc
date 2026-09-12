import { neon } from '@neondatabase/serverless';
import { getSession, hasPermission } from './_auth.js';
const sql = neon(process.env.DATABASE_URL);

function json(res,code,data){res.setHeader('Cache-Control','no-store, no-cache, must-revalidate');return res.status(code).json(data)}

function publicSnapshot(data={}){
  const d=JSON.parse(JSON.stringify(data||{}));
  d.students=(d.students||[]).map(x=>({id:x.id,classId:x.classId,name:x.name,gender:x.gender,group:x.group,seat:x.seat}));
  d.scores=[]; d.attendance=[]; d.incidents=[]; d.positive=[]; d.finance=[]; d.comments=[]; d.messages=[]; d.members=[]; d.logs=[];
  d.tasks=(d.tasks||[]).filter(x=>String(x.visibility||'').toLowerCase()==='public');
  return d;
}

const KEY_PERM={
  classes:'classes', students:'students', timetable:'timetable', scores:'scores',
  attendance:'discipline', incidents:'discipline', positive:'discipline', disciplineRules:'discipline',
  duty:'duty', weekly:'weekly', tasks:'tasks', finance:'finance', comments:'comments', messages:'parentcomms',
  members:'members'
};

function changedKeys(a,b){
  const keys=new Set([...Object.keys(a||{}),...Object.keys(b||{})]);
  return [...keys].filter(k=>JSON.stringify(a?.[k])!==JSON.stringify(b?.[k]));
}

export default async function handler(req,res){
  try{
    if(req.method==='GET'){
      const metaOnly=req.query?.meta==='1'||req.url?.includes('meta=1');
      if(metaOnly){
        const rows=await sql`SELECT updated_at, CASE WHEN data IS NULL OR data='{}'::jsonb THEN false ELSE true END AS has_data FROM app_snapshots WHERE id='gvcn-main' LIMIT 1`;
        return json(res,200,{ok:true,hasData:Boolean(rows[0]?.has_data),updatedAt:rows[0]?.updated_at||null});
      }
      const rows=await sql`SELECT data, updated_at FROM app_snapshots WHERE id='gvcn-main' LIMIT 1`;
      const user=await getSession(req);
      const raw=rows[0]?.data||{};
      return json(res,200,{ok:true,data:user?raw:publicSnapshot(raw),updatedAt:rows[0]?.updated_at||null,access:user?'member':'public'});
    }

    if(req.method==='POST'){
      const user=await getSession(req);
      if(!user) return json(res,401,{ok:false,error:'Cần đăng nhập để cập nhật dữ liệu'});
      const data=req.body;
      if(!data || typeof data!=='object' || Array.isArray(data)) return json(res,400,{ok:false,error:'Dữ liệu không hợp lệ'});
      const oldRows=await sql`SELECT data FROM app_snapshots WHERE id='gvcn-main' LIMIT 1`;
      const old=oldRows[0]?.data||{};
      const changes=changedKeys(old,data).filter(k=>!['logs','sync'].includes(k));
      const denied=changes.filter(k=>{
        if(user.role==='admin') return false;
        const perm=KEY_PERM[k];
        return !perm || !hasPermission(user,perm);
      });
      if(denied.length) return json(res,403,{ok:false,error:'Tài khoản không có quyền cập nhật khu vực này',denied});
      const rows=await sql`
        INSERT INTO app_snapshots(id,data,updated_at) VALUES('gvcn-main',${JSON.stringify(data)}::jsonb,NOW())
        ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,updated_at=NOW()
        RETURNING updated_at
      `;
      return json(res,200,{ok:true,updatedAt:rows[0]?.updated_at||new Date().toISOString()});
    }
    return json(res,405,{ok:false,error:'Method not allowed'});
  }catch(e){console.error('[api/sync]',e);return json(res,500,{ok:false,error:'Database error'});}
}
