import { neon } from "@neondatabase/serverless";
import crypto from "node:crypto";

const sql = neon(process.env.DATABASE_URL);
const COOKIE = "gvcn_session";
let schemaReady = false;

function json(res,status,body){
  res.status(status).setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  return res.end(JSON.stringify(body));
}
function parseCookies(req){
  const out={};
  String(req.headers.cookie||"").split(";").forEach(p=>{
    const i=p.indexOf("="); if(i>0) out[decodeURIComponent(p.slice(0,i).trim())]=decodeURIComponent(p.slice(i+1).trim());
  });
  return out;
}
function stableUuid(text){
  const h=crypto.createHash("sha256").update("gvcn:"+String(text)).digest("hex");
  return `${h.slice(0,8)}-${h.slice(8,12)}-4${h.slice(13,16)}-a${h.slice(17,20)}-${h.slice(20,32)}`;
}
function hashPassword(password){
  const salt=crypto.randomBytes(16);
  const hash=crypto.scryptSync(String(password),salt,64,{N:16384,r:8,p:1});
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}
function verifyPassword(password,stored){
  try{
    const [kind,saltHex,hashHex]=String(stored||"").split("$");
    if(kind!=="scrypt")return false;
    const expected=Buffer.from(hashHex,"hex");
    const got=crypto.scryptSync(String(password),Buffer.from(saltHex,"hex"),expected.length,{N:16384,r:8,p:1});
    return got.length===expected.length && crypto.timingSafeEqual(got,expected);
  }catch{return false}
}
function tokenHash(token){return crypto.createHash("sha256").update(token).digest("hex")}
function roleDb(label){
  const m={"Lớp trưởng":"class_monitor","Bí thư":"secretary","Thủ quỹ":"treasurer","Lớp phó":"vice_monitor","Thư ký":"assistant"};
  return m[label]||"assistant";
}
function roleLabel(role){
  const m={admin:"Quản trị",teacher:"Giáo viên",class_monitor:"Lớp trưởng",secretary:"Bí thư",treasurer:"Thủ quỹ",vice_monitor:"Lớp phó",assistant:"Hỗ trợ"};
  return m[role]||"Hỗ trợ";
}
async function ensureSchema(){
  if(schemaReady)return;
  await sql`ALTER TABLE public.gvcn_users
    ADD COLUMN IF NOT EXISTS username TEXT,
    ADD COLUMN IF NOT EXISTS password_hash TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'teacher',
    ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb`;
  await sql`CREATE UNIQUE INDEX IF NOT EXISTS gvcn_users_username_lower_uq ON public.gvcn_users (lower(username)) WHERE username IS NOT NULL`;
  await sql`CREATE TABLE IF NOT EXISTS public.gvcn_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES public.gvcn_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS gvcn_sessions_user_idx ON public.gvcn_sessions(user_id)`;
  schemaReady=true;
}
async function getSession(req){
  const token=parseCookies(req)[COOKIE];
  if(!token)return null;
  const rows=await sql`
    SELECT u.id,u.full_name,u.username,u.role,u.account_type,u.active,
           wm.workspace_id,wm.role AS workspace_role,w.owner_user_id,
           owner.full_name AS owner_name
    FROM public.gvcn_sessions s
    JOIN public.gvcn_users u ON u.id=s.user_id
    LEFT JOIN public.gvcn_workspace_members wm ON wm.user_id=u.id AND wm.active=TRUE
    LEFT JOIN public.gvcn_workspaces w ON w.id=wm.workspace_id AND w.active=TRUE
    LEFT JOIN public.gvcn_users owner ON owner.id=w.owner_user_id
    WHERE s.token_hash=${tokenHash(token)} AND s.expires_at>NOW() AND u.active=TRUE
    ORDER BY wm.created_at ASC LIMIT 1`;
  return rows[0]||null;
}
async function setSession(res,userId){
  const token=crypto.randomBytes(32).toString("base64url");
  await sql`DELETE FROM public.gvcn_sessions WHERE expires_at<=NOW()`;
  await sql`INSERT INTO public.gvcn_sessions(token_hash,user_id,expires_at) VALUES(${tokenHash(token)},${userId}::uuid,NOW()+INTERVAL '12 hours')`;
  res.setHeader("Set-Cookie",`${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200; Secure`);
}
function clearSession(res){res.setHeader("Set-Cookie",`${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`)}
async function snapshotClassId(workspaceId){
  const rows=await sql`SELECT id FROM public.gvcn_classes WHERE workspace_id=${workspaceId}::uuid AND name='__GVCN_SYNC__' LIMIT 1`;
  if(rows.length)return rows[0].id;
  const id=stableUuid("snapshot:"+workspaceId);
  await sql`INSERT INTO public.gvcn_classes(id,workspace_id,name,active) VALUES(${id}::uuid,${workspaceId}::uuid,'__GVCN_SYNC__',TRUE)
            ON CONFLICT(id) DO NOTHING`;
  return id;
}
async function bootstrapAdmin(username,password){
  if(username!=="thien" || password!=="123456")return null;
  const existing=await sql`SELECT id FROM public.gvcn_users WHERE id=${stableUuid("user:teacher-thien")}::uuid LIMIT 1`;
  if(!existing.length)return null;
  await sql`UPDATE public.gvcn_users SET username='thien',password_hash=${hashPassword("123456")},role='admin',active=TRUE,updated_at=NOW()
            WHERE id=${existing[0].id}::uuid AND username IS NULL`;
  return existing[0].id;
}
export default async function handler(req,res){
  if(req.method!=="POST")return json(res,405,{ok:false,message:"Method not allowed"});
  try{
    await ensureSchema();
    const body=typeof req.body==="string"?JSON.parse(req.body||"{}"):(req.body||{});
    const action=body.action;

    if(action==="ping"){await sql`SELECT 1`;return json(res,200,{ok:true,message:"Kết nối Neon thành công"})}

    if(action==="login"){
      const username=String(body.username||"").trim().toLowerCase();
      const password=String(body.password||"");
      if(!username||!password)return json(res,400,{ok:false,message:"Nhập tài khoản và mật khẩu"});
      let rows=await sql`SELECT id,full_name,username,password_hash,role,active FROM public.gvcn_users WHERE lower(username)=${username} LIMIT 1`;
      if(!rows.length){await bootstrapAdmin(username,password);rows=await sql`SELECT id,full_name,username,password_hash,role,active FROM public.gvcn_users WHERE lower(username)=${username} LIMIT 1`}
      const u=rows[0];
      if(!u||!u.active||!verifyPassword(password,u.password_hash))return json(res,401,{ok:false,message:"Tài khoản hoặc mật khẩu không đúng"});
      await setSession(res,u.id);
      const s=(await sql`
        SELECT u.id,u.full_name,u.username,u.role,wm.workspace_id,wm.role AS workspace_role,w.owner_user_id,owner.full_name AS owner_name
        FROM public.gvcn_users u
        LEFT JOIN public.gvcn_workspace_members wm ON wm.user_id=u.id AND wm.active=TRUE
        LEFT JOIN public.gvcn_workspaces w ON w.id=wm.workspace_id
        LEFT JOIN public.gvcn_users owner ON owner.id=w.owner_user_id
        WHERE u.id=${u.id}::uuid ORDER BY wm.created_at ASC LIMIT 1`)[0];
      return json(res,200,{ok:true,user:{id:s.id,name:s.full_name,username:s.username,role:roleLabel(s.role),systemRole:s.role,isAdmin:s.role==="admin",workspaceId:s.workspace_id,workspaceRole:s.workspace_role,teacherId:s.owner_user_id||s.id,teacherName:s.owner_name||s.full_name}});
    }

    if(action==="logout"){
      const token=parseCookies(req)[COOKIE]; if(token)await sql`DELETE FROM public.gvcn_sessions WHERE token_hash=${tokenHash(token)}`;
      clearSession(res);return json(res,200,{ok:true});
    }

    const user=await getSession(req);
    if(!user)return json(res,401,{ok:false,message:"Phiên đăng nhập đã hết hạn"});

    if(action==="me"){
      return json(res,200,{ok:true,authenticated:true,user:{id:user.id,name:user.full_name,username:user.username,role:roleLabel(user.role),systemRole:user.role,isAdmin:user.role==="admin",workspaceId:user.workspace_id,workspaceRole:user.workspace_role,teacherId:user.owner_user_id||user.id,teacherName:user.owner_name||user.full_name}});
    }

    if(action==="create_teacher"){
      if(user.role!=="admin")return json(res,403,{ok:false,message:"Chỉ quản trị được tạo giáo viên"});
      const t=body.teacher||{};
      const username=String(t.username||"").trim().toLowerCase();
      const fullName=String(t.name||"").trim();
      const password=String(t.password||"");
      const className=String(t.className||"").trim();
      const schoolYear=String(t.schoolYear||"").trim();
      const assistants=Array.isArray(t.assistants)?t.assistants.slice(0,3):[];
      if(!fullName||!username||!password||!className)return json(res,400,{ok:false,message:"Thiếu họ tên, tài khoản, mật khẩu hoặc tên lớp"});
      if(!/^[a-z0-9._-]{3,32}$/.test(username))return json(res,400,{ok:false,message:"Tài khoản giáo viên không hợp lệ"});
      if(assistants.length<2)return json(res,400,{ok:false,message:"Cần ít nhất 2 tài khoản hỗ trợ"});
      const names=[username,...assistants.map(a=>String(a.username||"").trim().toLowerCase())];
      if(new Set(names).size!==names.length)return json(res,400,{ok:false,message:"Các tài khoản không được trùng nhau"});
      const conflict=await sql`SELECT username FROM public.gvcn_users WHERE lower(username)=ANY(${names}) LIMIT 1`;
      if(conflict.length)return json(res,409,{ok:false,message:`Tài khoản ${conflict[0].username} đã tồn tại`});

      const teacherId=crypto.randomUUID(),workspaceId=crypto.randomUUID(),classId=crypto.randomUUID(),snapId=crypto.randomUUID();
      await sql`INSERT INTO public.gvcn_users(id,full_name,username,password_hash,role,account_type,active) VALUES(${teacherId}::uuid,${fullName},${username},${hashPassword(password)},'teacher','teacher',TRUE)`;
      await sql`INSERT INTO public.gvcn_workspaces(id,owner_user_id,name,school_year,active) VALUES(${workspaceId}::uuid,${teacherId}::uuid,${"GVCN - "+fullName},${schoolYear},TRUE)`;
      await sql`INSERT INTO public.gvcn_workspace_members(workspace_id,user_id,role,active) VALUES(${workspaceId}::uuid,${teacherId}::uuid,'teacher',TRUE)`;
      await sql`INSERT INTO public.gvcn_classes(id,workspace_id,name,school_year,teacher_name,active) VALUES(${classId}::uuid,${workspaceId}::uuid,${className},${schoolYear},${fullName},TRUE)`;

      const createdAssistants=[];
      for(const a of assistants){
        const an=String(a.name||"").trim(),au=String(a.username||"").trim().toLowerCase(),ap=String(a.password||"");
        if(!an||!au||!ap)continue;
        const aid=crypto.randomUUID(),ar=roleDb(a.role);
        await sql`INSERT INTO public.gvcn_users(id,full_name,username,password_hash,role,account_type,active) VALUES(${aid}::uuid,${an},${au},${hashPassword(ap)},'assistant','assistant',TRUE)`;
        await sql`INSERT INTO public.gvcn_workspace_members(workspace_id,user_id,role,active) VALUES(${workspaceId}::uuid,${aid}::uuid,${ar},TRUE)`;
        createdAssistants.push({id:aid,name:an,username:au,role:a.role||"Hỗ trợ"});
      }

      if(body.initialData && typeof body.initialData==="object"){
        const payload=JSON.stringify(body.initialData);
        if(Buffer.byteLength(payload,"utf8")<=8_000_000){
          await sql`INSERT INTO public.gvcn_classes(id,workspace_id,name,school_year,teacher_name,active) VALUES(${snapId}::uuid,${workspaceId}::uuid,'__GVCN_SYNC__',${schoolYear},${fullName},TRUE)`;
          await sql`INSERT INTO public.gvcn_class_data(class_id,revision,data,updated_by,updated_at) VALUES(${snapId}::uuid,1,${payload}::jsonb,${teacherId}::uuid,NOW())`;
        }
      }
      await sql`INSERT INTO public.gvcn_activity_logs(workspace_id,user_id,action,module,description) VALUES(${workspaceId}::uuid,${user.id}::uuid,'CREATE_TEACHER','admin',${"Tạo giáo viên "+fullName})`;
      return json(res,200,{ok:true,teacher:{id:teacherId,name:fullName,username,workspaceId,classId,className,schoolYear,assistants:createdAssistants}});
    }

    if(!user.workspace_id)return json(res,403,{ok:false,message:"Tài khoản chưa được cấp không gian dữ liệu"});
    const snapId=await snapshotClassId(user.workspace_id);

    if(action==="meta"){
      const rows=await sql`SELECT revision,updated_at FROM public.gvcn_class_data WHERE class_id=${snapId}::uuid LIMIT 1`;
      return json(res,200,{ok:true,hasData:!!rows.length,revision:rows[0]?.revision||0,updatedAt:rows[0]?.updated_at||null});
    }
    if(action==="pull"){
      const rows=await sql`SELECT data,revision,updated_at FROM public.gvcn_class_data WHERE class_id=${snapId}::uuid LIMIT 1`;
      return json(res,200,{ok:true,data:rows[0]?.data||null,revision:rows[0]?.revision||0,updatedAt:rows[0]?.updated_at||null});
    }
    if(action==="push"){
      if(!body.data||typeof body.data!=="object")return json(res,400,{ok:false,message:"Thiếu dữ liệu đồng bộ"});
      const payload=JSON.stringify(body.data);
      if(Buffer.byteLength(payload,"utf8")>8_000_000)return json(res,413,{ok:false,message:"Dữ liệu vượt giới hạn 8 MB"});
      const rows=await sql`
        INSERT INTO public.gvcn_class_data(class_id,revision,data,updated_by,updated_at)
        VALUES(${snapId}::uuid,1,${payload}::jsonb,${user.id}::uuid,NOW())
        ON CONFLICT(class_id) DO UPDATE SET revision=public.gvcn_class_data.revision+1,data=EXCLUDED.data,updated_by=EXCLUDED.updated_by,updated_at=NOW()
        RETURNING revision,updated_at`;
      return json(res,200,{ok:true,revision:rows[0].revision,updatedAt:rows[0].updated_at});
    }
    return json(res,400,{ok:false,message:"Action không hợp lệ"});
  }catch(err){
    console.error("GVCN API",err);
    return json(res,500,{ok:false,message:"Lỗi máy chủ GVCN"});
  }
}
