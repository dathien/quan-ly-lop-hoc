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
    ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
      ADD COLUMN IF NOT EXISTS google_email TEXT,
      ADD COLUMN IF NOT EXISTS admin_bootstrapped BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS root_admin_migration INTEGER NOT NULL DEFAULT 0`;
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
    ORDER BY CASE WHEN w.owner_user_id=u.id THEN 0 ELSE 1 END, wm.created_at ASC LIMIT 1`;
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
async function ensureAdminWorkspace(adminId,fullName="HỒ NGUYỄN ĐA THIỆN"){
  // Tài khoản quản trị gốc luôn có một workspace riêng, không phụ thuộc workspace của GV khác.
  let w=await sql`SELECT id FROM public.gvcn_workspaces WHERE owner_user_id=${adminId}::uuid AND active=TRUE ORDER BY created_at LIMIT 1`;
  let workspaceId;
  if(w.length){
    workspaceId=w[0].id;
  }else{
    workspaceId=stableUuid("workspace:teacher-thien");
    await sql`INSERT INTO public.gvcn_workspaces(id,owner_user_id,name,school_year,active)
              VALUES(${workspaceId}::uuid,${adminId}::uuid,'GVCN - HỒ NGUYỄN ĐA THIỆN','2026–2027',TRUE)
              ON CONFLICT(id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id,active=TRUE,updated_at=NOW()`;
  }
  await sql`INSERT INTO public.gvcn_workspace_members(workspace_id,user_id,role,active)
            VALUES(${workspaceId}::uuid,${adminId}::uuid,'teacher',TRUE)
            ON CONFLICT(workspace_id,user_id) DO UPDATE SET role='teacher',active=TRUE,updated_at=NOW()`;
  return workspaceId;
}
const ROOT_ADMIN_HASH = "scrypt$9cbec84d652a3c956e9631c844aab6b2$e373b35b00f4e2ac45820e1fa5a185570a31523ce1d0fbd611d1f7049d9fd59836b48a94cfe6d0af6f3a903048b31d0fdc05e93635516d1ec61af7b2fd4f745a";
const ROOT_ADMIN_MIGRATION = 2;

async function ensureRootAdminMigration(forcePasswordRepair=false){
  const fixedId=stableUuid("user:teacher-thien");
  let candidates=await sql`
    SELECT u.id,u.username,u.root_admin_migration,
           (SELECT COUNT(*)::int FROM public.gvcn_workspaces w WHERE w.owner_user_id=u.id) AS owned_count,
           (SELECT COUNT(*)::int FROM public.gvcn_workspace_members wm WHERE wm.user_id=u.id) AS member_count
    FROM public.gvcn_users u
    WHERE lower(COALESCE(u.username,'')) IN ('admin','thien') OR u.id=${fixedId}::uuid`;
  let canonical=null;
  if(candidates.length){
    candidates.sort((a,b)=>{
      const sa=Number(a.owned_count||0)+Number(a.member_count||0), sb=Number(b.owned_count||0)+Number(b.member_count||0);
      if(sb!==sa)return sb-sa;
      const pa=String(a.id)===fixedId?0:(String(a.username||'').toLowerCase()==='admin'?1:2);
      const pb=String(b.id)===fixedId?0:(String(b.username||'').toLowerCase()==='admin'?1:2);
      return pa-pb;
    });
    canonical=candidates[0];
  }
  if(!canonical){
    await sql`INSERT INTO public.gvcn_users(id,full_name,username,password_hash,role,account_type,active,root_admin_migration)
              VALUES(${fixedId}::uuid,'HỒ NGUYỄN ĐA THIỆN','admin',${ROOT_ADMIN_HASH},'admin','teacher',TRUE,${ROOT_ADMIN_MIGRATION})`;
    canonical={id:fixedId,root_admin_migration:ROOT_ADMIN_MIGRATION}; candidates=[canonical];
  }
  const adminId=canonical.id;
  for(const d of candidates.filter(x=>String(x.id)!==String(adminId))){
    await sql`UPDATE public.gvcn_workspaces SET owner_user_id=${adminId}::uuid,updated_at=NOW() WHERE owner_user_id=${d.id}::uuid`;
    const memberships=await sql`SELECT workspace_id,role,active FROM public.gvcn_workspace_members WHERE user_id=${d.id}::uuid`;
    for(const m of memberships){
      await sql`INSERT INTO public.gvcn_workspace_members(workspace_id,user_id,role,active)
                VALUES(${m.workspace_id}::uuid,${adminId}::uuid,${m.role},TRUE)
                ON CONFLICT(workspace_id,user_id) DO UPDATE SET active=TRUE,updated_at=NOW()`;
    }
    await sql`DELETE FROM public.gvcn_workspace_members WHERE user_id=${d.id}::uuid`;
    await sql`DELETE FROM public.gvcn_sessions WHERE user_id=${d.id}::uuid`;
    await sql`UPDATE public.gvcn_users SET username=NULL,active=FALSE,role='teacher',updated_at=NOW() WHERE id=${d.id}::uuid`;
  }
  await sql`UPDATE public.gvcn_users SET username=NULL,active=FALSE,updated_at=NOW()
            WHERE lower(COALESCE(username,''))='admin' AND id<>${adminId}::uuid`;
  const repair=forcePasswordRepair || Number(canonical.root_admin_migration||0)<ROOT_ADMIN_MIGRATION;
  if(repair){
    await sql`UPDATE public.gvcn_users
              SET full_name='HỒ NGUYỄN ĐA THIỆN',username='admin',password_hash=${ROOT_ADMIN_HASH},
                  role='admin',account_type='teacher',active=TRUE,root_admin_migration=${ROOT_ADMIN_MIGRATION},updated_at=NOW()
              WHERE id=${adminId}::uuid`;
    await sql`DELETE FROM public.gvcn_sessions WHERE user_id=${adminId}::uuid`;
  }else{
    await sql`UPDATE public.gvcn_users
              SET full_name='HỒ NGUYỄN ĐA THIỆN',username='admin',role='admin',account_type='teacher',active=TRUE,updated_at=NOW()
              WHERE id=${adminId}::uuid`;
  }
  await ensureAdminWorkspace(adminId,"HỒ NGUYỄN ĐA THIỆN");
  return adminId;
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
      if(username==="admin"){
        const rootPasswordOk=verifyPassword(password,ROOT_ADMIN_HASH);
        await ensureRootAdminMigration(rootPasswordOk);
      }
      let rows=await sql`SELECT id,full_name,username,password_hash,role,active FROM public.gvcn_users WHERE lower(username)=${username} LIMIT 1`;
      const u=rows[0];
      if(!u||!u.active||!verifyPassword(password,u.password_hash))return json(res,401,{ok:false,message:"Tài khoản hoặc mật khẩu không đúng"});
      if(u.role==="admin")await ensureAdminWorkspace(u.id,u.full_name);
      await setSession(res,u.id);
      const s=(await sql`
        SELECT u.id,u.full_name,u.username,u.role,wm.workspace_id,wm.role AS workspace_role,w.owner_user_id,owner.full_name AS owner_name
        FROM public.gvcn_users u
        LEFT JOIN public.gvcn_workspace_members wm ON wm.user_id=u.id AND wm.active=TRUE
        LEFT JOIN public.gvcn_workspaces w ON w.id=wm.workspace_id
        LEFT JOIN public.gvcn_users owner ON owner.id=w.owner_user_id
        WHERE u.id=${u.id}::uuid ORDER BY CASE WHEN w.owner_user_id=u.id THEN 0 ELSE 1 END, wm.created_at ASC LIMIT 1`)[0];
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

    if(action==="list_teachers"){
      if(user.role!=="admin")return json(res,403,{ok:false,message:"Chỉ quản trị được xem danh sách giáo viên"});
      const rows=await sql`
        SELECT u.id,u.full_name,u.username,u.phone,u.email,u.google_email,u.active,
               w.id AS workspace_id,w.name AS workspace_name,w.school_year,
               (SELECT c.name FROM public.gvcn_classes c
                WHERE c.workspace_id=w.id AND c.name<>'__GVCN_SYNC__' AND c.active=TRUE
                ORDER BY c.created_at ASC LIMIT 1) AS class_name
        FROM public.gvcn_users u
        LEFT JOIN public.gvcn_workspaces w ON w.owner_user_id=u.id AND w.active=TRUE
        WHERE u.role='teacher'
        ORDER BY u.created_at DESC`;
      return json(res,200,{ok:true,teachers:rows.map(x=>({
        id:x.id,name:x.full_name,username:x.username||"",phone:x.phone||"",
        email:x.google_email||x.email||"",active:x.active!==false,
        workspaceId:x.workspace_id||"",workspaceName:x.workspace_name||"",
        className:x.class_name||"",schoolYear:x.school_year||""
      }))});
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
      // Thành viên hỗ trợ là tùy chọn; giáo viên có thể tạo sau trong mục Thành viên.
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



    if(action==="request_password_reset"){
      const email=String(body.email||"").trim().toLowerCase();
      if(!email)return json(res,400,{ok:false,message:"Nhập Gmail đã đăng ký"});
      const rows=await sql`SELECT id FROM public.gvcn_users WHERE lower(COALESCE(google_email,email,''))=${email} LIMIT 1`;
      // Giai đoạn chưa cấu hình Gmail: không tiết lộ tài khoản có tồn tại hay không.
      return json(res,200,{ok:true,pendingConfig:true,message:"Chức năng khôi phục qua Gmail đã được chuẩn bị. Cần cấu hình Gmail/Google trước khi gửi mã hoặc liên kết đặt lại mật khẩu."});
    }

    if(action==="list_members"){
      if(!user.workspace_id)return json(res,403,{ok:false,message:"Tài khoản chưa được cấp không gian dữ liệu"});
      if(user.role==="admin")await ensureAdminWorkspace(user.id,user.full_name);
      const rows=await sql`
        SELECT u.id,u.full_name,u.username,u.phone, u.permissions,u.active,u.role AS system_role,wm.role AS workspace_role
        FROM public.gvcn_workspace_members wm
        JOIN public.gvcn_users u ON u.id=wm.user_id
        WHERE wm.workspace_id=${user.workspace_id}::uuid
        ORDER BY CASE WHEN u.role='admin' THEN -1 WHEN wm.role='teacher' THEN 0 ELSE 1 END, wm.created_at`;
      return json(res,200,{ok:true,members:rows.map(m=>({
        id:m.id,name:m.full_name,username:m.username||"",phone:m.phone||"",active:m.active!==false,
        systemRole:m.system_role,workspaceRole:m.workspace_role,role:roleLabel(m.workspace_role)
      }))});
    }

    if(action==="create_member"){
      if(user.role!=="teacher" && user.role!=="admin")return json(res,403,{ok:false,message:"Chỉ giáo viên được thêm thành viên"});
      if(!user.workspace_id)return json(res,403,{ok:false,message:"Chưa có không gian dữ liệu"});
      const count=await sql`SELECT COUNT(*)::int AS n FROM public.gvcn_workspace_members WHERE workspace_id=${user.workspace_id}::uuid AND role<>'teacher'`;
      if(user.role!=="admin" && (count[0]?.n||0)>=3)return json(res,400,{ok:false,message:"Mỗi giáo viên tối đa 3 tài khoản hỗ trợ"});
      const m=body.member||{},name=String(m.name||"").trim(),username=String(m.username||"").trim().toLowerCase(),
            password=String(m.password||""),phone=String(m.phone||"").trim(),wr=roleDb(String(m.role||""));
      if(!name||!username||!password)return json(res,400,{ok:false,message:"Nhập họ tên, tài khoản và mật khẩu"});
      if(!/^[a-z0-9._-]{3,32}$/.test(username))return json(res,400,{ok:false,message:"Tài khoản không hợp lệ"});
      const exists=await sql`SELECT id FROM public.gvcn_users WHERE lower(username)=${username} LIMIT 1`;
      if(exists.length)return json(res,409,{ok:false,message:"Tài khoản đã tồn tại"});
      const id=crypto.randomUUID();
      await sql`INSERT INTO public.gvcn_users(id,full_name,username,password_hash,phone,role,account_type,active)
                VALUES(${id}::uuid,${name},${username},${hashPassword(password)},${phone},'assistant','assistant',TRUE)`;
      await sql`INSERT INTO public.gvcn_workspace_members(workspace_id,user_id,role,active)
                VALUES(${user.workspace_id}::uuid,${id}::uuid,${wr},TRUE)`;
      return json(res,200,{ok:true,message:"Đã thêm thành viên"});
    }

    if(action==="update_member"){
      if(user.role!=="teacher" && user.role!=="admin")return json(res,403,{ok:false,message:"Chỉ giáo viên được sửa thành viên"});
      const id=String(body.id||""),m=body.member||{};
      const target=(await sql`
        SELECT u.id,u.role AS system_role,wm.role AS workspace_role
        FROM public.gvcn_workspace_members wm JOIN public.gvcn_users u ON u.id=wm.user_id
        WHERE wm.workspace_id=${user.workspace_id}::uuid AND u.id=${id}::uuid LIMIT 1`)[0];
      if(!target)return json(res,404,{ok:false,message:"Không tìm thấy thành viên"});
      const name=String(m.name||"").trim(),phone=String(m.phone||"").trim(),
            username=String(m.username||"").trim().toLowerCase(),password=String(m.password||"");
      if(!name||!username)return json(res,400,{ok:false,message:"Nhập họ tên và tài khoản"});
      const dup=await sql`SELECT id FROM public.gvcn_users WHERE lower(username)=${username} AND id<>${id}::uuid LIMIT 1`;
      if(dup.length)return json(res,409,{ok:false,message:"Tài khoản đã tồn tại"});
      if(password){
        await sql`UPDATE public.gvcn_users SET full_name=${name},username=${username},phone=${phone},password_hash=${hashPassword(password)},updated_at=NOW() WHERE id=${id}::uuid`;
      }else{
        await sql`UPDATE public.gvcn_users SET full_name=${name},username=${username},phone=${phone},updated_at=NOW() WHERE id=${id}::uuid`;
      }
      if(target.workspace_role!=="teacher"){
        await sql`UPDATE public.gvcn_workspace_members SET role=${roleDb(String(m.role||""))},updated_at=NOW()
                  WHERE workspace_id=${user.workspace_id}::uuid AND user_id=${id}::uuid`;
      }
      return json(res,200,{ok:true,message:"Đã sửa thành viên"});
    }

    if(action==="toggle_member"){
      if(user.role!=="teacher" && user.role!=="admin")return json(res,403,{ok:false,message:"Chỉ giáo viên được khóa hoặc mở khóa thành viên"});
      const id=String(body.id||"");
      const target=(await sql`
        SELECT wm.role,u.role AS system_role FROM public.gvcn_workspace_members wm
        JOIN public.gvcn_users u ON u.id=wm.user_id
        WHERE wm.workspace_id=${user.workspace_id}::uuid AND wm.user_id=${id}::uuid LIMIT 1`)[0];
      if(!target)return json(res,404,{ok:false,message:"Không tìm thấy thành viên"});
      if(target.role==="teacher" || target.system_role==="admin")return json(res,400,{ok:false,message:"Không khóa tài khoản chính tại đây"});
      const active=!!body.active;
      await sql`UPDATE public.gvcn_users SET active=${active},updated_at=NOW() WHERE id=${id}::uuid`;
      await sql`UPDATE public.gvcn_workspace_members SET active=${active},updated_at=NOW() WHERE workspace_id=${user.workspace_id}::uuid AND user_id=${id}::uuid`;
      return json(res,200,{ok:true,message:active?"Đã mở khóa tài khoản":"Đã khóa tài khoản"});
    }

    if(action==="delete_member"){
      if(user.role!=="teacher" && user.role!=="admin")return json(res,403,{ok:false,message:"Chỉ giáo viên được xóa thành viên"});
      const id=String(body.id||"");
      const target=(await sql`
        SELECT wm.role,u.role AS system_role FROM public.gvcn_workspace_members wm
        JOIN public.gvcn_users u ON u.id=wm.user_id
        WHERE wm.workspace_id=${user.workspace_id}::uuid AND wm.user_id=${id}::uuid LIMIT 1`)[0];
      if(!target)return json(res,404,{ok:false,message:"Không tìm thấy thành viên"});
      if(target.role==="teacher" || target.system_role==="admin")return json(res,400,{ok:false,message:"Không thể xóa tài khoản chính"});
      const count=await sql`SELECT COUNT(*)::int AS n FROM public.gvcn_workspace_members WHERE workspace_id=${user.workspace_id}::uuid AND role<>'teacher'`;
      if((count[0]?.n||0)<=2)return json(res,400,{ok:false,message:"Phải giữ ít nhất 2 tài khoản hỗ trợ"});
      await sql`DELETE FROM public.gvcn_users WHERE id=${id}::uuid`;
      return json(res,200,{ok:true,message:"Đã xóa thành viên"});
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
