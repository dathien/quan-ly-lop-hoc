import { neon } from '@neondatabase/serverless';
import { SignJWT, jwtVerify } from 'jose';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export const sql = neon(process.env.DATABASE_URL);
const COOKIE = 'gvcn_session';

function secretKey(){
  const s = process.env.AUTH_SECRET || '';
  if (s.length < 32) throw new Error('AUTH_SECRET must be at least 32 characters');
  return new TextEncoder().encode(s);
}

export function parseCookies(req){
  const raw = req.headers.cookie || '';
  const out = {};
  raw.split(';').forEach(part=>{
    const i = part.indexOf('=');
    if(i>0) out[decodeURIComponent(part.slice(0,i).trim())] = decodeURIComponent(part.slice(i+1).trim());
  });
  return out;
}

export async function signSession(user){
  return await new SignJWT({
    role:user.role,
    username:user.username,
    fullName:user.full_name,
    permissions:user.permissions || []
  })
    .setProtectedHeader({alg:'HS256'})
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime('12h')
    .sign(secretKey());
}

export function setSessionCookie(res, token){
  const secure = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${secure?'; Secure':''}`);
}

export function clearSessionCookie(res){
  const secure = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure?'; Secure':''}`);
}

export async function getSession(req){
  try{
    const token = parseCookies(req)[COOKIE];
    if(!token) return null;
    const {payload} = await jwtVerify(token, secretKey());
    const rows = await sql`
      SELECT id, username, full_name, role, google_email, permissions, active
      FROM gvcn_users WHERE id=${payload.sub} LIMIT 1
    `;
    const u = rows[0];
    if(!u || !u.active) return null;
    return u;
  }catch(e){ return null; }
}

export function isAdmin(user){ return !!user && user.role === 'admin'; }
export function hasPermission(user, perm){
  if(!user) return false;
  if(isAdmin(user)) return true;
  const p = Array.isArray(user.permissions) ? user.permissions : [];
  return p.includes('*') || p.includes(perm);
}

export function publicUser(user){
  if(!user) return null;
  return {
    id:user.id, username:user.username, fullName:user.full_name, role:user.role,
    googleEmail:user.google_email || '', permissions:Array.isArray(user.permissions)?user.permissions:[]
  };
}

export function hashPassword(password){
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, 64, {N:16384,r:8,p:1});
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password, stored){
  try{
    const [kind,saltHex,hashHex] = String(stored||'').split('$');
    if(kind!=='scrypt' || !saltHex || !hashHex) return false;
    const salt=Buffer.from(saltHex,'hex');
    const expected=Buffer.from(hashHex,'hex');
    const got=scryptSync(String(password),salt,expected.length,{N:16384,r:8,p:1});
    return got.length===expected.length && timingSafeEqual(got,expected);
  }catch(e){ return false; }
}

export function json(res, code, data){
  res.setHeader('Cache-Control','no-store, no-cache, must-revalidate');
  return res.status(code).json(data);
}
