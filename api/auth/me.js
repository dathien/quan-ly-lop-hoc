import { getSession, publicUser, json } from '../_auth.js';
export default async function handler(req,res){
  if(req.method!=='GET') return json(res,405,{ok:false,error:'Method not allowed'});
  const user=await getSession(req);
  return json(res,200,{ok:true,authenticated:!!user,user:publicUser(user)});
}

